//! Journal database: open, schema application.

use std::path::Path;

use rusqlite::Connection;

use super::anchor::JOURNAL_FILENAME;

/// Open (or create) `store-journal.sqlite` at `anchor_dir` (WAL mode, 5 s
/// busy timeout) and apply the schema idempotently.
pub fn open_journal(anchor_dir: &Path) -> Result<Connection, String> {
    std::fs::create_dir_all(anchor_dir).map_err(|e| format!("create anchor dir: {e}"))?;
    let path = anchor_dir.join(JOURNAL_FILENAME);
    let conn = Connection::open(&path).map_err(|e| format!("open store-journal.sqlite: {e}"))?;

    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(|e| format!("set busy_timeout: {e}"))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("set WAL mode: {e}"))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| format!("enable foreign_keys: {e}"))?;

    apply_journal_schema(&conn)?;
    Ok(conn)
}

/// Apply all journal schema migrations idempotently.
/// Exposed as `apply_journal_schema_pub` for tests.
#[cfg(test)]
pub fn apply_journal_schema_pub(conn: &Connection) -> Result<(), String> {
    apply_journal_schema(conn)
}

pub(super) fn apply_journal_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        -- Per-key generation / tombstone metadata.
        -- generation stored as TEXT to preserve full u64 range.
        -- is_tombstone=1: key deleted; generation kept forever (no GC).
        CREATE TABLE IF NOT EXISTS key_generations (
            key_id    TEXT NOT NULL PRIMARY KEY,
            generation TEXT NOT NULL,
            is_tombstone INTEGER NOT NULL DEFAULT 0,
            updated_at  INTEGER NOT NULL DEFAULT 0
        );

        -- Saga spine.  disposition: pending|committed|compensating|
        -- compensated|failed|uncertain|accepted.
        -- compensation_id/generation: phased claim fence (v10/v12).
        -- nonterminal_follow_up: 1 if uncertain/accepted needs a recheck.
        CREATE TABLE IF NOT EXISTS operations (
            operation_id TEXT NOT NULL PRIMARY KEY,
            kind         TEXT NOT NULL,
            key_id       TEXT NOT NULL,
            disposition  TEXT NOT NULL DEFAULT 'pending',
            generation   TEXT NOT NULL,
            compensation_id         TEXT,
            compensation_generation TEXT,
            nonterminal_follow_up   INTEGER NOT NULL DEFAULT 0,
            created_at   INTEGER NOT NULL,
            updated_at   INTEGER NOT NULL
        );

        -- Immutable outbox rows (written once; publication progress tracked
        -- via append-only operation/event phase transitions, not a mutable
        -- flag).
        -- published_state: 0=pending, 1=published, 2=uncertain, 3=accepted.
        -- Advancing published_state is a fenced CAS; see mark_outbox_published.
        -- retention_d_tag: the exact d_tag used in the retention coordinate at
        -- enqueue time -- persisted so boot recovery can re-insert at the same
        -- (kind, pubkey, d_tag) coordinate without re-deriving it from the
        -- event payload, which may not carry a d-tag (e.g. kind-5 tombstones
        -- use a synthetic key like 30177:<agent_pk>).
        CREATE TABLE IF NOT EXISTS outbox_events (
            event_id     TEXT NOT NULL PRIMARY KEY,
            operation_id TEXT NOT NULL
                REFERENCES operations(operation_id),
            payload      BLOB NOT NULL,
            published_state INTEGER NOT NULL DEFAULT 0,
            retention_d_tag TEXT NOT NULL DEFAULT '',
            created_at   INTEGER NOT NULL
        );

        -- Immutable inbox rows (written once, never updated).
        CREATE TABLE IF NOT EXISTS inbox_events (
            event_id     TEXT NOT NULL PRIMARY KEY,
            operation_id TEXT NOT NULL
                REFERENCES operations(operation_id),
            payload      BLOB NOT NULL,
            received_at  INTEGER NOT NULL
        );

        -- Two-phase file-commit record.
        --
        -- Written inside the same SQLite transaction as operation/generation
        -- mutations. Tracks the progression of a mutate_store call through
        -- its three file-commit phases so boot recovery can determine how far
        -- a crashed commit progressed and finish or compensate it.
        --
        -- phase:
        --   'intent'         - journal transaction committed; staged files
        --                      written + fsynced; no rename has occurred.
        --   'first_renamed'  - managed-agents.json.stage renamed to canonical.
        --   'committed'      - teams.json.stage renamed to canonical; complete.
        --
        -- agents_stage_path / teams_stage_path name the temp files written
        -- before rename. Recovery checks for them to decide what remains to do.
        CREATE TABLE IF NOT EXISTS file_commit_phases (
            commit_id           TEXT NOT NULL PRIMARY KEY,
            operation_id        TEXT NOT NULL,
            phase               TEXT NOT NULL DEFAULT 'intent',
            agents_stage_path   TEXT NOT NULL,
            teams_stage_path    TEXT NOT NULL,
            agents_content_hash TEXT NOT NULL DEFAULT '',
            teams_content_hash  TEXT NOT NULL DEFAULT '',
            created_at          INTEGER NOT NULL,
            updated_at          INTEGER NOT NULL
        );
        ",
    )
    .map_err(|e| format!("apply journal schema: {e}"))?;

    // Schema upgrades (v3: content-hash columns; v4: retention_d_tag).
    //
    // We inspect existing columns via PRAGMA table_info (not "duplicate column"
    // errors) so genuine failures (SQLITE_BUSY, disk full, corrupt schema) are
    // propagated and the version is NOT silently advanced on partial migration.
    // All ADD COLUMN operations and the user_version stamp happen inside a
    // single transaction so the DB cannot be left half-migrated with a
    // "completed" version stamp.
    let current_version: u32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap_or(0);

    if current_version < 4 {
        // Read existing column names BEFORE opening the transaction.
        // PRAGMA table_info cannot run inside a BEGIN on some SQLite builds.
        let fcp_cols = table_column_names(conn, "file_commit_phases")?;
        let oe_cols = table_column_names(conn, "outbox_events")?;
        let need_agents_hash = !fcp_cols.contains(&"agents_content_hash".to_string());
        let need_teams_hash = !fcp_cols.contains(&"teams_content_hash".to_string());
        let need_d_tag = !oe_cols.contains(&"retention_d_tag".to_string());

        // Run all ADD COLUMN calls and the version stamp in one transaction.
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("begin migration transaction: {e}"))?;
        if need_agents_hash {
            tx.execute_batch(
                "ALTER TABLE file_commit_phases ADD COLUMN agents_content_hash TEXT NOT NULL DEFAULT \'\';",
            )
            .map_err(|e| format!("add agents_content_hash: {e}"))?;
        }
        if need_teams_hash {
            tx.execute_batch(
                "ALTER TABLE file_commit_phases ADD COLUMN teams_content_hash TEXT NOT NULL DEFAULT \'\';",
            )
            .map_err(|e| format!("add teams_content_hash: {e}"))?;
        }
        if need_d_tag {
            tx.execute_batch(
                "ALTER TABLE outbox_events ADD COLUMN retention_d_tag TEXT NOT NULL DEFAULT \'\';",
            )
            .map_err(|e| format!("add retention_d_tag: {e}"))?;
        }
        tx.pragma_update(None, "user_version", 4)
            .map_err(|e| format!("set schema user_version to 4: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit migration transaction: {e}"))?;

        // Post-migration verification (after commit — PRAGMA runs outside tx).
        let fcp_after = table_column_names(conn, "file_commit_phases")?;
        let oe_after = table_column_names(conn, "outbox_events")?;
        for col in &["agents_content_hash", "teams_content_hash"] {
            if !fcp_after.contains(&col.to_string()) {
                return Err(format!(
                    "schema migration: file_commit_phases.{col} absent after migration"
                ));
            }
        }
        if !oe_after.contains(&"retention_d_tag".to_string()) {
            return Err(
                "schema migration: outbox_events.retention_d_tag absent after migration"
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// Return the column names of `table` via `PRAGMA table_info`.
fn table_column_names(conn: &Connection, table: &str) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| format!("PRAGMA table_info({table}): {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("query table_info({table}): {e}"))?;
    let mut names = Vec::new();
    for row in rows {
        names.push(row.map_err(|e| format!("read table_info({table}) row: {e}"))?);
    }
    Ok(names)
}
