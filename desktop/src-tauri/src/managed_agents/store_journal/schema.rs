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
        CREATE TABLE IF NOT EXISTS outbox_events (
            event_id     TEXT NOT NULL PRIMARY KEY,
            operation_id TEXT NOT NULL
                REFERENCES operations(operation_id),
            payload      BLOB NOT NULL,
            published_state INTEGER NOT NULL DEFAULT 0,
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
            commit_id         TEXT NOT NULL PRIMARY KEY,
            operation_id      TEXT NOT NULL,
            phase             TEXT NOT NULL DEFAULT 'intent',
            agents_stage_path TEXT NOT NULL,
            teams_stage_path  TEXT NOT NULL,
            created_at        INTEGER NOT NULL,
            updated_at        INTEGER NOT NULL
        );
        ",
    )
    .map_err(|e| format!("apply journal schema: {e}"))?;

    // Set schema version via PRAGMA user_version (authoritative singleton,
    // never duplicated).
    conn.pragma_update(None, "user_version", 2)
        .map_err(|e| format!("set schema user_version: {e}"))?;

    Ok(())
}
