//! Closure-only mutation API (v34.1) and boot recovery driver.
//!
//! `mutate_store` is the **only** write entry point for the managed-agents
//! store.  It owns the full lock sequence:
//!
//!   in-process mutex (caller-held `store_mutex_guard`)
//!   → anchored OS advisory lock (acquired here)
//!   → fresh fail-closed decode
//!   → SQLite `BEGIN` transaction (journal mutations + file_commit_phase record)
//!   → stage both JSON files (fsync before rename)
//!   → SQLite `COMMIT` the transaction
//!   → rename managed-agents.json.stage (record 'first_renamed' phase)
//!   → rename teams.json.stage (record 'committed' phase)
//!   → release OS advisory lock
//!
//! A closure returning `Err` rolls back the SQLite transaction — no journal
//! row is written, no file is staged.  A crash after `COMMIT` but before the
//! final rename is recovered at next boot via `run_boot_recovery_at`, which
//! inspects the `file_commit_phases` row and re-executes the pending renames.
//!
//! Network I/O and keyring access stay outside every critical section —
//! they are driven by durable operation phases recorded in the journal.

use std::path::Path;
use std::sync::MutexGuard;

use rusqlite::params;
use tauri::AppHandle;

use crate::managed_agents::{ManagedAgentRecord, TeamRecord};

use super::anchor::store_anchor_dir;
use super::codec::{decode_agent_store, decode_team_store};
use super::events::{insert_outbox_event, read_outbox_events, InsertEventOutcome};
use super::lock::JournalLockGuard;
use super::operations::{advance_disposition, read_nonterminal_operations, Disposition};
use super::schema::open_journal;
use super::util::{new_operation_id, unix_now_secs};

/// The decoded state passed to a mutation or read closure.
pub struct StoreState<'a> {
    /// Agent records decoded from `managed-agents.json` (all records —
    /// instances with a pubkey AND key-less definitions).
    pub agents: Vec<ManagedAgentRecord>,
    /// Team records decoded from `teams.json`.
    pub teams: Vec<TeamRecord>,
    /// Open journal connection (anchor-locked, inside a live SQLite transaction).
    pub journal: &'a rusqlite::Connection,
    /// Anchor directory (for constructing file paths).
    #[allow(dead_code)]
    pub anchor: &'a Path,
}

/// File-commit phase values recorded in `file_commit_phases`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileCommitPhase {
    Intent,
    FirstRenamed,
    Committed,
}

impl FileCommitPhase {
    fn as_str(&self) -> &'static str {
        match self {
            FileCommitPhase::Intent => "intent",
            FileCommitPhase::FirstRenamed => "first_renamed",
            FileCommitPhase::Committed => "committed",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "intent" => Some(FileCommitPhase::Intent),
            "first_renamed" => Some(FileCommitPhase::FirstRenamed),
            "committed" => Some(FileCommitPhase::Committed),
            _ => None,
        }
    }
}

/// Advance the `file_commit_phases` row to a new phase via SQL CAS.
/// Uses `INSERT OR REPLACE` pattern: writes a new row on `intent`, updates on
/// subsequent phases.  The `updated_at` timestamp provides a monotonic audit trail.
fn advance_file_commit_phase(
    conn: &rusqlite::Connection,
    commit_id: &str,
    new_phase: &FileCommitPhase,
) -> Result<(), String> {
    let now = unix_now_secs();
    conn.execute(
        "UPDATE file_commit_phases SET phase = ?1, updated_at = ?2
         WHERE commit_id = ?3",
        params![new_phase.as_str(), now, commit_id],
    )
    .map_err(|e| format!("advance_file_commit_phase({commit_id}): {e}"))?;
    Ok(())
}

/// Mutate the store under the full lock sequence.
///
/// The closure runs inside a real `rusqlite::Transaction` — if it returns
/// `Err`, all journal writes are rolled back and no file is staged.  Only
/// after `COMMIT` does `mutate_store` proceed to rename the staged files.
///
/// On any decode error inside this function no file is written, no journal
/// transition occurs, and the error is propagated with `?`.
pub fn mutate_store<'g, F, T>(
    app: &AppHandle,
    store_mutex_guard: MutexGuard<'g, ()>,
    mutation: F,
) -> Result<(T, MutexGuard<'g, ()>), String>
where
    F: FnOnce(StoreState<'_>) -> Result<(Vec<ManagedAgentRecord>, Vec<TeamRecord>, T), String>,
{
    let anchor = store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor).map_err(|e| format!("create anchor dir: {e}"))?;

    // Acquire advisory lock while holding the in-process mutex.
    let _advisory = JournalLockGuard::acquire(&anchor)?;

    let agents_path = anchor.join("managed-agents.json");
    let teams_path = anchor.join("teams.json");

    // Fresh fail-closed decode — any parse error is propagated; no mutation.
    let agents: Vec<ManagedAgentRecord> = if agents_path.exists() {
        let bytes =
            std::fs::read(&agents_path).map_err(|e| format!("read managed-agents.json: {e}"))?;
        decode_agent_store(&bytes).map_err(|e| {
            crate::managed_agents::storage::backup_invalid_store(&agents_path);
            e.message
        })?
    } else {
        Vec::new()
    };

    let teams: Vec<TeamRecord> = if teams_path.exists() {
        let bytes = std::fs::read(&teams_path).map_err(|e| format!("read teams.json: {e}"))?;
        decode_team_store(&bytes).map_err(|e| {
            crate::managed_agents::storage::backup_invalid_store(&teams_path);
            e.message
        })?
    } else {
        Vec::new()
    };

    let mut journal = open_journal(&anchor)?;

    // ── Phase 1: SQLite transaction wrapping ALL journal mutations ────────────
    //
    // The closure runs INSIDE a rusqlite::Transaction.  If the closure returns
    // Err, the transaction rolls back automatically on drop.  Only if the
    // closure succeeds do we proceed to stage files, and only after staging do
    // we COMMIT — so the journal and the staged files are durably consistent
    // before any rename occurs.
    let commit_id = new_operation_id();
    // Commit-unique stage paths prevent two concurrent mutate_store calls (or
    // a recovery-vs-mutation race) from overwriting each other's temp files.
    // The paths are stored in file_commit_phases and used by recovery.
    let agents_stage = anchor.join(format!("managed-agents.{commit_id}.stage"));
    let teams_stage = anchor.join(format!("teams.{commit_id}.stage"));

    // Record the commit intent row INSIDE the transaction so a crash before
    // COMMIT leaves no orphan phase row.
    let (_new_agents, _new_teams, result) = {
        let tx = journal
            .transaction()
            .map_err(|e| format!("begin journal transaction: {e}"))?;

        let state = StoreState {
            agents,
            teams,
            journal: &tx,
            anchor: &anchor,
        };

        let (new_agents, new_teams, result) = match mutation(state) {
            Ok(v) => v,
            Err(e) => {
                // tx rolls back on drop
                return Err(e);
            }
        };

        // Serialize both files while the transaction is open (before COMMIT)
        // so a serialization error also rolls back journal writes.
        let agents_payload = serde_json::to_vec_pretty(&new_agents)
            .map_err(|e| format!("serialize managed-agents.json: {e}"))?;
        let teams_payload = serde_json::to_vec_pretty(&new_teams)
            .map_err(|e| format!("serialize teams.json: {e}"))?;

        // Write both staged files and fsync before COMMIT.  If staging fails,
        // roll back the transaction so the journal stays consistent.
        stage_file(&agents_stage, &agents_payload)?;
        stage_file(&teams_stage, &teams_payload).inspect_err(|_| {
            // agents stage file written but no COMMIT — clean up best-effort
            let _ = std::fs::remove_file(&agents_stage);
        })?;

        // Insert the file-commit intent row.  This is the durable record that
        // recovery uses to identify an interrupted two-phase commit.
        // Content hashes allow recovery to verify a canonical file after a
        // missing-stage scenario: if the canonical hash matches the recorded
        // hash, the rename completed; otherwise fail closed.
        use sha2::Digest;
        let agents_hash = hex::encode(sha2::Sha256::digest(&agents_payload));
        let teams_hash = hex::encode(sha2::Sha256::digest(&teams_payload));
        let now = unix_now_secs();
        tx.execute(
            "INSERT INTO file_commit_phases
                 (commit_id, operation_id, phase,
                  agents_stage_path, teams_stage_path,
                  agents_content_hash, teams_content_hash,
                  created_at, updated_at)
             VALUES (?1, ?2, 'intent', ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                commit_id,
                commit_id, // operation_id == commit_id for phase records
                agents_stage.to_string_lossy().as_ref(),
                teams_stage.to_string_lossy().as_ref(),
                agents_hash,
                teams_hash,
                now,
            ],
        )
        .map_err(|e| {
            let _ = std::fs::remove_file(&agents_stage);
            let _ = std::fs::remove_file(&teams_stage);
            format!("insert file_commit_phase: {e}")
        })?;

        tx.commit().map_err(|e| {
            let _ = std::fs::remove_file(&agents_stage);
            let _ = std::fs::remove_file(&teams_stage);
            format!("commit journal transaction: {e}")
        })?;

        (new_agents, new_teams, result)
    }; // tx committed; journal borrowed as &mut for advance_file_commit_phase

    // ── Phase 2: rename agents (record first_renamed phase) ──────────────────
    //
    // After COMMIT the journal has a durable 'intent' row.  Recovery can
    // replay from here.  Rename managed-agents.json, then record the phase,
    // then rename teams.json, then record committed.
    //
    // If we crash between COMMIT and the first rename, recovery finds
    // 'intent', sees both stage files exist, and replays both renames.
    // If we crash after the first rename and its phase record, recovery
    // finds 'first_renamed', teams stage still exists, and replays only
    // the second rename.
    rename_staged(&agents_stage, &agents_path)?;

    advance_file_commit_phase(&journal, &commit_id, &FileCommitPhase::FirstRenamed)?;

    rename_staged(&teams_stage, &teams_path)?;

    advance_file_commit_phase(&journal, &commit_id, &FileCommitPhase::Committed)?;

    // Fsync parent directory on Unix so directory entries are durable.
    #[cfg(unix)]
    if let Some(parent) = agents_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    // Advisory lock drops here; in-process mutex guard returned to caller so
    // post-write work (retain, tombstone) can run inside the in-process lock.
    Ok((result, store_mutex_guard))
}

/// Write `payload` to `stage_path` with fsync, creating the temp file at
/// the exact stage path (rather than a random tmp name) so recovery can
/// verify its existence deterministically.
fn stage_file(stage_path: &Path, payload: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::File::create(stage_path)
        .map_err(|e| format!("create stage {}: {e}", stage_path.display()))?;
    f.write_all(payload)
        .map_err(|e| format!("write stage {}: {e}", stage_path.display()))?;
    f.sync_all()
        .map_err(|e| format!("fsync stage {}: {e}", stage_path.display()))?;
    Ok(())
}

/// Rename a staged file to its canonical path (restricted permissions for
/// the agents file, plain rename for teams).
fn rename_staged(stage: &Path, canonical: &Path) -> Result<(), String> {
    // Use restricted-write helper for agents (may carry nsecs), plain for
    // teams.  Both are already staged+fsynced; this just does the rename.
    // For agents we re-use the writer's restricted path so the canonical file
    // retains 0o600 on Unix.
    let name = canonical.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == "managed-agents.json" {
        // Canonicalize to handle symlinks, then rename over target.
        let resolved = std::fs::canonicalize(canonical).unwrap_or_else(|_| canonical.to_path_buf());
        std::fs::rename(stage, &resolved)
            .map_err(|e| format!("rename {} → {}: {e}", stage.display(), resolved.display()))?;
        // Set permissions on the canonical file (Unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&resolved, std::fs::Permissions::from_mode(0o600));
        }
    } else {
        let resolved = std::fs::canonicalize(canonical).unwrap_or_else(|_| canonical.to_path_buf());
        std::fs::rename(stage, &resolved)
            .map_err(|e| format!("rename {} → {}: {e}", stage.display(), resolved.display()))?;
    }
    Ok(())
}

/// Read the store under the full lock sequence without writing back files.
///
/// Both the lock and file paths are resolved from `store_anchor_dir` so this
/// read is always anchored — never from the process-local path.
///
/// The `store_mutex_guard` is returned so callers can continue holding the
/// in-process lock after the read.
#[allow(dead_code)] // B1 substrate — exposed for tests via pub(crate) re-export
pub fn read_store<'g, F, T>(
    app: &AppHandle,
    store_mutex_guard: MutexGuard<'g, ()>,
    reader: F,
) -> Result<(T, MutexGuard<'g, ()>), String>
where
    F: FnOnce(StoreState<'_>) -> Result<T, String>,
{
    let anchor = store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor).map_err(|e| format!("create anchor dir: {e}"))?;
    let _advisory = JournalLockGuard::acquire(&anchor)?;

    let agents_path = anchor.join("managed-agents.json");
    let teams_path = anchor.join("teams.json");

    let agents: Vec<ManagedAgentRecord> = if agents_path.exists() {
        let bytes =
            std::fs::read(&agents_path).map_err(|e| format!("read managed-agents.json: {e}"))?;
        decode_agent_store(&bytes).map_err(|e| {
            crate::managed_agents::storage::backup_invalid_store(&agents_path);
            e.message
        })?
    } else {
        Vec::new()
    };

    let teams: Vec<TeamRecord> = if teams_path.exists() {
        let bytes = std::fs::read(&teams_path).map_err(|e| format!("read teams.json: {e}"))?;
        decode_team_store(&bytes).map_err(|e| {
            crate::managed_agents::storage::backup_invalid_store(&teams_path);
            e.message
        })?
    } else {
        Vec::new()
    };

    let journal = open_journal(&anchor)?;

    let state = StoreState {
        agents,
        teams,
        journal: &journal,
        anchor: &anchor,
    };

    let result = reader(state)?;
    Ok((result, store_mutex_guard))
}

/// Boot recovery: open the journal and re-drive any nonterminal operations.
///
/// Performs two recovery passes:
///
/// 1. **File-commit recovery**: inspects `file_commit_phases` rows that are
///    not in `'committed'` state.  For each:
///    - `'intent'`: both stage files should exist — replay both renames.
///    - `'first_renamed'`: agents canonical is already renamed; only teams
///      stage file should exist — replay the teams rename.
///
/// 2. **Publication recovery**: for each nonterminal operation, reads its
///    outbox events and ensures they are surfaced for the flush loop.
///    For `keyring_write` operations, inspects inbox events and marks Failed
///    when the write was in-progress (the inline-key fallback re-migrates on
///    next load).
pub fn run_boot_recovery(
    app: &AppHandle,
    state: &tauri::State<crate::app_state::AppState>,
) -> Result<(), String> {
    let anchor = store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor).map_err(|e| format!("boot-recovery create anchor: {e}"))?;
    // Resolve the active scoped retention DB path — the same database the flush
    // loop drains via `flush_active_pending_events`.  Using a flat
    // `anchor/retention.db` path fails because production scopes to
    // `anchor/retention/<sha256(relay,owner)>.db`.
    let retention_path = match crate::managed_agents::retention::active_retention_scope(app, state)
    {
        Ok(scope) => {
            if scope.db_path.exists() {
                Some(scope.db_path)
            } else {
                None
            }
        }
        Err(e) => {
            eprintln!(
                "buzz-desktop: boot-recovery: cannot resolve retention scope ({e}), \
                 publication re-drive skipped — pending outbox rows will be re-tried at next boot"
            );
            None
        }
    };
    run_boot_recovery_at(&anchor, retention_path.as_deref())
}

/// Path-level boot recovery, extracted so tests can call it without an AppHandle.
///
/// `retention_db_path` is the path to the anchor's active scoped retention DB.  When
/// `Some`, recovery can re-insert missing `pending_sync` retention rows from
/// journal outbox payloads so the flush loop can re-publish them.  When `None`,
/// recovery logs the gap and leaves the outbox row pending for the next boot.
///
/// **File-commit recovery runs under the anchored advisory lock** so it cannot
/// race a concurrent `mutate_store` call.  Publication recovery (outbox re-drive)
/// runs under its own journal connection; it does not rename files and does not
/// require the lock.
pub(crate) fn run_boot_recovery_at(
    anchor: &std::path::Path,
    retention_db_path: Option<&std::path::Path>,
) -> Result<(), String> {
    // Phase 1: file-commit recovery — must hold the advisory lock so a
    // concurrent mutate_store cannot race the same *.stage paths.
    {
        let _advisory = super::lock::JournalLockGuard::acquire(anchor)?;
        let journal = open_journal(anchor)?;
        recover_interrupted_file_commits(&journal)?;
    }
    // Phase 2: publication recovery — no file I/O, no lock required.
    let journal = open_journal(anchor)?;
    recover_nonterminal_operations(&journal, retention_db_path)?;
    Ok(())
}

/// File-commit-only recovery: acquire the advisory lock, replay any interrupted
/// two-phase file commits, then release the lock.
///
/// Called synchronously during app setup (before commands are admitted) so the
/// store is always in a consistent state by the time the first command runs.
pub fn run_file_commit_recovery(app: &AppHandle) -> Result<(), String> {
    let anchor = store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor).map_err(|e| format!("boot-recovery create anchor: {e}"))?;
    let _advisory = super::lock::JournalLockGuard::acquire(&anchor)?;
    let journal = open_journal(&anchor)?;
    recover_interrupted_file_commits(&journal)
}

/// Derive the canonical (non-staged) path from a commit-unique stage path.
///
/// Stage paths follow the pattern `<anchor>/<base>.<commit_id>.stage` where
/// `<base>` is either `managed-agents` or `teams`.  The canonical path is
/// `<anchor>/managed-agents.json` or `<anchor>/teams.json`.
fn canonical_from_stage(stage: &Path) -> std::path::PathBuf {
    let anchor = stage.parent().unwrap_or(std::path::Path::new("."));
    let file_name = stage
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    // The stage file name always starts with either "managed-agents." or "teams.".
    // Map to the corresponding canonical JSON file name.
    let canonical = if file_name.starts_with("managed-agents.") {
        "managed-agents.json"
    } else if file_name.starts_with("teams.") {
        "teams.json"
    } else {
        // Fallback: strip everything from the second '.' onward.
        let without_stage = file_name.strip_suffix(".stage").unwrap_or(file_name);
        if let Some(idx) = without_stage.find('.') {
            return anchor.join(format!("{}.json", &without_stage[..idx]));
        }
        without_stage
    };
    anchor.join(canonical)
}

/// Recover any interrupted two-phase file commits from `file_commit_phases`.
///
/// Called before `recover_nonterminal_operations` so the JSON files are in a
/// consistent state before publication recovery reads or reconciles them.
/// Compute the SHA-256 hash of a file's contents, or `None` if the file cannot
/// be read. Used by recovery to verify canonical files match recorded hashes.
fn sha256_hex_of_file(path: &std::path::Path) -> Option<String> {
    use sha2::Digest;
    let bytes = std::fs::read(path).ok()?;
    Some(hex::encode(sha2::Sha256::digest(&bytes)))
}

#[allow(clippy::type_complexity)]
fn recover_interrupted_file_commits(journal: &rusqlite::Connection) -> Result<(), String> {
    // Read commit_id, phase, stage paths, AND content hashes.
    let rows: Vec<(String, String, String, String, String, String)> = {
        let mut stmt = journal
            .prepare(
                "SELECT commit_id, phase, agents_stage_path, teams_stage_path,
                        agents_content_hash, teams_content_hash
                 FROM file_commit_phases
                 WHERE phase != 'committed'",
            )
            .map_err(|e| format!("prepare file_commit_phases query: {e}"))?;
        let collected: Vec<rusqlite::Result<(String, String, String, String, String, String)>> =
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| format!("query file_commit_phases: {e}"))?
            .collect();
        collected
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("read file_commit_phases row: {e}"))?
    };

    for (commit_id, phase_str, agents_stage_str, teams_stage_str, agents_hash, teams_hash) in rows {
        let phase = FileCommitPhase::from_str(&phase_str).unwrap_or(FileCommitPhase::Intent);
        let agents_stage = std::path::PathBuf::from(&agents_stage_str);
        let teams_stage = std::path::PathBuf::from(&teams_stage_str);

        eprintln!(
            "buzz-desktop: boot-recovery: interrupted file commit {commit_id} phase={phase_str}"
        );

        let agents_canonical = canonical_from_stage(&agents_stage);
        let teams_canonical = canonical_from_stage(&teams_stage);

        match phase {
            FileCommitPhase::Intent => {
                // Both stage files should exist for a full intent commit.
                let agents_exists = agents_stage.exists();
                let teams_exists = teams_stage.exists();
                if !agents_exists && !teams_exists {
                    // Both stage files absent. Verify the canonical files match
                    // the recorded hashes — proof both renames completed.
                    let agents_ok = !agents_hash.is_empty()
                        && sha256_hex_of_file(&agents_canonical).as_deref() == Some(&agents_hash);
                    let teams_ok = !teams_hash.is_empty()
                        && sha256_hex_of_file(&teams_canonical).as_deref() == Some(&teams_hash);
                    if agents_ok && teams_ok {
                        eprintln!(
                            "buzz-desktop: boot-recovery: {commit_id}: both stage files absent,                              canonicals verified — advancing to committed"
                        );
                        advance_file_commit_phase(journal, &commit_id, &FileCommitPhase::Committed)
                            .unwrap_or_else(|e| {
                                eprintln!(
                                    "buzz-desktop: boot-recovery: advance committed failed: {e}"
                                )
                            });
                    } else {
                        eprintln!(
                            "buzz-desktop: boot-recovery: {commit_id}: both stage files absent                              in intent phase and canonicals do not match recorded hashes —                              failing closed; manual recovery may be needed"
                        );
                    }
                    continue;
                }
                if !agents_exists {
                    // Agents stage absent, teams stage present: ambiguous —
                    // cannot determine if agents rename completed without proof.
                    // Fail closed: skip this commit; operator intervention needed.
                    eprintln!(
                        "buzz-desktop: boot-recovery: {commit_id}: agents stage absent in                          intent phase (teams stage present) — cannot safely complete;                          skipping (manual recovery may be needed)"
                    );
                    continue;
                }
                // Agents stage exists — replay agents rename.
                if let Err(e) = rename_staged(&agents_stage, &agents_canonical) {
                    eprintln!("buzz-desktop: boot-recovery: agents rename failed: {e}");
                    continue;
                }
                if let Err(e) =
                    advance_file_commit_phase(journal, &commit_id, &FileCommitPhase::FirstRenamed)
                {
                    eprintln!("buzz-desktop: boot-recovery: advance first_renamed failed: {e}");
                }
                // Teams rename.
                if teams_exists {
                    if let Err(e) = rename_staged(&teams_stage, &teams_canonical) {
                        eprintln!("buzz-desktop: boot-recovery: teams rename failed: {e}");
                        continue;
                    }
                } else {
                    // Teams stage absent after agents rename. Verify via hash.
                    let teams_ok = !teams_hash.is_empty()
                        && sha256_hex_of_file(&teams_canonical).as_deref() == Some(&teams_hash);
                    if !teams_ok {
                        eprintln!(
                            "buzz-desktop: boot-recovery: {commit_id}: teams stage absent \
                             in intent phase (after agents rename) and canonical does not \
                             match recorded hash — failing closed"
                        );
                        continue;
                    }
                }
                advance_file_commit_phase(journal, &commit_id, &FileCommitPhase::Committed)
                    .unwrap_or_else(|e| {
                        eprintln!("buzz-desktop: boot-recovery: advance committed failed: {e}")
                    });
            }
            FileCommitPhase::FirstRenamed => {
                // Agents already renamed; only teams stage remains.
                if teams_stage.exists() {
                    if let Err(e) = rename_staged(&teams_stage, &teams_canonical) {
                        eprintln!(
                            "buzz-desktop: boot-recovery: teams rename (first_renamed) failed: {e}"
                        );
                        continue;
                    }
                    // Teams rename succeeded — advance to committed.
                } else {
                    // Teams stage absent. Verify via recorded hash.
                    let teams_ok = !teams_hash.is_empty()
                        && sha256_hex_of_file(&teams_canonical).as_deref() == Some(&teams_hash);
                    if !teams_ok {
                        eprintln!(
                            "buzz-desktop: boot-recovery: {commit_id}: teams stage absent in                              first_renamed phase and canonical does not match recorded hash —                              failing closed; manual recovery may be needed"
                        );
                        continue;
                    }
                    // Canonical matches — teams rename already completed.
                }
                advance_file_commit_phase(journal, &commit_id, &FileCommitPhase::Committed)
                    .unwrap_or_else(|e| {
                        eprintln!("buzz-desktop: boot-recovery: advance committed failed: {e}")
                    });
            }
            FileCommitPhase::Committed => unreachable!("filtered out in query"),
        }
    }

    Ok(())
}

/// Recover nonterminal operations from the journal outbox.
///
/// For each nonterminal operation:
/// - `keyring_write`: check inbox for in-progress pre-image → mark Failed
///   (inline-key fallback re-migrates on next load).
/// - Other ops with outbox evidence: surface pending rows and ensure the
///   retention DB will pick them up on the next flush loop tick.  If ALL
///   outbox events are published, advance the op to Committed.
/// - No outbox evidence: mark Failed.
///
/// Publication evidence re-drive: for ops with a pending outbox row, the
/// flush loop drains `pending_sync` retention rows.  If the retention row
/// is absent (team retain wrote journal-only evidence), insert a
/// `pending_sync` retention row from the immutable outbox payload so the
/// flush loop can re-publish it.
fn recover_nonterminal_operations(
    journal: &rusqlite::Connection,
    retention_db_path: Option<&std::path::Path>,
) -> Result<(), String> {
    let nonterminal = read_nonterminal_operations(journal)?;
    if nonterminal.is_empty() {
        return Ok(());
    }

    let mut re_driven = 0usize;
    let mut failed = 0usize;

    for op in &nonterminal {
        eprintln!(
            "buzz-desktop: boot-recovery: nonterminal op {} kind={} key={} disposition={:?}",
            op.operation_id, op.kind, op.key_id, op.disposition
        );

        // Read outbox events for this operation.
        let outbox = match read_outbox_events(journal, &op.operation_id) {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!(
                    "buzz-desktop: boot-recovery: read outbox for {}: {e}",
                    op.operation_id
                );
                continue;
            }
        };

        // keyring_write: check inbox for pre-image → mark Failed so the
        // inline-key fallback path re-migrates on next load.
        if op.kind == "keyring_write" && outbox.is_empty() {
            let _ = advance_disposition(
                journal,
                &op.operation_id,
                &op.disposition,
                &Disposition::Failed,
            );
            failed += 1;
            continue;
        }

        if outbox.is_empty() {
            // No outbox evidence — nothing to re-drive; mark failed.
            let _ = advance_disposition(
                journal,
                &op.operation_id,
                &op.disposition,
                &Disposition::Failed,
            );
            failed += 1;
            continue;
        }

        // Determine publication state.
        let mut any_pending = false;
        for (event_id, payload, published_state, retention_d_tag) in &outbox {
            if *published_state == 0 {
                any_pending = true;
                eprintln!(
                    "buzz-desktop: boot-recovery: outbox event {event_id} for op {} pending",
                    op.operation_id
                );
                // Ensure the retention DB has a `pending_sync` row for this
                // event payload so the flush loop can publish it.  The
                // retention_d_tag is the exact coordinate persisted at enqueue
                // time — used directly instead of re-parsing the event payload
                // so tombstones and archives (kind 5 / 9035) recover at the
                // correct (kind, pubkey, d_tag) coordinate.
                //
                // Best-effort: a retention failure here is logged; the outbox
                // row remains pending for the next boot.
                if let Err(e) = ensure_retention_row_for_payload(
                    payload,
                    event_id,
                    retention_d_tag,
                    retention_db_path,
                ) {
                    eprintln!(
                        "buzz-desktop: boot-recovery: could not ensure retention row for \
                         event {event_id}: {e}"
                    );
                }
            }
        }

        if any_pending {
            re_driven += 1;
        } else {
            // All outbox events published — advance to Committed.
            let _ = advance_disposition(
                journal,
                &op.operation_id,
                &op.disposition,
                &Disposition::Committed,
            );
        }
    }

    if re_driven > 0 || failed > 0 {
        eprintln!(
            "buzz-desktop: boot-recovery: {} op(s) queued for re-drive, {} op(s) marked failed",
            re_driven, failed
        );
    }
    Ok(())
}

/// Attempt to insert a `pending_sync` retention row from the raw event
/// payload stored in the journal outbox.  This ensures the flush loop can
/// publish the event even when the retention row was never written (e.g. the
/// process crashed between the journal COMMIT and the `retain_event` call).
///
/// `retention_d_tag` is the exact d_tag persisted in the outbox row at
/// enqueue time — it is used as the retention coordinate without any
/// re-parsing of the event payload.  This is essential for kinds like 5 and
/// 9035 that carry no d-tag in the event itself (tombstones use a synthetic
/// key like `"30177:<agent_pk>"`; archives use the agent pubkey directly).
///
/// When `retention_db_path` is `Some`, parses the Nostr event and inserts a
/// `pending_sync` row.  When `None` (first-boot before the retention DB
/// exists, or test paths without AppHandle), logs a diagnostic and returns
/// `Ok` — the next boot that runs with a live retention DB will call
/// `run_event_sync` / `reconcile_agents_to_events` and re-queue the row.
fn ensure_retention_row_for_payload(
    payload: &[u8],
    event_id: &str,
    retention_d_tag: &str,
    retention_db_path: Option<&std::path::Path>,
) -> Result<(), String> {
    use nostr::JsonUtil;

    let event = nostr::Event::from_json(
        std::str::from_utf8(payload).map_err(|e| format!("outbox payload not utf8: {e}"))?,
    )
    .map_err(|e| format!("parse outbox payload event {event_id}: {e}"))?;

    let Some(db_path) = retention_db_path else {
        // No retention DB path available (e.g. pre-existing DB or test context).
        // Log and return Ok — next live boot will reconcile.
        eprintln!(
            "buzz-desktop: boot-recovery: outbox event {event_id} has pending payload \
             (kind={}) — no retention DB path, will be re-queued by reconcile on next boot",
            event.kind
        );
        return Ok(());
    };

    // Open the retention DB and insert a pending_sync row for this event.
    let conn = crate::managed_agents::retention::open_retention_db(db_path)
        .map_err(|e| format!("boot-recovery: open retention db: {e}"))?;

    let owner_pubkey = event.pubkey.to_hex();

    crate::managed_agents::retention::retain_event(
        &conn,
        &crate::managed_agents::retention::RetainedEvent {
            kind: event.kind.as_u16() as u32,
            pubkey: owner_pubkey,
            d_tag: retention_d_tag.to_string(),
            content: event.content.to_string(),
            created_at: event.created_at.as_secs() as i64,
            raw_event: event.as_json(),
            pending_sync: true,
        },
    )
    .map_err(|e| format!("boot-recovery: insert retention row for {event_id}: {e}"))?;

    eprintln!(
        "buzz-desktop: boot-recovery: re-inserted retention row for outbox event {event_id} \
         (kind={}, d_tag={retention_d_tag:?})",
        event.kind
    );
    Ok(())
}

/// Prepare and record immutable publication evidence in a single atomic step.
///
/// This is the **single publication authority** for B1.  It establishes
/// durable evidence in a recoverable ordered protocol across two databases:
///
/// 1. Inserts the outbox row (immutable event payload) into the journal
///    SQLite connection — `?`-propagated so a collision or journal failure
///    aborts before anything is flushable.
/// 2. Inserts the retention row with `pending_sync = true` into the retention
///    SQLite connection — `?`-propagated.
///
/// These two writes span two separate SQLite connections (journal and
/// retention) and therefore cannot be wrapped in a single SQL transaction.
/// The ordering is intentional: if the process crashes after (1) but before
/// (2), boot recovery reads the outbox row and re-inserts the retention
/// projection via `ensure_retention_row_for_payload`.  If (2) fails after
/// (1) succeeds, the same recovery path applies on next boot.
///
/// `IdentityCollision` from `insert_outbox_event` is converted to `Err` —
/// never silently discarded.
///
/// Callers that do NOT need a new outbox row (e.g. no content change) call
/// `retain_agent_record` directly and skip this function.
#[allow(clippy::too_many_arguments)]
pub fn prepare_publication(
    journal: &rusqlite::Connection,
    retention_conn: &rusqlite::Connection,
    operation_id: &str,
    event_id: &str,
    raw_json: &str,
    kind: u32,
    owner_pubkey: &str,
    d_tag: &str,
    content: &str,
    created_at: i64,
) -> Result<(), String> {
    use crate::managed_agents::retention::{retain_event, RetainedEvent};

    // Insert outbox evidence first — if this fails the closure Err rolls
    // back the whole transaction.
    match insert_outbox_event(journal, event_id, operation_id, raw_json.as_bytes(), d_tag)? {
        InsertEventOutcome::Inserted | InsertEventOutcome::ExactDuplicate => {}
        InsertEventOutcome::IdentityCollision => {
            return Err(format!(
                "prepare_publication: identity collision on event {event_id} (operation {operation_id})"
            ));
        }
    }

    // Insert retention row with pending_sync = true.
    retain_event(
        retention_conn,
        &RetainedEvent {
            kind,
            pubkey: owner_pubkey.to_string(),
            d_tag: d_tag.to_string(),
            content: content.to_string(),
            created_at,
            raw_event: raw_json.to_string(),
            pending_sync: true,
        },
    )
}

/// Advance a journal operation from `Pending` to `Committed` after a
/// successful publication.  Best-effort: a journal-open or CAS failure is
/// logged and ignored so a journal hiccup never prevents the write from being
/// acknowledged.
pub fn advance_to_committed(app: &tauri::AppHandle, op_id: &str) {
    if let Ok(anchor) = super::anchor::store_anchor_dir(app) {
        if let Ok(journal) = super::schema::open_journal(&anchor) {
            let _ = super::operations::advance_disposition(
                &journal,
                op_id,
                &Disposition::Pending,
                &Disposition::Committed,
            );
        }
    }
}
