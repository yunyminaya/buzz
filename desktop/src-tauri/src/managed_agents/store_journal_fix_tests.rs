//! Tests for round-6/7 fixes: hash-verified recovery (Fix 3b), scoped
//! recovery path (Fix 1), and keyring chokepoint (Fix 2).

use super::operations::insert_operation;
use super::{insert_outbox_event, open_journal, run_boot_recovery_at, Generation};
use crate::managed_agents::retention::{get_pending_sync, open_retention_db};
use nostr::JsonUtil;

fn tmp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create temp dir")
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

fn insert_phase_row(
    conn: &rusqlite::Connection,
    cid: &str,
    phase: &str,
    as_: &str,
    ts: &str,
    ah: &str,
    th: &str,
) {
    conn.execute(
        "INSERT INTO file_commit_phases (commit_id,operation_id,phase,agents_stage_path,teams_stage_path,agents_content_hash,teams_content_hash,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,0,0)",
        rusqlite::params![cid, cid, phase, as_, ts, ah, th],
    ).unwrap();
}

fn agents_can(anchor: &std::path::Path) -> std::path::PathBuf {
    anchor.join("managed-agents.json")
}
fn teams_can(anchor: &std::path::Path) -> std::path::PathBuf {
    anchor.join("teams.json")
}
fn agents_stage(anchor: &std::path::Path) -> std::path::PathBuf {
    anchor.join("managed-agents.cc1.stage")
}
fn teams_stage(anchor: &std::path::Path) -> std::path::PathBuf {
    anchor.join("teams.cc1.stage")
}

/// Fix 3b — rename completed, phase update did not: both stage absent,
/// canonicals match recorded hashes → recovery advances to committed.
#[test]
fn test_file_recovery_rename_done_phase_not_updated_succeeds() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let ac = agents_can(&anchor);
    let tc = teams_can(&anchor);
    let ac_data = b"[{\"pubkey\":\"aa\"}]";
    let tc_data = b"[]";
    std::fs::write(&ac, ac_data).unwrap();
    std::fs::write(&tc, tc_data).unwrap();
    let j = open_journal(&anchor).unwrap();
    insert_phase_row(
        &j,
        "cc1",
        "intent",
        agents_stage(&anchor).to_str().unwrap(),
        teams_stage(&anchor).to_str().unwrap(),
        &sha256_hex(ac_data),
        &sha256_hex(tc_data),
    );
    drop(j);
    run_boot_recovery_at(&anchor, None).unwrap();
    // Row should be committed now (file_commit_phases phase = 'committed').
    let j = open_journal(&anchor).unwrap();
    let count: i64 = j
        .query_row(
            "SELECT COUNT(*) FROM file_commit_phases WHERE phase='committed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "recovery must advance to committed when canonicals verified"
    );
}

/// Fix 3b — both stages absent, canonical hashes do NOT match → fail closed.
#[test]
fn test_file_recovery_hash_mismatch_fails_closed() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let ac = agents_can(&anchor);
    let tc = teams_can(&anchor);
    std::fs::write(&ac, b"[{\"pubkey\":\"different\"}]").unwrap();
    std::fs::write(&tc, b"[]").unwrap();
    let j = open_journal(&anchor).unwrap();
    insert_phase_row(
        &j,
        "cc2",
        "intent",
        agents_stage(&anchor).to_str().unwrap(),
        teams_stage(&anchor).to_str().unwrap(),
        "badhash",
        "badhash",
    );
    drop(j);
    run_boot_recovery_at(&anchor, None).unwrap();
    // Phase must NOT be committed — fail closed.
    let j = open_journal(&anchor).unwrap();
    let count: i64 = j
        .query_row(
            "SELECT COUNT(*) FROM file_commit_phases WHERE phase='committed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "hash mismatch must leave phase uncommitted (fail closed)"
    );
}

/// Fix 3b — first_renamed: teams stage absent, canonical matches hash → advance.
#[test]
fn test_file_recovery_first_renamed_teams_done_hash_verified() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let ac = agents_can(&anchor);
    let tc = teams_can(&anchor);
    let tc_data = b"[]";
    std::fs::write(&ac, b"[{\"pubkey\":\"aa\"}]").unwrap();
    std::fs::write(&tc, tc_data).unwrap();
    let j = open_journal(&anchor).unwrap();
    insert_phase_row(
        &j,
        "cc3",
        "first_renamed",
        agents_stage(&anchor).to_str().unwrap(),
        teams_stage(&anchor).to_str().unwrap(),
        "",
        &sha256_hex(tc_data),
    );
    drop(j);
    run_boot_recovery_at(&anchor, None).unwrap();
    let j = open_journal(&anchor).unwrap();
    let count: i64 = j
        .query_row(
            "SELECT COUNT(*) FROM file_commit_phases WHERE phase='committed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "teams canonical verified in first_renamed → committed"
    );
}

/// Fix 3b — first_renamed: teams stage absent, hash missing (empty string) → fail closed.
#[test]
fn test_file_recovery_first_renamed_teams_absent_no_hash_fails_closed() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let ac = agents_can(&anchor);
    std::fs::write(&ac, b"[{\"pubkey\":\"aa\"}]").unwrap();
    // teams canonical ABSENT
    let j = open_journal(&anchor).unwrap();
    insert_phase_row(
        &j,
        "cc4",
        "first_renamed",
        agents_stage(&anchor).to_str().unwrap(),
        teams_stage(&anchor).to_str().unwrap(),
        "",
        "",
    );
    drop(j);
    run_boot_recovery_at(&anchor, None).unwrap();
    let j = open_journal(&anchor).unwrap();
    let count: i64 = j
        .query_row(
            "SELECT COUNT(*) FROM file_commit_phases WHERE phase='committed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "absent teams canonical with no hash → fail closed"
    );
}

/// Fix 1 — scoped recovery path: journal-only outbox evidence, retention DB at
/// a specific path (simulating the scoped hash-named path). Recovery re-inserts
/// the retention row into THAT path, not a flat path.
#[test]
fn test_boot_recovery_inserts_into_supplied_retention_path_not_flat() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let scoped_path = anchor.join("retention").join("abc123.db");
    std::fs::create_dir_all(scoped_path.parent().unwrap()).unwrap();
    let flat_path = anchor.join("retention.db");

    // Build real signed event for outbox.
    let keys = nostr::Keys::generate();
    let owner_pubkey = keys.public_key().to_hex();
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(30177), "content")
        .tag(nostr::Tag::identifier("agent-1"))
        .sign_with_keys(&keys)
        .unwrap();
    let event_id = event.id.to_hex();
    let raw = event.as_json();

    {
        let j = open_journal(&anchor).unwrap();
        insert_operation(&j, "op-1", "publish", "agent-1", Generation(0)).unwrap();
        insert_outbox_event(&j, &event_id, "op-1", raw.as_bytes()).unwrap();
    }

    // Recovery with scoped path — must insert into scoped, NOT flat.
    run_boot_recovery_at(&anchor, Some(&scoped_path)).unwrap();

    let conn_scoped = open_retention_db(&scoped_path).unwrap();
    let pending_scoped = get_pending_sync(&conn_scoped).unwrap();
    assert_eq!(pending_scoped.len(), 1, "re-inserted into scoped path");
    assert_eq!(pending_scoped[0].pubkey, owner_pubkey);

    // Flat path must NOT have been created.
    assert!(!flat_path.exists(), "must not write to flat retention.db");
}
