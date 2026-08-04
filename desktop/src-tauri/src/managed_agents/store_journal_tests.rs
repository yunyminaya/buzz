//! Crash/concurrency fixture tests for the B1 store-journal substrate.

use std::sync::{Arc, Barrier};
use std::thread;

use rusqlite::Connection;

use super::{
    advance_disposition, apply_journal_schema_pub, atomic_write_with_fsync,
    canonical_dev_anchor_pub, cas_generation, decode_agent_store, decode_team_store,
    insert_inbox_event, insert_operation, insert_outbox_event, mark_outbox_published, open_journal,
    pin_compensation, read_generation, read_inbox_events, read_nonterminal_operations,
    read_operation, read_outbox_events, set_nonterminal_follow_up, tombstone_key, CasOutcome,
    Disposition, Generation, InsertEventOutcome, JournalLockGuard, TransitionOutcome,
};

fn in_memory_journal() -> Connection {
    let conn = Connection::open(":memory:").unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    apply_journal_schema_pub(&conn).unwrap();
    conn
}

fn tmp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create temp dir")
}

#[test]
fn test_cas_generation_first_write_succeeds() {
    let conn = in_memory_journal();
    let result = cas_generation(&conn, "key1", Generation::zero()).unwrap();
    assert!(
        matches!(
            result,
            CasOutcome::Committed {
                new_generation: Generation(1)
            }
        ),
        "expected committed gen 1, got {result:?}"
    );
}

#[test]
fn test_cas_generation_conflict_returns_current() {
    let conn = in_memory_journal();
    cas_generation(&conn, "key1", Generation::zero()).unwrap();
    let result = cas_generation(&conn, "key1", Generation::zero()).unwrap();
    assert!(
        matches!(
            result,
            CasOutcome::Conflict {
                current: Generation(1)
            }
        ),
        "expected conflict gen 1, got {result:?}"
    );
}

#[test]
fn test_cas_generation_monotonically_increasing() {
    let conn = in_memory_journal();
    for expected in 0u64..5 {
        let result = cas_generation(&conn, "key1", Generation(expected)).unwrap();
        assert!(
            matches!(result, CasOutcome::Committed { new_generation: g } if g.0 == expected + 1),
            "expected committed gen {}, got {result:?}",
            expected + 1
        );
    }
}

#[test]
fn test_tombstone_prevents_aba_recreate() {
    let conn = in_memory_journal();
    cas_generation(&conn, "key1", Generation::zero()).unwrap();
    let tomb = tombstone_key(&conn, "key1", Generation(1)).unwrap();
    assert!(
        matches!(
            tomb,
            CasOutcome::Committed {
                new_generation: Generation(2)
            }
        ),
        "expected tombstone gen 2, got {tomb:?}"
    );
    let aba = cas_generation(&conn, "key1", Generation(2)).unwrap();
    assert!(
        matches!(aba, CasOutcome::Tombstoned { .. }),
        "expected tombstoned, got {aba:?}"
    );
}

#[test]
fn test_tombstone_generation_retained_forever() {
    let conn = in_memory_journal();
    cas_generation(&conn, "key1", Generation::zero()).unwrap();
    tombstone_key(&conn, "key1", Generation(1)).unwrap();
    let (gen, is_tombstone) = read_generation(&conn, "key1").unwrap();
    assert!(is_tombstone, "should be tombstoned");
    assert_eq!(gen, Generation(2), "tombstone gen should be 2");
}

#[test]
fn test_tombstone_at_wrong_generation_conflicts() {
    let conn = in_memory_journal();
    cas_generation(&conn, "key1", Generation::zero()).unwrap();
    let result = tombstone_key(&conn, "key1", Generation(99)).unwrap();
    assert!(
        matches!(
            result,
            CasOutcome::Conflict {
                current: Generation(1)
            }
        ),
        "expected conflict, got {result:?}"
    );
}

#[test]
fn test_insert_and_read_operation() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-1", "create_agent", "key1", Generation(0)).unwrap();
    let op = read_operation(&conn, "op-1")
        .unwrap()
        .expect("op should exist");
    assert_eq!(op.operation_id, "op-1");
    assert_eq!(op.kind, "create_agent");
    assert_eq!(op.key_id, "key1");
    assert_eq!(op.disposition, Disposition::Pending);
    assert_eq!(op.generation, Generation(0));
    assert!(op.compensation_id.is_none());
    assert!(!op.nonterminal_follow_up);
}

#[test]
fn test_advance_disposition_committed() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-2", "update_agent", "key2", Generation(1)).unwrap();
    let outcome = advance_disposition(
        &conn,
        "op-2",
        &Disposition::Pending,
        &Disposition::Committed,
    )
    .unwrap();
    assert_eq!(outcome, TransitionOutcome::Advanced);
    let op = read_operation(&conn, "op-2").unwrap().unwrap();
    assert_eq!(op.disposition, Disposition::Committed);
    assert!(op.disposition.is_terminal());
}

#[test]
fn test_pin_compensation_sets_claim_fence() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-3", "delete_agent", "key3", Generation(2)).unwrap();
    pin_compensation(&conn, "op-3", "comp-event-1", Generation(2)).unwrap();
    let op = read_operation(&conn, "op-3").unwrap().unwrap();
    assert_eq!(op.disposition, Disposition::Compensating);
    assert_eq!(op.compensation_id.as_deref(), Some("comp-event-1"));
    assert_eq!(op.compensation_generation, Some(Generation(2)));
}

#[test]
fn test_nonterminal_follow_up_flag() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-4", "publish_event", "key4", Generation(0)).unwrap();
    advance_disposition(
        &conn,
        "op-4",
        &Disposition::Pending,
        &Disposition::Uncertain,
    )
    .unwrap();
    set_nonterminal_follow_up(&conn, "op-4", &Disposition::Uncertain, true).unwrap();
    let op = read_operation(&conn, "op-4").unwrap().unwrap();
    assert!(op.disposition.requires_follow_up());
    assert!(op.nonterminal_follow_up);
}

#[test]
fn test_read_nonterminal_operations_excludes_terminal() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-a", "create", "k1", Generation(0)).unwrap();
    insert_operation(&conn, "op-b", "create", "k2", Generation(0)).unwrap();
    insert_operation(&conn, "op-c", "create", "k3", Generation(0)).unwrap();
    advance_disposition(
        &conn,
        "op-b",
        &Disposition::Pending,
        &Disposition::Committed,
    )
    .unwrap();
    advance_disposition(
        &conn,
        "op-c",
        &Disposition::Pending,
        &Disposition::Compensated,
    )
    .unwrap();
    let nonterminal = read_nonterminal_operations(&conn).unwrap();
    let ids: Vec<&str> = nonterminal
        .iter()
        .map(|op| op.operation_id.as_str())
        .collect();
    assert!(ids.contains(&"op-a"), "pending op-a should be nonterminal");
    assert!(!ids.contains(&"op-b"), "committed op-b should be excluded");
    assert!(
        !ids.contains(&"op-c"),
        "compensated op-c should be excluded"
    );
}

#[test]
fn test_outbox_insert_is_idempotent() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-out", "create", "k1", Generation(0)).unwrap();
    let payload = b"hello";
    let r1 = insert_outbox_event(&conn, "ev-1", "op-out", payload).unwrap();
    assert_eq!(
        r1,
        InsertEventOutcome::Inserted,
        "first insert must be Inserted"
    );
    let r2 = insert_outbox_event(&conn, "ev-1", "op-out", payload).unwrap();
    assert_eq!(
        r2,
        InsertEventOutcome::ExactDuplicate,
        "same payload must be ExactDuplicate"
    );
    let rows = read_outbox_events(&conn, "op-out").unwrap();
    assert_eq!(rows.len(), 1, "must have exactly one outbox row");
    assert_eq!(rows[0].1, payload);
}

#[test]
fn test_outbox_insert_identity_collision_fails_closed() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-out2", "create", "k1", Generation(0)).unwrap();
    insert_outbox_event(&conn, "ev-col", "op-out2", b"payload-a").unwrap();
    let r = insert_outbox_event(&conn, "ev-col", "op-out2", b"payload-b").unwrap();
    assert_eq!(r, InsertEventOutcome::IdentityCollision);
}

#[test]
fn test_inbox_insert_is_idempotent() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-in", "create", "k2", Generation(0)).unwrap();
    let payload = b"world";
    let r1 = insert_inbox_event(&conn, "in-1", "op-in", payload).unwrap();
    assert_eq!(r1, InsertEventOutcome::Inserted);
    let r2 = insert_inbox_event(&conn, "in-1", "op-in", payload).unwrap();
    assert_eq!(r2, InsertEventOutcome::ExactDuplicate);
    let rows = read_inbox_events(&conn, "op-in").unwrap();
    assert_eq!(rows.len(), 1, "must have exactly one inbox row");
    assert_eq!(rows[0].1, payload);
}

#[test]
fn test_decode_agent_store_empty_array_ok() {
    let bytes = b"[]";
    assert!(decode_agent_store(bytes).is_ok());
}

#[test]
fn test_decode_agent_store_malformed_fails_closed() {
    let bytes = b"{not json}";
    let result = decode_agent_store(bytes);
    assert!(result.is_err(), "malformed JSON must fail closed");
}

#[test]
fn test_decode_team_store_empty_array_ok() {
    let bytes = b"[]";
    assert!(decode_team_store(bytes).is_ok());
}

#[test]
fn test_decode_team_store_malformed_fails_closed() {
    let bytes = b"bare string";
    assert!(decode_team_store(bytes).is_err());
}

#[test]
fn test_atomic_write_with_fsync_roundtrip() {
    let dir = tmp_dir();
    let path = dir.path().join("test.json");
    let payload = b"[\"hello\"]";
    atomic_write_with_fsync(&path, payload).unwrap();
    let read_back = std::fs::read(&path).unwrap();
    assert_eq!(read_back, payload);
}

#[test]
#[cfg(unix)]
fn test_atomic_write_with_fsync_symlink_preserved() {
    let dir = tmp_dir();
    let real = dir.path().join("real.json");
    let link = dir.path().join("link.json");
    std::fs::write(&real, b"[]").unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    atomic_write_with_fsync(&link, b"[1]").unwrap();
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read(&real).unwrap(), b"[1]");
}

#[test]
fn test_atomic_write_with_fsync_first_boot_no_file() {
    let dir = tmp_dir();
    let path = dir.path().join("new.json");
    atomic_write_with_fsync(&path, b"[]").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"[]");
}

#[test]
fn test_canonical_dev_anchor_from_dev_data_dir() {
    use std::path::PathBuf;
    let local_agents =
        PathBuf::from("/Library/Application Support/xyz.block.buzz.app.dev.my-branch/agents");
    let anchor = canonical_dev_anchor_pub(&local_agents);
    assert_eq!(
        anchor,
        Some(PathBuf::from(
            "/Library/Application Support/xyz.block.buzz.app.dev/agents"
        ))
    );
}

#[test]
fn test_canonical_dev_anchor_from_production_data_dir_is_none() {
    use std::path::PathBuf;
    let local_agents = PathBuf::from("/Library/Application Support/xyz.block.buzz.app/agents");
    let anchor = canonical_dev_anchor_pub(&local_agents);
    assert!(
        anchor.is_none(),
        "production dir should not produce a dev anchor"
    );
}

#[test]
fn test_saga_crash_mid_compensation_recovers() {
    // Simulate: operation inserted, CAS committed, compensation pinned
    // (crash here), then recovery reads it as Compensating with a non-nil
    // compensation_id and can continue.
    let conn = in_memory_journal();
    insert_operation(&conn, "op-crash", "create", "k1", Generation(0)).unwrap();
    cas_generation(&conn, "k1", Generation(0)).unwrap();
    pin_compensation(&conn, "op-crash", "comp-1", Generation(1)).unwrap();
    let ops = read_nonterminal_operations(&conn).unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].disposition, Disposition::Compensating);
    assert_eq!(ops[0].compensation_id.as_deref(), Some("comp-1"));
}

#[test]
fn test_saga_uncertain_publication_sets_follow_up() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-unc", "publish", "k2", Generation(0)).unwrap();
    advance_disposition(
        &conn,
        "op-unc",
        &Disposition::Pending,
        &Disposition::Uncertain,
    )
    .unwrap();
    set_nonterminal_follow_up(&conn, "op-unc", &Disposition::Uncertain, true).unwrap();
    let op = read_operation(&conn, "op-unc").unwrap().unwrap();
    assert!(op.disposition.requires_follow_up());
    assert!(op.nonterminal_follow_up);
    advance_disposition(
        &conn,
        "op-unc",
        &Disposition::Uncertain,
        &Disposition::Committed,
    )
    .unwrap();
    set_nonterminal_follow_up(&conn, "op-unc", &Disposition::Committed, false).unwrap();
    let op2 = read_operation(&conn, "op-unc").unwrap().unwrap();
    assert!(op2.disposition.is_terminal());
    assert!(!op2.nonterminal_follow_up);
}

#[test]
fn test_two_threads_serialised_by_advisory_lock() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));
    let anchor2 = anchor.clone();
    let barrier2 = barrier.clone();
    let handle = thread::spawn(move || {
        let _guard = JournalLockGuard::acquire(&anchor2).unwrap();
        std::fs::write(anchor2.join("data.txt"), b"A").unwrap();
        barrier2.wait(); // signal that A has written and holds the lock
        thread::sleep(std::time::Duration::from_millis(20));
    });
    barrier.wait(); // wait until A holds the lock
    let _guard = JournalLockGuard::acquire(&anchor).unwrap();
    let content = std::fs::read(anchor.join("data.txt")).unwrap();
    assert_eq!(content, b"A");
    handle.join().unwrap();
}

#[test]
fn test_open_journal_creates_on_first_boot() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let conn = open_journal(&anchor).unwrap();
    let ops = read_nonterminal_operations(&conn).unwrap();
    assert!(ops.is_empty());
}

#[test]
fn test_decode_agent_store_absent_file_empty_vec() {
    let result = decode_agent_store(b"[]").unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_advance_disposition_wrong_expected_returns_conflict() {
    let conn = in_memory_journal();
    insert_operation(&conn, "op-conflict", "create", "k1", Generation(0)).unwrap();
    let outcome = advance_disposition(
        &conn,
        "op-conflict",
        &Disposition::Committed,
        &Disposition::Compensated,
    )
    .unwrap();
    assert!(
        matches!(outcome, TransitionOutcome::Conflict { .. }),
        "wrong expected must → Conflict"
    );
    let op = read_operation(&conn, "op-conflict").unwrap().unwrap();
    assert_eq!(
        op.disposition,
        Disposition::Pending,
        "disposition must not change on Conflict"
    );
}

#[test]
fn test_advance_disposition_not_found_returns_not_found() {
    let conn = in_memory_journal();
    let outcome = advance_disposition(
        &conn,
        "nonexistent",
        &Disposition::Pending,
        &Disposition::Committed,
    )
    .unwrap();
    assert_eq!(outcome, TransitionOutcome::NotFound);
}

#[test]
fn test_two_dev_worktree_paths_resolve_to_same_canonical_anchor() {
    use std::path::PathBuf;
    let branch_a =
        PathBuf::from("/Library/Application Support/xyz.block.buzz.app.dev.branch-a/agents");
    let branch_b =
        PathBuf::from("/Library/Application Support/xyz.block.buzz.app.dev.branch-b/agents");
    let anchor_a = canonical_dev_anchor_pub(&branch_a);
    let anchor_b = canonical_dev_anchor_pub(&branch_b);
    assert!(
        anchor_a.is_some(),
        "branch-a must resolve to a canonical anchor"
    );
    assert_eq!(
        anchor_a, anchor_b,
        "two dev worktrees must select the same anchor"
    );
    let expected = PathBuf::from("/Library/Application Support/xyz.block.buzz.app.dev/agents");
    assert_eq!(anchor_a.unwrap(), expected);
}

#[test]
fn test_mutate_store_malformed_agents_json_is_fail_closed() {
    let dir = tmp_dir();
    let agents_path = dir.path().join("managed-agents.json");
    let bad_bytes = b"{\"this is\":\"not a valid agent array\"}";
    std::fs::write(&agents_path, bad_bytes).unwrap();
    assert!(
        decode_agent_store(bad_bytes).is_err(),
        "malformed JSON array must fail closed"
    );
    assert_eq!(std::fs::read(&agents_path).unwrap(), bad_bytes);
}

#[test]
fn test_decode_agent_store_unknown_field_fails_closed() {
    let bytes = br#"[{"pubkey":"abc","name":"test","slug":"test-slug",
        "system_prompt":"","private_key_nsec":"","created_at":"","updated_at":"",
        "respond_to":"everyone","respond_to_allowlist":[],"relay_url":"",
        "backend":"local","parallelism":1,"agent_args":[],
        "acp_command":null,"agent_command_override":null,"env_vars":[],
        "__unknown_extra_field__": "value"}]"#;
    let result = decode_agent_store(bytes);
    assert!(
        result.is_err(),
        "unknown field in record must cause a decode error (deny_unknown_fields)"
    );
}

#[test]
fn test_decode_team_store_unknown_field_fails_closed() {
    let bytes = br#"[{"id":"team-1","name":"My Team","personas":[],
        "agents":[],"__extra__":"bad"}]"#;
    let result = decode_team_store(bytes);
    assert!(
        result.is_err(),
        "unknown field in TeamRecord must cause a decode error (deny_unknown_fields)"
    );
}

#[test]
fn test_two_threads_serialised_by_advisory_lock_via_journal() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let counter_path = anchor.join("counter.txt");
    std::fs::create_dir_all(&anchor).unwrap();
    std::fs::write(&counter_path, b"0").unwrap();
    let anchor_a = anchor.clone();
    let counter_a = counter_path.clone();
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();
    let handle = thread::spawn(move || {
        let _guard = JournalLockGuard::acquire(&anchor_a).unwrap();
        let v: u32 = std::fs::read_to_string(&counter_a)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::fs::write(&counter_a, (v + 1).to_string()).unwrap();
        barrier2.wait();
        thread::sleep(std::time::Duration::from_millis(20));
    });
    barrier.wait();
    let _guard = JournalLockGuard::acquire(&anchor).unwrap();
    let final_val: u32 = std::fs::read_to_string(&counter_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    handle.join().unwrap();
    assert_eq!(final_val, 1, "B must observe A's committed write");
}

/// Verify that a nonterminal pending operation with no outbox evidence is
/// advanced to Failed by run_boot_recovery_at (real journal close + reopen).
#[test]
fn test_boot_recovery_marks_no_evidence_op_failed_on_reopen() {
    use super::run_boot_recovery_at;

    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    {
        let journal = open_journal(&anchor).unwrap();
        insert_operation(
            &journal,
            "op-crash-1",
            "create_agent",
            "key-crash",
            Generation(0),
        )
        .unwrap();
    }

    run_boot_recovery_at(&anchor, None).unwrap();
    let journal = open_journal(&anchor).unwrap();
    let op = read_operation(&journal, "op-crash-1")
        .unwrap()
        .expect("op must still exist");
    assert_eq!(
        op.disposition,
        Disposition::Failed,
        "no-evidence op must be Failed"
    );
    assert!(op.disposition.is_terminal());
    let remaining = read_nonterminal_operations(&journal).unwrap();
    assert!(
        remaining.iter().all(|o| o.operation_id != "op-crash-1"),
        "failed op must not appear in nonterminal"
    );
}

/// Verify that a pending op WITH an unpublished outbox event is left in its
/// current (Pending) disposition so the flush loop can re-drive it.
#[test]
fn test_boot_recovery_leaves_pending_outbox_op_for_redriving() {
    use super::run_boot_recovery_at;

    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    {
        let journal = open_journal(&anchor).unwrap();
        insert_operation(&journal, "op-outbox-1", "publish", "key-pub", Generation(0)).unwrap();
        insert_outbox_event(
            &journal,
            "ev-pub-1",
            "op-outbox-1",
            b"{\"id\":\"ev-pub-1\"}",
        )
        .unwrap();
    }

    run_boot_recovery_at(&anchor, None).unwrap();
    let journal = open_journal(&anchor).unwrap();
    let op = read_operation(&journal, "op-outbox-1")
        .unwrap()
        .expect("op must exist");
    assert_eq!(
        op.disposition,
        Disposition::Pending,
        "op with pending outbox must stay Pending"
    );
    let nonterminal = read_nonterminal_operations(&journal).unwrap();
    assert!(
        nonterminal.iter().any(|o| o.operation_id == "op-outbox-1"),
        "op must be nonterminal"
    );
}

/// Verify that a keyring_write op WITH an inbox pre-image is advanced to Failed
/// (interrupted write detected; inline fallback re-migrates on next load).
#[test]
fn test_boot_recovery_keyring_write_with_inbox_marks_failed() {
    use super::run_boot_recovery_at;

    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    {
        let journal = open_journal(&anchor).unwrap();
        insert_operation(
            &journal,
            "op-kr-1",
            "keyring_write",
            "key-kr",
            Generation(0),
        )
        .unwrap();
        insert_inbox_event(&journal, "in-kr-1", "op-kr-1", b"pubkey-bytes").unwrap();
    }

    run_boot_recovery_at(&anchor, None).unwrap();
    let journal = open_journal(&anchor).unwrap();
    let op = read_operation(&journal, "op-kr-1")
        .unwrap()
        .expect("op must exist");
    assert_eq!(
        op.disposition,
        Disposition::Failed,
        "interrupted keyring_write must be Failed"
    );
}

/// Boot recovery re-inserts a missing retention row from the immutable outbox
/// payload, then simulates the flush loop advancing the owning op to Committed.
/// A second recovery pass finds no nonterminal ops — published exactly once.
#[test]
fn test_boot_recovery_journal_only_evidence_published_terminal_once() {
    use super::run_boot_recovery_at;
    use crate::managed_agents::retention::{get_pending_sync, mark_synced, open_retention_db};
    use nostr::JsonUtil;

    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    let retention_db_path = anchor.join("retention.db");
    let keys = nostr::Keys::generate();
    let owner_pubkey = keys.public_key().to_hex();
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(30177), "test-content")
        .tag(nostr::Tag::identifier("test-agent"))
        .sign_with_keys(&keys)
        .unwrap();
    let event_id = event.id.to_hex();
    let raw_payload = event.as_json();
    {
        let journal = open_journal(&anchor).unwrap();
        insert_operation(&journal, "op-pub-1", "publish", "test-agent", Generation(0)).unwrap();
        insert_outbox_event(&journal, &event_id, "op-pub-1", raw_payload.as_bytes()).unwrap();
    }
    let conn = open_retention_db(&retention_db_path).unwrap();
    assert!(
        get_pending_sync(&conn).unwrap().is_empty(),
        "no retention rows before recovery"
    );
    drop(conn);
    run_boot_recovery_at(&anchor, Some(&retention_db_path)).unwrap();
    let conn = open_retention_db(&retention_db_path).unwrap();
    let pending = get_pending_sync(&conn).unwrap();
    assert_eq!(
        pending.len(),
        1,
        "recovery must re-insert exactly one pending_sync row"
    );
    let row = &pending[0];
    assert_eq!(row.d_tag, "test-agent");
    assert_eq!(row.pubkey, owner_pubkey);
    let journal = open_journal(&anchor).unwrap();
    let op = read_operation(&journal, "op-pub-1").unwrap().unwrap();
    assert_eq!(
        op.disposition,
        Disposition::Pending,
        "op must stay Pending after recovery"
    );
    mark_synced(
        &conn,
        row.kind,
        &row.pubkey,
        &row.d_tag,
        row.created_at,
        &row.content,
    )
    .unwrap();
    assert!(mark_outbox_published(&journal, &event_id, 0, 1).unwrap());
    let pending_siblings: i64 = journal
        .query_row(
            "SELECT COUNT(*) FROM outbox_events WHERE operation_id = ?1 AND published_state = 0",
            rusqlite::params!["op-pub-1"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending_siblings, 0);
    advance_disposition(
        &journal,
        "op-pub-1",
        &Disposition::Pending,
        &Disposition::Committed,
    )
    .unwrap();
    drop(journal);
    run_boot_recovery_at(&anchor, Some(&retention_db_path)).unwrap();
    let journal = open_journal(&anchor).unwrap();
    let op = read_operation(&journal, "op-pub-1").unwrap().unwrap();
    assert_eq!(
        op.disposition,
        Disposition::Committed,
        "op must remain Committed"
    );
    assert!(
        read_nonterminal_operations(&journal)
            .unwrap()
            .iter()
            .all(|o| o.operation_id != "op-pub-1"),
        "committed op must not appear in nonterminal"
    );
}

/// Subprocess helper: when `STORE_JOURNAL_TEST_ROLE` is set, runs the named role
/// (writer, json_mutator) and exits. No-op on normal test runs.
#[doc(hidden)]
pub fn maybe_run_subprocess_helper() {
    let role = std::env::var("STORE_JOURNAL_TEST_ROLE").unwrap_or_default();
    match role.as_str() {
        "writer" => {
            let dir = std::env::var("STORE_JOURNAL_TEST_DIR")
                .expect("STORE_JOURNAL_TEST_DIR must be set for writer role");
            let anchor = std::path::PathBuf::from(&dir);
            let output_path = anchor.join("output.txt");
            let _guard =
                JournalLockGuard::acquire(&anchor).expect("subprocess: acquire advisory lock");
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&output_path)
                .expect("subprocess: open output.txt");
            use std::io::Write;
            writeln!(file, "from-writer").expect("subprocess: write");
            drop(file);
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::process::exit(0);
        }
        "json_mutator" => {
            let dir = std::env::var("STORE_JOURNAL_TEST_DIR")
                .expect("STORE_JOURNAL_TEST_DIR must be set for json_mutator role");
            let anchor = std::path::PathBuf::from(&dir);
            let agents_path = anchor.join("managed-agents.json");
            let _guard =
                JournalLockGuard::acquire(&anchor).expect("subprocess: acquire advisory lock");
            let mut records =
                decode_agent_store(&std::fs::read(&agents_path).expect("subprocess: read"))
                    .expect("subprocess: decode");
            records.extend(
                decode_agent_store(&minimal_agents_json("subprocess_agent"))
                    .expect("subprocess: new record"),
            );
            let payload = serde_json::to_vec_pretty(&records).expect("subprocess: serialize");
            atomic_write_with_fsync(&agents_path, &payload).expect("subprocess: write");
            std::process::exit(0);
        }
        _ => {}
    }
}

/// Subprocess entry-point check: when `STORE_JOURNAL_TEST_ROLE=writer` is set,
/// delegate to the helper (which writes and exits 0) before any other test
/// discovery runs. Harmless no-op on normal test runs.
#[test]
fn subprocess_mode_check() {
    maybe_run_subprocess_helper();
}

/// Two real processes serialised by the advisory lock. Process A acquires,
/// writes "from-a\n", spawns B which blocks until A releases, then B writes.
/// Output must contain both lines in order.
#[test]
fn test_two_processes_serialised_by_advisory_lock() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    std::fs::create_dir_all(&anchor).unwrap();
    let output_path = anchor.join("output.txt");
    {
        let _guard = JournalLockGuard::acquire(&anchor).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&output_path)
            .unwrap();
        use std::io::Write;
        writeln!(file, "from-a").unwrap();
        drop(file);
        let exe = std::env::current_exe().expect("current_exe must be available in tests");
        let mut child = std::process::Command::new(&exe)
            .env("STORE_JOURNAL_TEST_ROLE", "writer")
            .env("STORE_JOURNAL_TEST_DIR", anchor.to_str().unwrap())
            .env("RUST_TEST_NOCAPTURE", "0")
            .arg("subprocess_mode_check")
            .arg("--test-threads=1")
            .spawn()
            .expect("failed to spawn writer subprocess");
        std::thread::sleep(std::time::Duration::from_millis(80));
        drop(_guard);
        let status = child.wait().expect("subprocess must finish");
        assert!(
            status.success(),
            "writer subprocess must exit 0, got {status:?}"
        );
    }

    let content = std::fs::read_to_string(&output_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec!["from-a", "from-writer"],
        "output must show A wrote first, then B: got {lines:?}"
    );
}

/// Two real processes, no lost update. Seed=1 record, A appends 1 under lock,
/// spawns B which blocks, B appends 1. Final count must be 3 (2 = lost-update).
#[test]
fn test_two_processes_no_lost_json_update() {
    let dir = tmp_dir();
    let anchor = dir.path().to_path_buf();
    std::fs::create_dir_all(&anchor).unwrap();
    let agents_path = anchor.join("managed-agents.json");
    std::fs::write(&agents_path, minimal_agents_json("seed_agent")).unwrap();
    {
        let _guard = JournalLockGuard::acquire(&anchor).unwrap();
        let mut records = decode_agent_store(&std::fs::read(&agents_path).unwrap()).unwrap();
        records.extend(decode_agent_store(&minimal_agents_json("process_a_agent")).unwrap());
        atomic_write_with_fsync(&agents_path, &serde_json::to_vec_pretty(&records).unwrap())
            .unwrap();
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = std::process::Command::new(&exe)
            .env("STORE_JOURNAL_TEST_ROLE", "json_mutator")
            .env("STORE_JOURNAL_TEST_DIR", anchor.to_str().unwrap())
            .env("RUST_TEST_NOCAPTURE", "0")
            .arg("subprocess_mode_check")
            .arg("--test-threads=1")
            .spawn()
            .expect("spawn json_mutator");
        std::thread::sleep(std::time::Duration::from_millis(80));
        drop(_guard);
        assert!(
            child.wait().expect("subprocess wait").success(),
            "json_mutator failed"
        );
    }

    let records = decode_agent_store(&std::fs::read(&agents_path).unwrap()).unwrap();
    let pubkeys: Vec<&str> = records.iter().map(|r| r.pubkey.as_str()).collect();
    assert_eq!(records.len(), 3, "lost-update: got {pubkeys:?}");
    assert!(
        pubkeys.contains(&"seed_agent")
            && pubkeys.contains(&"process_a_agent")
            && pubkeys.contains(&"subprocess_agent"),
        "missing agent: {pubkeys:?}"
    );
}

/// Build a minimal well-formed `ManagedAgentRecord` JSON list with one record.
fn minimal_agents_json(pubkey: &str) -> Vec<u8> {
    let records: Vec<crate::managed_agents::ManagedAgentRecord> = serde_json::from_str(&format!(
        r#"[{{"pubkey":{pubkey:?},"name":"T","relay_url":"","acp_command":"","agent_command":"",
             "agent_args":[],"mcp_command":"","turn_timeout_seconds":0,
             "created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}}]"#
    ))
    .expect("minimal_agents_json");
    serde_json::to_vec_pretty(&records).expect("serialize")
}

fn empty_teams_json() -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!([])).unwrap()
}

fn insert_file_commit_phase_row(
    conn: &Connection,
    commit_id: &str,
    phase: &str,
    agents_stage: &str,
    teams_stage: &str,
) {
    conn.execute(
        "INSERT INTO file_commit_phases
             (commit_id, operation_id, phase,
              agents_stage_path, teams_stage_path,
              created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)",
        rusqlite::params![commit_id, commit_id, phase, agents_stage, teams_stage],
    )
    .unwrap();
}

/// Three crash scenarios for the two-phase file-commit protocol (intent,
/// first_renamed+pending, first_renamed+done), driven by `run_boot_recovery_at`.
#[test]
#[allow(clippy::type_complexity)]
fn test_crash_recovery_file_commit_phases() {
    use super::run_boot_recovery_at;

    // (phase, commit_id, [a_stage,t_stage,a_can,t_can] pre-exist, a_can post, t_can post, pubkey)
    let cases: &[(&str, &str, [bool; 4], bool, bool, &str)] = &[
        (
            "intent",
            "cc-1",
            [true, true, false, false],
            true,
            true,
            "crash1",
        ),
        (
            "first_renamed",
            "cc-2",
            [false, true, true, false],
            true,
            true,
            "crash2",
        ),
        (
            "first_renamed",
            "cc-3",
            [false, false, true, true],
            true,
            true,
            "crash3",
        ),
    ];

    fn wr(flag: bool, p: &std::path::Path, d: Vec<u8>) {
        if flag {
            std::fs::write(p, d).unwrap();
        }
    }

    for (phase, cid, pre, a_exists, t_exists, pk) in cases {
        let dir = tmp_dir();
        let anchor = dir.path().to_path_buf();
        let a_stage = anchor.join("managed-agents.json.stage");
        let t_stage = anchor.join("teams.json.stage");
        let a_can = anchor.join("managed-agents.json");
        let t_can = anchor.join("teams.json");
        wr(pre[0], &a_stage, minimal_agents_json(pk));
        wr(pre[1], &t_stage, empty_teams_json());
        wr(pre[2], &a_can, minimal_agents_json(pk));
        wr(pre[3], &t_can, empty_teams_json());
        let j = open_journal(&anchor).unwrap();
        insert_file_commit_phase_row(
            &j,
            cid,
            phase,
            a_stage.to_str().unwrap(),
            t_stage.to_str().unwrap(),
        );
        drop(j);
        run_boot_recovery_at(&anchor, None).unwrap();
        assert_eq!(a_can.exists(), *a_exists, "{pk} agents_can");
        assert_eq!(t_can.exists(), *t_exists, "{pk} teams_can");
        if *a_exists {
            let recs = decode_agent_store(&std::fs::read(&a_can).unwrap()).unwrap();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].pubkey, *pk);
        }
    }
}
