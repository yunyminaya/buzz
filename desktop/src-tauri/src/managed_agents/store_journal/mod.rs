//! B1 transactional managed-agents store substrate.
//!
//! `managed-agents.json` / `teams.json` stay the canonical user-visible files.
//! `store-journal.sqlite` (beside them, at the **store-family anchor**) holds
//! shared recovery facts: operation records, per-key generation / tombstone
//! metadata, immutable inbox/outbox rows.
//!
//! **Anchor**: canonical dev `agents/` dir for shared worktrees
//! (`BUZZ_SHARE_IDENTITY=1`); the bundle's own `agents/` dir for standalone.
//! Lock identity is never derived from a possibly-absent file.
//!
//! **Lock sequence**: in-process `AppState::managed_agents_store_lock` →
//! anchored OS advisory lock (`flock`/named-mutex) → fresh decode → mutation
//! closure → atomic fsync write → release.  Network I/O and keyring access
//! stay outside every critical section.
//!
//! **Posture**: protects against crashes and concurrent cooperating processes
//! on one machine only.  Does not defend against adversarial same-user
//! tampering, cross-machine duplication, supply-chain attack, mixed-version
//! writers, sign-out/reset races, or concurrent bundles.

mod anchor;
mod codec;
mod events;
mod generations;
mod lock;
mod operations;
mod schema;
mod txn;
mod util;
mod writer;

// ── Public re-exports ─────────────────────────────────────────────────────────

#[cfg(test)]
pub use anchor::canonical_dev_anchor_pub;
pub use anchor::store_anchor_dir;

#[cfg(test)]
#[allow(unused_imports)]
pub use codec::StoreDecodeError;
pub use codec::{decode_agent_record_permissive, decode_agent_store, decode_team_store};

pub use events::{insert_inbox_event, mark_outbox_published};
#[cfg(test)]
pub use events::{insert_outbox_event, read_inbox_events, read_outbox_events, InsertEventOutcome};

pub use generations::{cas_generation, read_generation, tombstone_key, CasOutcome, Generation};

pub use lock::JournalLockGuard;

pub use operations::{advance_disposition, insert_operation, Disposition};
#[cfg(test)]
#[allow(unused_imports)]
pub use operations::{
    pin_compensation, read_nonterminal_operations, read_operation, set_nonterminal_follow_up,
    OperationRecord, TransitionOutcome,
};

#[cfg(test)]
pub use schema::apply_journal_schema_pub;
pub use schema::open_journal;

pub use txn::{
    advance_to_committed, mutate_store, prepare_publication, run_boot_recovery,
    run_file_commit_recovery, StoreState,
};
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use txn::{file_commit_recovery_at_pub, read_store, run_boot_recovery_at};

pub use util::new_operation_id;

pub use writer::{atomic_write_restricted_with_fsync, atomic_write_with_fsync};

#[cfg(test)]
#[path = "../store_journal_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../store_journal_fix_tests.rs"]
mod fix_tests;
