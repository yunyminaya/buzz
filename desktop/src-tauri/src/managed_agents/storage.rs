use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use tauri::{AppHandle, Manager};

use crate::app_state::keyring_service;
use crate::managed_agents::{
    ManagedAgentRecord, ManagedAgentRuntimeKey, ManagedAgentRuntimeReceipt,
};
use crate::secret_store::{KeyringProbe, SecretStore};

/// Keyring key name for an agent's nsec, namespaced from the human identity
/// key (`"identity"`) which shares the service.
fn agent_keyring_name(pubkey: &str) -> String {
    format!("agent:{pubkey}")
}

/// The agent secret store. `None` when the build has no keyring backend, in
/// which case agent keys stay inline in the `0o600` JSON file. Uses
/// `SecretStore::shared` so identity and agent callers share one instance —
/// and therefore one in-memory cache and one mutex — preventing last-writer-wins
/// races on concurrent blob writes.
fn agent_secret_store() -> Option<&'static SecretStore> {
    if cfg!(feature = "system-keyring") {
        Some(SecretStore::shared(keyring_service()))
    } else {
        None
    }
}

pub fn managed_agents_base_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("failed to resolve app data dir: {error}"))?
        .join("agents");
    fs::create_dir_all(&dir).map_err(|error| format!("failed to create agents dir: {error}"))?;
    Ok(dir)
}

#[allow(dead_code)]
pub(crate) fn managed_agents_store_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(managed_agents_base_dir(app)?.join("managed-agents.json"))
}

fn managed_agents_logs_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = managed_agents_base_dir(app)?.join("logs");
    fs::create_dir_all(&dir).map_err(|error| format!("failed to create logs dir: {error}"))?;
    Ok(dir)
}

/// Install-log path for `runtime_id`, alongside the agent logs.
pub fn install_log_path(app: &AppHandle, runtime_id: &str) -> Result<PathBuf, String> {
    Ok(managed_agents_logs_dir(app)?.join(install_log_filename(runtime_id)?))
}

/// Filename for a runtime's install log, or an error for an id that must not
/// become one.
///
/// The id is validated rather than trusted: ids reach this from user-defined
/// custom harnesses as well as the catalog, and a `../` or a separator in one
/// would place the log outside the logs directory. Rejecting beats sanitizing —
/// a rejected id means no log, while a rewritten one could collide with another
/// runtime's.
fn install_log_filename(runtime_id: &str) -> Result<String, String> {
    if runtime_id.is_empty() || !runtime_id.chars().all(is_safe_id_char) {
        return Err(format!(
            "unsafe runtime id for a log filename: {runtime_id}"
        ));
    }
    Ok(format!("install-{runtime_id}.log"))
}

/// Characters allowed in a runtime id used as a filename. Excludes `/`, `\`,
/// `:` and `.`, so no id can traverse or escape the logs directory.
fn is_safe_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

pub fn managed_agent_log_path(app: &AppHandle, pubkey: &str) -> Result<PathBuf, String> {
    Ok(managed_agents_logs_dir(app)?.join(format!("{pubkey}.log")))
}

/// Pair-scoped log path for a managed runtime. The relay URL never appears in
/// the filename; the suffix is a hash of the canonical URL.
pub fn managed_agent_runtime_log_path(
    app: &AppHandle,
    key: &ManagedAgentRuntimeKey,
) -> Result<PathBuf, String> {
    Ok(managed_agents_logs_dir(app)?.join(format!("{}.log", key.runtime_id())))
}

/// Log path to surface for an agent whose runtime is not tracked in memory:
/// the most recently written of its pair-scoped logs, falling back to the
/// legacy single-runtime path when the agent has not run since harnesses
/// became per (agent, relay) pair.
pub fn latest_managed_agent_log_path(app: &AppHandle, pubkey: &str) -> Result<PathBuf, String> {
    match newest_agent_log_in_dir(&managed_agents_logs_dir(app)?, pubkey) {
        Some(path) => Ok(path),
        None => managed_agent_log_path(app, pubkey),
    }
}

/// Newest log in `dir` belonging to `pubkey` — either a pair-scoped
/// `{pubkey}__{relay_hash}.log` or the legacy `{pubkey}.log`. Ties break
/// toward the higher filename so the choice is deterministic.
fn newest_agent_log_in_dir(dir: &Path, pubkey: &str) -> Option<PathBuf> {
    let legacy_name = format!("{pubkey}.log");
    let pair_prefix = format!("{pubkey}__");
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let matches = name.to_str().is_some_and(|name| {
                name == legacy_name || (name.starts_with(&pair_prefix) && name.ends_with(".log"))
            });
            if !matches {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, name, entry.path()))
        })
        .max_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)))
        .map(|(_, _, path)| path)
}

/// The keyring operations the migration chokepoint needs. Abstracted so the
/// migrate-and-strip decision logic ([`migrate_inline_key`]) can be unit-tested
/// against a fake without touching the live OS keyring.
trait KeyStore {
    fn probe(&self, name: &str) -> KeyringProbe;
    /// Read a key. `Ok(None)` is "no such entry" (absent); `Err` is a backend
    /// failure (keyring unreachable) — the caller MUST NOT collapse the two.
    fn load(&self, name: &str) -> Result<Option<String>, String>;
    /// Read the entire blob as a map without any side effects.
    /// `Ok(None)` when no blob exists yet; `Err` only on backend failure.
    /// Callers must not call `migrate_legacy_key` — this is a read-only view.
    fn load_all_readonly(&self) -> Result<Option<HashMap<String, String>>, String>;
    /// Write `value` and read it back to confirm before the caller strips the
    /// inline copy.
    fn write_and_verify(&self, name: &str, value: &str) -> Result<(), String>;
    /// Insert all entries from `entries` in a single blob mutation.
    fn store_all(&self, entries: &HashMap<String, String>) -> Result<(), String>;
}

impl KeyStore for SecretStore {
    fn probe(&self, name: &str) -> KeyringProbe {
        SecretStore::probe(self, name)
    }
    fn load(&self, name: &str) -> Result<Option<String>, String> {
        SecretStore::load(self, name)
    }
    fn load_all_readonly(&self) -> Result<Option<HashMap<String, String>>, String> {
        SecretStore::load_all_readonly(self)
    }
    fn write_and_verify(&self, name: &str, value: &str) -> Result<(), String> {
        self.store(name, value)?;
        match self.load(name)? {
            Some(stored) if stored == value => Ok(()),
            _ => Err("keyring read-back verify failed".to_string()),
        }
    }
    fn store_all(&self, entries: &HashMap<String, String>) -> Result<(), String> {
        SecretStore::store_all(self, entries)
    }
}

/// Outcome of attempting to lift a record's inline key into the keyring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyMigration {
    /// Written to the keyring and read-back verified. Safe to drop the inline
    /// copy when serializing.
    Persisted,
    /// Could not persist (keyring unreachable, or write/verify failed). The key
    /// must stay inline (0o600 file fallback); do NOT drop it.
    KeptInline,
    /// The record carried no inline key, so there was nothing to migrate. Kept
    /// distinct from [`KeyMigration::Persisted`] so an empty key is never
    /// mistaken for "verified present in the keyring" — an empty key after a
    /// keyring outage means the secret is currently unavailable, not persisted.
    Nothing,
}

/// Attempt to lift one record's inline key into the keyring with read-back
/// verify. Pure decision logic — does NOT mutate the record, so the caller
/// chooses whether to strip the inline copy based on the returned outcome.
///
/// The single source of truth for the migrate-vs-keep decision, shared by the
/// load-time opportunistic re-migrate ([`hydrate_keys`]) and the save-time
/// chokepoint ([`persist_agent_keys`]). An empty key returns
/// [`KeyMigration::Nothing`] — never [`KeyMigration::Persisted`], so a record
/// left empty by a keyring outage is not mistaken for one verified present.
fn migrate_inline_key(store: &impl KeyStore, record: &ManagedAgentRecord) -> KeyMigration {
    if record.private_key_nsec.is_empty() {
        return KeyMigration::Nothing;
    }
    let name = agent_keyring_name(&record.pubkey);
    match store.probe(&name) {
        // Keyring down this boot: keep the key inline (file fallback), do NOT
        // migrate — re-importing later could resurrect a rotated key.
        KeyringProbe::Unreachable => KeyMigration::KeptInline,
        KeyringProbe::Present | KeyringProbe::ReachableButEmpty => {
            match store.write_and_verify(&name, &record.private_key_nsec) {
                Ok(()) => KeyMigration::Persisted,
                Err(e) => {
                    eprintln!(
                        "buzz-desktop: keyring write for agent {} failed ({e}), keeping inline",
                        record.pubkey
                    );
                    KeyMigration::KeptInline
                }
            }
        }
    }
}

/// Refuse to spawn an agent whose private key is unavailable. Returns
/// `Some(error)` when `private_key_nsec` is empty — after [`hydrate_keys`] an
/// empty key means a keyring outage or a genuinely absent secret, NOT a
/// deliberately keyless agent. Spawning anyway would inject an empty
/// `BUZZ_PRIVATE_KEY`/`NOSTR_PRIVATE_KEY`, launching with no identity. Callers
/// (the spawn path) must fail closed (Wes storage.rs:158).
pub(crate) fn spawn_key_refusal(record: &ManagedAgentRecord) -> Option<String> {
    record.private_key_nsec.is_empty().then(|| {
        format!(
            "agent {} has no private key available — the OS keyring may be unreachable. \
             Refusing to start without an identity; retry once the keyring is reachable.",
            record.pubkey
        )
    })
}

/// Read from `agents_path`. Caller must hold the advisory lock.
fn load_agent_store_locked(
    _anchor: &std::path::Path,
    agents_path: &std::path::Path,
) -> Result<Vec<ManagedAgentRecord>, String> {
    if !agents_path.exists() {
        return Ok(Vec::new());
    }
    let bytes =
        fs::read(agents_path).map_err(|error| format!("failed to read agent store: {error}"))?;
    crate::managed_agents::store_journal::decode_agent_store(&bytes).map_err(|e| {
        // Fail loudly and preserve the evidence: a later in-app save rewrites
        // this file wholesale, which would silently destroy a malformed hand
        // edit. Best-effort file-authoring contract (see managed_agents::
        // reconcile): the broken content survives as `.invalid` for the user
        // to recover, and the parse error propagates instead of being
        // swallowed into an empty store.
        backup_invalid_store(agents_path);
        format!(
            "failed to parse agent store (preserved as .invalid): {}",
            e.message
        )
    })
}

/// Read the raw unified store — keyed instances AND key-less definitions —
/// with fail-loud parse handling. Internal seam; public readers filter.
///
/// Acquires the B1 advisory store lock so this call is serialized against
/// concurrent writers from other processes.  The in-process mutex
/// (`AppState::managed_agents_store_lock`) is held by callers at the
/// command level; the OS advisory lock here closes the cross-process gap.
fn load_agent_store(app: &AppHandle) -> Result<Vec<ManagedAgentRecord>, String> {
    let anchor = crate::managed_agents::store_journal::store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor).map_err(|e| format!("failed to create anchor dir: {e}"))?;
    let _advisory = crate::managed_agents::store_journal::JournalLockGuard::acquire(&anchor)?;
    let agents_path = anchor.join("managed-agents.json");
    load_agent_store_locked(&anchor, &agents_path)
}

/// Load the keyed agent *instances*. Key-less definitions (former personas,
/// folded into the same store) are filtered out so every pre-fold call site
/// keeps seeing exactly the records it always did.
///
/// NOTE: This function acquires and immediately releases the OS advisory lock.
/// For read-only contexts where the in-process mutex is already held, this is
/// safe.  For any path that follows with a `save_managed_agents` call, use
/// `mutate_managed_agents` instead so the OS lock is held across the full
/// read → mutate → write sequence.
pub fn load_managed_agents(app: &AppHandle) -> Result<Vec<ManagedAgentRecord>, String> {
    let mut records = load_agent_store(app)?;
    records.retain(|record| !record.pubkey.is_empty());
    hydrate_keys(&mut records);
    Ok(records)
}

/// Load the key-less agent *definitions* (former personas) from the unified
/// store. The persona compatibility shim (`load_personas`) presents these in
/// the legacy shape via `to_definition_view`.
pub(crate) fn load_agent_definitions(app: &AppHandle) -> Result<Vec<ManagedAgentRecord>, String> {
    let mut records = load_agent_store(app)?;
    records.retain(|record| record.pubkey.is_empty());
    Ok(records)
}

/// Preserve a malformed store file as `<name>.invalid` before the error path
/// unwinds. Copy, not rename: the original stays in place so repeated boots
/// keep failing loudly (rename would make the next launch look like a fresh
/// install and mint an empty store over the evidence). Overwrites any prior
/// `.invalid` — the newest broken content is the one worth keeping. Failure
/// here is logged and swallowed; it must never mask the parse error itself.
pub(crate) fn backup_invalid_store(path: &Path) {
    let backup = path.with_extension("json.invalid");
    if let Err(e) = fs::copy(path, &backup) {
        eprintln!(
            "buzz-desktop: failed to preserve malformed store {} as {}: {e}",
            path.display(),
            backup.display()
        );
    }
}

/// Fill in each record's in-memory `private_key_nsec` from the keyring, and
/// opportunistically re-migrate any key that is still inline.
///
/// - Empty key → fetch it from the keyring (the normal keyring-backed case).
/// - Non-empty key → the JSON carried it inline because the keyring was
///   unreachable at its last save. Re-migrate it now ([`migrate_inline_key`]):
///   if the keyring is reachable this boot, write-verify-strip so the next save
///   writes clean JSON and plaintext stops lingering on disk; if still
///   unreachable, leave it inline. This makes the strip deterministic on the
///   next reachable boot rather than waiting for a non-deterministic save.
fn hydrate_keys(records: &mut [ManagedAgentRecord]) {
    let Some(store) = agent_secret_store() else {
        return;
    };
    hydrate_keys_with(store, records);
}

/// Testable core of [`hydrate_keys`], generic over the [`KeyStore`] seam.
///
/// A keyring LOAD error (`Err`) is an OUTAGE — distinct from `Ok(None)`
/// (genuinely absent). On an outage the key is left empty and the record is
/// surfaced as unavailable rather than silently swallowed: callers must refuse
/// to spawn an agent whose key could not be read (see the empty-key bail in
/// `spawn_agent_child`). Empty here never means "fine" — it means "no usable
/// key this boot."
fn hydrate_keys_with(store: &impl KeyStore, records: &mut [ManagedAgentRecord]) {
    for record in records.iter_mut() {
        // A key-less definition (no pubkey yet — unified agent model) has no
        // keyring entry by construction; keys are minted on first start.
        if record.pubkey.is_empty() {
            continue;
        }
        if record.private_key_nsec.is_empty() {
            match store.load(&agent_keyring_name(&record.pubkey)) {
                Ok(Some(nsec)) => record.private_key_nsec = nsec,
                Ok(None) => {
                    eprintln!(
                        "buzz-desktop: agent {} has no key in JSON or keyring",
                        record.pubkey
                    );
                }
                // Outage, NOT absence: the key may exist in the keyring but is
                // unreadable this boot. Leave it empty so the spawn path
                // refuses rather than launching with no identity.
                Err(e) => {
                    eprintln!(
                        "buzz-desktop: agent {} key unavailable — keyring read failed ({e}); \
                         agent will be refused until the keyring is reachable",
                        record.pubkey
                    );
                }
            }
        } else {
            // Inline residue from a prior keyring-unreachable save. Lift it
            // into the keyring now (side effect) but KEEP it in memory — the
            // returned record must carry the key for readers. The next save
            // then strips it from JSON. Outcome is intentionally ignored:
            // on failure the key simply stays inline until a later boot.
            let _ = migrate_inline_key(store, record);
        }
    }
}

/// Atomically mutate the **instance** half of the agent store via a closure,
/// holding the OS advisory lock across fresh-decode → mutation → write.
/// `mutation` receives instances WITHOUT keyring hydration (keys stay as-is
/// from JSON — the closure works with the raw records and must not call
/// keyring APIs).  After the file write the advisory lock is released and
/// THEN keyring operations run outside all critical sections.
///
/// Returns `(T, guard)` so post-write work can run inside the in-process lock.
pub fn mutate_agent_store<'g, F, T>(
    app: &AppHandle,
    store_mutex_guard: std::sync::MutexGuard<'g, ()>,
    mutation: F,
) -> Result<(T, std::sync::MutexGuard<'g, ()>), String>
where
    F: FnOnce(
        Vec<ManagedAgentRecord>,
        &rusqlite::Connection,
    ) -> Result<(Vec<ManagedAgentRecord>, T), String>,
{
    crate::managed_agents::store_journal::mutate_store(app, store_mutex_guard, move |st| {
        // Present instances to the closure WITHOUT keyring hydration: keyring
        // I/O is prohibited inside the critical section.  The closure is
        // responsible for not calling hydrate_keys or persist_agent_keys.
        let instances: Vec<ManagedAgentRecord> = st
            .agents
            .iter()
            .filter(|r| !r.pubkey.is_empty())
            .cloned()
            .collect();

        let defs: Vec<ManagedAgentRecord> = st
            .agents
            .into_iter()
            .filter(|r| r.pubkey.is_empty())
            .collect();
        let teams = st.teams;

        let (mut new_instances, result) = mutation(instances, st.journal)?;

        // Sort instances (no keyring I/O here — keys stay as-is from mutation).
        new_instances.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.pubkey.cmp(&b.pubkey))
        });

        let mut all_defs = defs;
        all_defs.sort_by(|a, b| a.slug.cmp(&b.slug));
        let mut all = all_defs;
        all.extend(new_instances);

        Ok((all, teams, result))
    })
}

/// Atomically mutate a single agent instance by pubkey, holding the OS
/// advisory lock across fresh-decode → find → update → write.
///
/// Returns `(modified_record_clone, guard)` on success.  Returns `Err` when
/// the agent is not found or the decode fails.
pub fn mutate_managed_agent<'g, F, T>(
    app: &AppHandle,
    store_mutex_guard: std::sync::MutexGuard<'g, ()>,
    pubkey: &str,
    update: F,
) -> Result<(ManagedAgentRecord, T, std::sync::MutexGuard<'g, ()>), String>
where
    F: FnOnce(&mut ManagedAgentRecord, &rusqlite::Connection) -> Result<T, String>,
{
    let pubkey = pubkey.to_owned();
    mutate_agent_store(app, store_mutex_guard, move |mut instances, journal| {
        let record = instances
            .iter_mut()
            .find(|r| r.pubkey == pubkey)
            .ok_or_else(|| format!("agent {pubkey} not found"))?;
        let extra = update(record, journal)?;
        let record_clone = record.clone();
        Ok((instances, (record_clone, extra)))
    })
    .map(|((record_clone, extra), guard)| (record_clone, extra, guard))
}

/// Atomically mutate the **team** half of the store via a closure, holding the
/// OS advisory lock across fresh-decode → mutation → write of both JSON files.
///
/// `mutation` receives the full current team list and the open journal
/// connection, and returns a modified team list plus an arbitrary result
/// value `T`.  The agents half is preserved exactly (pass-through).
///
/// Returns `(T, guard)` so the caller can perform post-write work while still
/// holding the in-process mutex.
pub fn mutate_team_store<'g, F, T>(
    app: &AppHandle,
    store_mutex_guard: std::sync::MutexGuard<'g, ()>,
    mutation: F,
) -> Result<(T, std::sync::MutexGuard<'g, ()>), String>
where
    F: FnOnce(
        Vec<crate::managed_agents::TeamRecord>,
        &rusqlite::Connection,
    ) -> Result<(Vec<crate::managed_agents::TeamRecord>, T), String>,
{
    crate::managed_agents::store_journal::mutate_store(app, store_mutex_guard, move |st| {
        let agents = st.agents;
        let (new_teams, result) = mutation(st.teams, st.journal)?;
        Ok((agents, new_teams, result))
    })
}

/// Write each record's in-memory key to the keyring and blank the inline copy
/// on success. Keys that cannot be persisted (keyring unreachable) stay inline
/// in the JSON. Mutates `records` (a save-local clone) — the caller's in-memory
/// records keep their keys.
fn persist_agent_keys(records: &mut [ManagedAgentRecord]) {
    let Some(store) = agent_secret_store() else {
        // No keyring backend: keys stay inline.
        return;
    };
    persist_agent_keys_with(store, records);
}

/// Write each record's in-memory key to the keyring, recording a journal
/// pre-image before each write so boot recovery can detect interrupted writes.
///
/// Each key write that finds a non-empty `private_key_nsec` gets a
/// `keyring_write` journal operation.  On success the operation advances to
/// `Committed`; on failure (keyring unreachable, write/verify error) it advances
/// to `Failed` and the key stays inline.  Best-effort: a journal error must
/// never block the actual keyring write — if the journal record fails we fall
/// back to the unwrapped path and log the hiccup.
#[allow(dead_code)] // B1 keyring-journal protocol — wired to compensation phase in B1.1
fn persist_agent_keys_journaled(
    records: &mut [ManagedAgentRecord],
    journal: &rusqlite::Connection,
) {
    let Some(store) = agent_secret_store() else {
        return;
    };
    for record in records.iter_mut() {
        if record.private_key_nsec.is_empty() {
            continue;
        }
        // Record a pre-image before the keyring write.
        let op_id = crate::managed_agents::store_journal::new_operation_id();
        // event_id = deterministic key based on op_id; payload = just the pubkey
        // bytes so boot recovery can identify which agent's key was mid-flight.
        let event_id = format!("keyring_write:{op_id}");
        let journal_ok = (|| -> Result<(), String> {
            crate::managed_agents::store_journal::insert_operation(
                journal,
                &op_id,
                "keyring_write",
                &record.pubkey,
                crate::managed_agents::store_journal::Generation::zero(),
            )?;
            crate::managed_agents::store_journal::insert_inbox_event(
                journal,
                &event_id,
                &op_id,
                record.pubkey.as_bytes(),
            )?;
            Ok(())
        })();
        if let Err(e) = journal_ok {
            eprintln!(
                "buzz-desktop: keyring-journal: pre-image record failed for {}: {e}",
                record.pubkey
            );
        }

        let outcome = migrate_inline_key(store, record);
        if outcome == KeyMigration::Persisted {
            record.private_key_nsec.clear();
        }

        // Advance the journal operation to reflect the actual outcome.
        let disposition = if outcome == KeyMigration::Persisted {
            crate::managed_agents::store_journal::Disposition::Committed
        } else {
            crate::managed_agents::store_journal::Disposition::Failed
        };
        let _ = crate::managed_agents::store_journal::advance_disposition(
            journal,
            &op_id,
            &crate::managed_agents::store_journal::Disposition::Pending,
            &disposition,
        );
    }
}

/// Public wrapper around [`persist_agent_keys`] for callers that build their
/// own record lists inside a `mutate_store` closure (e.g. `team_snapshot.rs`).
pub fn persist_agent_keys_pub(records: &mut [ManagedAgentRecord]) {
    persist_agent_keys(records);
}

/// Testable core of [`persist_agent_keys`], generic over the [`KeyStore`] seam.
fn persist_agent_keys_with(store: &impl KeyStore, records: &mut [ManagedAgentRecord]) {
    for record in records.iter_mut() {
        // Only a verified keyring entry lets us drop the inline copy. Both
        // other outcomes keep the key inline: `KeptInline` (keyring
        // unreachable) so it is not lost, and `Nothing` (empty key) because
        // there is no verified entry to claim. This is a save-local clone, so
        // callers keep their keys regardless.
        if migrate_inline_key(store, record) == KeyMigration::Persisted {
            record.private_key_nsec.clear();
        }
    }
}

/// One-time migration of agent keys from the production keyring service
/// (`"buzz-desktop"`) to the dev service (`"buzz-desktop-dev"`). Only runs
/// in debug builds — release builds never touch `"buzz-desktop"` from this
/// path.
///
/// Idempotent: skips any key that already exists in the dev service so
/// repeated boots after migration are no-ops. Leaves the production keyring
/// untouched — a dev build and a prod install can coexist without sharing
/// keys after this migration.
///
/// Call this at boot before `hydrate_keys` runs (i.e. before
/// `load_managed_agents` is called) so agents find their keys on first boot
/// after the service-name change.
#[cfg(debug_assertions)]
pub fn migrate_agent_keys_to_dev_service(app: &tauri::AppHandle) {
    if !cfg!(feature = "system-keyring") || keyring_service() != "buzz-desktop-dev" {
        return;
    }

    // Read the JSON store for pubkeys only — we want every instance
    // record without running hydrate_keys (which would try the dev
    // keyring that is empty, and log noisy "has no key" warnings).
    let records = match load_agent_store(app) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("buzz-desktop: keyring-dev-migration: cannot read agent store: {e}");
            return;
        }
    };

    let pubkeys: Vec<String> = records
        .into_iter()
        .filter(|r| !r.pubkey.is_empty())
        .map(|r| r.pubkey)
        .collect();
    // A fresh non-singleton store for the prod service — its own empty
    // cache so reads go to the OS keyring without polluting the dev
    // singleton's cache.
    let prod_store = crate::secret_store::SecretStore::keyring("buzz-desktop");
    let dev_store = crate::secret_store::SecretStore::shared(keyring_service());
    copy_agent_keys_between_stores(&pubkeys, &prod_store, dev_store);
}

/// Marker key stored inside the dev blob after a successful agent-key migration.
/// Its presence means all agent keys that existed in the prod service at
/// migration time have been copied; subsequent dev boots skip the migration
/// entirely (no prod keyring access).
#[cfg(debug_assertions)]
const DEV_MIGRATION_MARKER: &str = "_dev_migration_v1";

/// Testable core of [`migrate_agent_keys_to_dev_service`]: copy `agent:<pubkey>`
/// entries from `src` to `dst` for each pubkey, then write a migration-complete
/// marker so future boots skip the entire function with zero prod-keyring access.
///
/// On the first migration boot:
///   1. One `dst.load_all_readonly()` — dev blob read (1 keychain prompt)
///   2. One `src.load_all_readonly()` — prod blob read (1 keychain prompt)
///   3. One `dst.store_all()` — dev blob write (same service as #1; macOS may
///      skip the ACL prompt if the initial grant was "Always Allow")
///
/// On subsequent boots (marker already present):
///   1. One `dst.load_all_readonly()` — dev blob read (1 keychain prompt)
///      Returns immediately — prod keyring is NEVER accessed.
///
/// Idempotency: keys already present in `dst` are not overwritten (the agent
/// may have rotated their key in the dev service after initial migration).
/// New agents (pubkey not in `src`) are silently skipped — they will mint a
/// fresh key on their next onboarding run.
#[cfg(debug_assertions)]
fn copy_agent_keys_between_stores(pubkeys: &[String], src: &impl KeyStore, dst: &impl KeyStore) {
    // One read of the dev blob. If the migration-complete marker is present,
    // all prior agent keys are already in the dev service — skip entirely.
    let dst_map: HashMap<String, String> = match dst.load_all_readonly() {
        Ok(Some(map)) if map.contains_key(DEV_MIGRATION_MARKER) => {
            return; // already migrated: 0 prod keyring accesses
        }
        Ok(Some(map)) => map,
        Ok(None) => HashMap::new(),
        Err(e) => {
            eprintln!("buzz-desktop: keyring-dev-migration: cannot read dev keyring: {e}");
            return;
        }
    };
    // Skip production when a reset left no agents or onboarding created every dev key.
    let src_map: HashMap<String, String> = if pubkeys
        .iter()
        .all(|pubkey| dst_map.contains_key(&agent_keyring_name(pubkey)))
    {
        HashMap::new()
    } else {
        match src.load_all_readonly() {
            Ok(Some(map)) => map,
            Ok(None) => HashMap::new(), // prod has no blob yet — nothing to copy
            Err(e) => {
                eprintln!("buzz-desktop: keyring-dev-migration: cannot read prod keyring: {e}");
                return;
            }
        }
    };

    // Compute the set of entries to write: agent keys absent from dst, plus
    // the migration-complete marker.
    let mut to_write: HashMap<String, String> = HashMap::new();
    let mut copied = 0usize;
    for pubkey in pubkeys {
        let name = agent_keyring_name(pubkey);
        if dst_map.contains_key(&name) {
            continue; // already in dev service — do not overwrite (idempotent)
        }
        if let Some(nsec) = src_map.get(&name) {
            to_write.insert(name, nsec.clone());
            copied += 1;
        }
        // absent from src → new agent, will mint a fresh key
    }

    // Always write the marker so future boots skip the prod read entirely,
    // even when there were no keys to copy (empty dev environment).
    to_write.insert(DEV_MIGRATION_MARKER.to_string(), "done".to_string());

    if let Err(e) = dst.store_all(&to_write) {
        eprintln!("buzz-desktop: keyring-dev-migration: cannot write to dev keyring: {e}");
        return;
    }

    if copied > 0 {
        eprintln!(
            "buzz-desktop: keyring-dev-migration: copied {copied} agent key(s) from buzz-desktop"
        );
    }
}

/// Remove an agent's key from the keyring, returning an error on failure.
/// Used by the snapshot-import rollback path, which must surface cleanup
/// failures rather than swallowing them.
pub(crate) fn try_delete_agent_key(pubkey: &str) -> Result<(), String> {
    if let Some(store) = agent_secret_store() {
        store.delete(&agent_keyring_name(pubkey))
    } else {
        // No keyring backend — nothing to clean up.
        Ok(())
    }
}

/// Remove an agent's key from the keyring (best-effort). Called when an agent
/// is deleted so its secret does not linger in the OS store.
pub fn delete_agent_key(pubkey: &str) {
    if let Err(e) = try_delete_agent_key(pubkey) {
        eprintln!("buzz-desktop: failed to delete agent {pubkey} key from keyring: {e}");
    }
}

/// Atomic, symlink-preserving JSON write with fsync before rename.
/// Resolves symlinks so the tmp+rename happens at the real target path,
/// preserving any symlink at `path`.
///
/// Sequence: write tmp → fsync → rename over target.  The fsync ensures the
/// bytes survive a crash between the write and the rename; without it a torn
/// write could leave a zero-length or truncated file on the target path.
#[allow(dead_code)]
pub(crate) fn atomic_write_json(path: &Path, payload: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let tmp = resolved.with_extension("json.tmp");
    let mut file =
        std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    file.write_all(payload)
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    file.sync_all()
        .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, &resolved)
        .map_err(|e| format!("failed to rename {}: {e}", resolved.display()))
}

/// Atomic, symlink-preserving JSON write that creates the file `0o600` BEFORE
/// any bytes hit disk — closing the umask window the post-write `chmod` left
/// open. Used for `managed-agents.json`, which carries plaintext agent nsecs in
/// the keyringless fallback. Mirrors [`crate::app_state::save_key_file`].
///
/// Canonicalizes `path` first so the write lands at the real target, preserving
/// any symlink at `path` exactly like [`atomic_write_json`].
pub(crate) fn atomic_write_json_restricted(path: &Path, payload: &[u8]) -> Result<(), String> {
    use atomic_write_file::AtomicWriteFile;

    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut file = AtomicWriteFile::open(&resolved)
        .map_err(|e| format!("open {} for atomic write: {e}", resolved.display()))?;

    // Set owner-only permissions before writing the secret bytes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("set {} permissions: {e}", resolved.display()))?;
    }

    file.write_all(payload)
        .map_err(|e| format!("write {}: {e}", resolved.display()))?;
    file.commit()
        .map_err(|e| format!("commit {}: {e}", resolved.display()))
}

pub(crate) use crate::managed_agents::agent_log_files::{
    append_log_marker, meaningful_agent_error_from_log, open_install_log_file, open_log_file,
    read_log_tail, start_install_log_session, AgentLogError,
};

fn agent_pids_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = managed_agents_base_dir(app)?.join("agent-pids");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("failed to create agent-pids dir: {error}"))?;
    Ok(dir)
}

/// Persist a pair-scoped runtime receipt atomically. Callers must register the
/// process in memory in the same runtime transition; on write failure they must
/// terminate the child before releasing that transition.
pub fn write_agent_runtime_receipt(
    app: &AppHandle,
    receipt: &ManagedAgentRuntimeReceipt,
) -> Result<(), String> {
    let path = agent_pids_dir(app)?.join(format!("{}.json", receipt.key.runtime_id()));
    let payload = serde_json::to_vec(receipt)
        .map_err(|error| format!("failed to serialize runtime receipt: {error}"))?;
    atomic_write_json_restricted(&path, &payload)
}

pub fn remove_agent_runtime_receipt(app: &AppHandle, key: &ManagedAgentRuntimeKey) {
    if let Ok(dir) = agent_pids_dir(app) {
        let _ = fs::remove_file(dir.join(format!("{}.json", key.runtime_id())));
    }
}

pub fn remove_agent_runtime_receipt_path(path: &Path) {
    let _ = fs::remove_file(path);
}

pub fn read_all_agent_runtime_receipts(
    app: &AppHandle,
) -> Vec<(PathBuf, ManagedAgentRuntimeReceipt)> {
    let Ok(dir) = agent_pids_dir(app) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .filter_map(|entry| {
            let path = entry.path();
            let bytes = fs::read(&path).ok()?;
            serde_json::from_slice(&bytes)
                .ok()
                .map(|receipt| (path, receipt))
        })
        .collect()
}

/// Remove the PID file for an agent (e.g. on normal stop).
pub fn remove_agent_pid_file(app: &AppHandle, pubkey: &str) {
    if let Ok(dir) = agent_pids_dir(app) {
        let _ = fs::remove_file(dir.join(format!("{pubkey}.pid")));
    }
}

/// Read all PID files from `agent-pids/`, returning `(pubkey, pid)` pairs.
pub fn read_all_agent_pid_files(app: &AppHandle) -> Vec<(String, u32)> {
    let Ok(dir) = agent_pids_dir(app) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let pubkey = name.strip_suffix(".pid")?;
            let pid: u32 = fs::read_to_string(entry.path()).ok()?.trim().parse().ok()?;
            Some((pubkey.to_string(), pid))
        })
        .collect()
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
