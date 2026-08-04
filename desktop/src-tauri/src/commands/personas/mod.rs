use tauri::AppHandle;

use crate::{
    app_state::AppState,
    managed_agents::{
        current_instance_id, delete_agent_key, load_managed_agents, load_personas, load_teams,
        mutate_agent_store, mutate_persona_store, stop_managed_agent_process,
        sync_managed_agent_processes, try_regenerate_nest, validate_persona_activation_change,
        validate_persona_deletion, AgentDefinition, ManagedAgentRecord,
    },
    util::now_iso,
};

fn trim_required(value: &str, label: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(trimmed.to_string())
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|candidate| {
        let trimmed = candidate.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

mod pending;
pub(in crate::commands) use pending::retain_persona_pending;
pub(super) use pending::tombstone_persona_pending;
mod create;
pub use create::create_persona;
mod sharing;
pub use sharing::set_persona_shared;
pub use sharing::update_persona_and_publish;
mod update;
pub use update::update_persona;
mod inbound;
pub use inbound::reconcile_inbound_persona_event;

#[tauri::command]
pub async fn list_personas(app: AppHandle) -> Result<Vec<AgentDefinition>, String> {
    use tauri::Manager;
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let mut personas = load_personas(&app)?;
        pending::project_active_persona_sharing(&app, &state, &mut personas);
        Ok(personas)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}

#[cfg(test)]
mod delete_cascade_tests;

/// Return pubkeys of every managed agent whose definition is the given persona.
///
/// Pure helper used by `delete_persona` to determine which agent records to
/// cascade-delete. Extracted so the filtering logic can be unit-tested without
/// a full Tauri `AppHandle`.
fn collect_cascade_pubkeys(agents: &[ManagedAgentRecord], persona_id: &str) -> Vec<String> {
    agents
        .iter()
        .filter(|a| a.persona_id.as_deref() == Some(persona_id))
        .map(|a| a.pubkey.clone())
        .collect()
}

/// Names of cascade agents that are provider-deployed: non-local backend with
/// a live `backend_agent_id`.
///
/// Pure helper used by `delete_persona`'s pre-flight: the cascade is refused
/// while any exist, because deleting the local record would orphan the remote
/// deployment. Mirrors `delete_managed_agent`'s `force_remote_delete` guard.
fn collect_remote_deployed(
    agents: &[ManagedAgentRecord],
    cascade: &std::collections::HashSet<String>,
) -> Vec<String> {
    agents
        .iter()
        .filter(|a| {
            cascade.contains(&a.pubkey)
                && a.backend != crate::managed_agents::BackendKind::Local
                && a.backend_agent_id.is_some()
        })
        .map(|a| a.name.clone())
        .collect()
}

/// Remove cascade agents from `agents` and persist via the injectable `save`.
///
/// Extracted from `delete_persona` so unit tests can inject a failing save and
/// verify retry-safety without a full `AppHandle` mock: if `save` returns `Err`,
/// this function propagates it before the keyring deletions and tombstones that
/// appear after the `?` in the call site — nothing is destroyed and the command
/// is safe to retry.
///
/// Generic over `G` so callers that need the store guard returned by
/// `save_managed_agents` (which returns `Result<MutexGuard, String>`) can thread
/// it back; tests use `G = ()`.
#[cfg(test)]
fn commit_cascade_agents<G>(
    agents: &mut Vec<ManagedAgentRecord>,
    cascade: &std::collections::HashSet<String>,
    save: impl FnOnce(&[ManagedAgentRecord]) -> Result<G, String>,
) -> Result<G, String> {
    agents.retain(|a| !cascade.contains(&a.pubkey));
    save(agents)
}

#[tauri::command]
pub async fn delete_persona(id: String, app: AppHandle) -> Result<(), String> {
    use tauri::Manager;
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();

        {
            // Store lock held across all three phases.
            // Lock ordering: store lock (acquired here) → process lock (per-agent in Phase 2).
            let store_guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|error| error.to_string())?;

            // Load and validate the persona before any destructive work.
            let personas = load_personas(&app)?;
            let persona = personas
                .iter()
                .find(|record| record.id == id)
                .ok_or_else(|| format!("persona {id} not found"))?;
            let referenced_by_team = load_teams(&app)?.iter().any(|team| {
                team.persona_ids
                    .iter()
                    .any(|persona_id| persona_id == id.as_str())
            });
            validate_persona_deletion(persona, referenced_by_team)?;
            // Capture the coordinate before the record might leave the list. Only
            // reached for non-builtin, non-team personas (both rejected above),
            // so every deleted persona here is one this owner published.
            let d_tag = crate::managed_agents::persona_events::persona_d_tag(persona);

            // ── Phase 1: Stage ─────────────────────────────────────────────
            //
            // Load agents, sync process state, and build the cascade set. Lock
            // ordering: store lock (held) → process lock (acquired for sync,
            // then released before Phase 2 stops). Every fallible read/lock is
            // here; an error leaves all state intact and the command is retryable.
            let mut agents = load_managed_agents(&app)?;
            let sync_exited = {
                let mut runtimes = state
                    .managed_agent_processes
                    .lock()
                    .map_err(|error| error.to_string())?;
                sync_managed_agent_processes(
                    &mut agents,
                    &mut runtimes,
                    &current_instance_id(&app),
                )
                // runtimes drops here (process lock released before Phase 2).
            };
            // If sync detected exited processes, persist their exit state atomically.
            let store_guard = if sync_exited.0 {
                let synced = agents.clone();
                let ((), sg) = mutate_agent_store(&app, store_guard, move |mut instances, _j| {
                    // Apply the same exit-state updates to the freshly-decoded instances.
                    for updated in &synced {
                        if let Some(live) = instances.iter_mut().find(|r| r.pubkey == updated.pubkey) {
                            live.last_exit_code = updated.last_exit_code;
                            live.last_stopped_at = updated.last_stopped_at.clone();
                            live.updated_at = updated.updated_at.clone();
                        }
                    }
                    Ok((instances, ()))
                })?;
                sg
            } else {
                store_guard
            };
            for pk in &sync_exited.1 {
                state.clear_agent_session_caches(pk);
            }

            // Build the cascade set. HashSet for O(1) membership in Phase 3.
            let cascade: std::collections::HashSet<String> =
                collect_cascade_pubkeys(&agents, &id).into_iter().collect();

            // Remote-agent pre-flight: refuse the cascade before any destructive
            // work while any target is provider-deployed. Nothing in
            // create_managed_agent forbids a persona-linked provider agent, so
            // this must be a runtime guard, not an assumed invariant.
            let remote_deployed = collect_remote_deployed(&agents, &cascade);
            if !remote_deployed.is_empty() {
                return Err(format!(
                    "persona {id} has provider-deployed agent instances ({}); delete those agent instances first",
                    remote_deployed.join(", ")
                ));
            }

            // ── Phase 2: Stop ───────────────────────────────────────────────
            //
            // Best-effort stop each running cascade instance. Lock ordering:
            // store lock (held) → process lock acquired per-agent and released
            // between stops so the process lock is not held across the full poll
            // cycle (stop_managed_agent_process polls 100ms×10 before SIGKILL).
            //
            // Per-agent stop errors are swallowed — these records are deleted in
            // Phase 3 regardless. Intentional difference from delete_managed_agent
            // (single-agent, fatal on stop failure); here the cascade is multi-agent
            // and deletion must proceed even if one instance cannot be stopped.
            for pk in &cascade {
                if let Some(rec) = agents.iter_mut().find(|a| a.pubkey == *pk) {
                    let mut runtimes = state
                        .managed_agent_processes
                        .lock()
                        .map_err(|error| error.to_string())?;
                    if let Err(e) = stop_managed_agent_process(&app, rec, &mut runtimes) {
                        eprintln!("buzz-desktop: delete_persona: failed to stop agent {pk}: {e}");
                    }
                    // runtimes drops here (per-agent, process lock not held across stops).
                }
            }

            // ── Phase 3: Commit ─────────────────────────────────────────────
            //
            // Disk-authoritative writes first, side effects strictly after.
            // Failure semantics:
            //   agent save fails   → nothing destroyed; full cascade retries cleanly
            //   persona save fails → cascade agents gone, persona survives; a retry
            //                        finds an empty cascade and proceeds cleanly
            // Keys and tombstones are enqueued only after their records leave disk.
            let store_guard = if !cascade.is_empty() {
                let cascade_for_closure = cascade.clone();
                let ((), sg) =
                    mutate_agent_store(&app, store_guard, move |mut instances, journal| {
                        // Tombstone each cascaded agent pubkey in the journal before
                        // removing the record — mirrors the single-agent delete path.
                        for pubkey in &cascade_for_closure {
                            if pubkey.is_empty() {
                                continue;
                            }
                            let (current_gen, _) =
                                crate::managed_agents::store_journal::read_generation(
                                    journal,
                                    pubkey,
                                )?;
                            crate::managed_agents::store_journal::tombstone_key(
                                journal,
                                pubkey,
                                current_gen,
                            )?;
                        }
                        instances.retain(|a| !cascade_for_closure.contains(&a.pubkey));
                        Ok((instances, ()))
                    })?;
                sg
            } else {
                store_guard
            };

            let id_for_closure = id.clone();
            let ((), _guard) =
                mutate_persona_store(&app, store_guard, move |mut defs| {
                    let original_len = defs.len();
                    defs.retain(|record| record.id != id_for_closure);
                    if defs.len() == original_len {
                        return Err(format!("persona {id_for_closure} not found"));
                    }
                    Ok((defs, ()))
                })?;

            // Side effects — strictly after records leave disk.
            for pk in &cascade {
                state.clear_agent_session_caches(pk);
                // Remove nsec from keyring after the record is gone.
                delete_agent_key(pk);
                // Propagate: no boot-reconcile fallback for tombstone/archive.
                super::agents::tombstone_managed_agent_pending(&app, &state, pk)
                    .map_err(|e| format!("persona-delete: agent tombstone failed for {pk}: {e}"))?;
                super::agents::archive_managed_agent_pending(&app, &state, pk)
                    .map_err(|e| format!("persona-delete: agent archive failed for {pk}: {e}"))?;
            }
            tombstone_persona_pending(&app, &state, &d_tag)
                .map_err(|e| format!("persona-delete: tombstone failed for {d_tag}: {e}"))?;

            // _store_guard drops here, before try_regenerate_nest.
        }

        try_regenerate_nest(&app);

        Ok(())
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}

#[tauri::command]
pub async fn set_persona_active(
    id: String,
    active: bool,
    app: AppHandle,
) -> Result<AgentDefinition, String> {
    use tauri::Manager;
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();

        // Load and validate before acquiring the store lock — load_personas may
        // call save_personas internally (built-in merge write-back) which also
        // acquires the lock; acquiring the lock first would deadlock.
        let mut personas = load_personas(&app)?;
        let persona = personas
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| format!("agent {id} not found"))?;

        let referenced_by_managed_agent = !active
            && load_managed_agents(&app)?
                .iter()
                .any(|agent| agent.persona_id.as_deref() == Some(id.as_str()));
        let referenced_by_team = !active
            && load_teams(&app)?.iter().any(|team| {
                team.persona_ids
                    .iter()
                    .any(|persona_id| persona_id == id.as_str())
            });

        validate_persona_activation_change(
            persona,
            active,
            referenced_by_managed_agent,
            referenced_by_team,
        )?;

        if persona.is_active == active {
            return Ok(persona.clone());
        }

        persona.is_active = active;
        persona.updated_at = now_iso();

        let updated = persona.clone();

        // Acquire the store lock for the write. load_personas above has already
        // flushed the built-in merge if needed, so no re-entrant lock risk here.
        let store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let id_for_closure = id.clone();
        let updated_at_for_closure = updated.updated_at.clone();
        let ((), _guard) = mutate_persona_store(&app, store_guard, move |mut defs| {
            if let Some(def) = defs.iter_mut().find(|d| d.id == id_for_closure) {
                def.is_active = active;
                def.updated_at = updated_at_for_closure;
            }
            Ok((defs, ()))
        })?;
        try_regenerate_nest(&app);
        Ok(updated)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}

pub(crate) const PNG_MAGIC: [u8; 4] = [0x89, 0x50, 0x4E, 0x47];
mod card;
mod snapshot;
pub use card::*;
#[cfg(test)]
pub(crate) use snapshot::import::decode_snapshot_from_bytes;
pub(crate) use snapshot::import::{
    parse_snapshot_payload_from_bytes, resolve_snapshot_import_behavior, MAX_SNAPSHOT_JSON_BYTES,
    MAX_SNAPSHOT_PNG_BYTES,
};
pub use snapshot::{confirm_agent_snapshot_import, preview_agent_snapshot_import};
pub use snapshot::{encode_agent_snapshot_for_send, export_agent_snapshot};
