use std::sync::atomic::Ordering;
use tauri::{AppHandle, Manager, State};

use crate::{
    app_state::AppState,
    managed_agents::{
        build_managed_agent_summary, current_instance_id, load_personas, mutate_agent_store,
        sync_managed_agent_processes, ManagedAgentSummary,
    },
    util::now_iso,
};

#[tauri::command]
pub fn set_agent_managed_profiles(enabled: bool, state: State<'_, AppState>) {
    state
        .managed_agent_profile_reconcile_enabled
        .store(!enabled, Ordering::Release);
}

#[tauri::command]
pub async fn set_managed_agent_start_on_app_launch(
    pubkey: String,
    start_on_app_launch: bool,
    app: AppHandle,
) -> Result<ManagedAgentSummary, String> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let mut runtimes = state
            .managed_agent_processes
            .lock()
            .map_err(|error| error.to_string())?;
        let instance_id = current_instance_id(&app);
        let personas = load_personas(&app).unwrap_or_default();
        let global_config =
            crate::managed_agents::load_global_agent_config(&app).unwrap_or_default();

        let app_for_closure = app.clone();
        let pubkey_for_closure = pubkey.clone();
        let ((summary, exited_pubkeys), _guard) =
            mutate_agent_store(&app, store_guard, move |mut instances, journal| {
                let (_, exited) =
                    sync_managed_agent_processes(&mut instances, &mut runtimes, &instance_id);
                let record = instances
                    .iter_mut()
                    .find(|r| r.pubkey == pubkey)
                    .ok_or_else(|| format!("agent {pubkey} not found"))?;
                // Journal: record update + CAS generation for this agent key.
                let op_id = crate::managed_agents::store_journal::new_operation_id();
                let (current_gen, _) = crate::managed_agents::store_journal::read_generation(
                    journal,
                    &pubkey_for_closure,
                )?;
                crate::managed_agents::store_journal::insert_operation(
                    journal,
                    &op_id,
                    "update",
                    &pubkey_for_closure,
                    current_gen,
                )?;
                match crate::managed_agents::store_journal::cas_generation(
                    journal,
                    &pubkey_for_closure,
                    current_gen,
                )? {
                    crate::managed_agents::store_journal::CasOutcome::Committed { .. } => {}
                    crate::managed_agents::store_journal::CasOutcome::Tombstoned { .. } => {
                        return Err(format!(
                            "agent {pubkey_for_closure}: tombstoned — cannot update settings"
                        ));
                    }
                    crate::managed_agents::store_journal::CasOutcome::Conflict { current } => {
                        return Err(format!(
                            "agent {pubkey_for_closure}: generation conflict (expected {}, current {})",
                            current_gen.0, current.0
                        ));
                    }
                }
                record.start_on_app_launch = start_on_app_launch;
                record.updated_at = now_iso();
                let summary = build_managed_agent_summary(
                    &app_for_closure,
                    record,
                    &runtimes,
                    &personas,
                    &global_config,
                )?;
                Ok((instances, (summary, exited)))
            })?;
        for pk in &exited_pubkeys {
            state.clear_agent_session_caches(pk);
        }
        Ok(summary)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}

#[tauri::command]
pub async fn set_managed_agent_auto_restart(
    pubkey: String,
    auto_restart_on_config_change: bool,
    app: AppHandle,
) -> Result<ManagedAgentSummary, String> {
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let mut runtimes = state
            .managed_agent_processes
            .lock()
            .map_err(|error| error.to_string())?;
        let instance_id = current_instance_id(&app);
        let personas = load_personas(&app).unwrap_or_default();
        let global_config =
            crate::managed_agents::load_global_agent_config(&app).unwrap_or_default();

        let app_for_closure = app.clone();
        let pubkey_for_closure2 = pubkey.clone();
        let ((summary, exited_pubkeys), _guard) =
            mutate_agent_store(&app, store_guard, move |mut instances, journal| {
                let (_, exited) =
                    sync_managed_agent_processes(&mut instances, &mut runtimes, &instance_id);
                let record = instances
                    .iter_mut()
                    .find(|r| r.pubkey == pubkey)
                    .ok_or_else(|| format!("agent {pubkey} not found"))?;
                // Journal: record update + CAS generation for this agent key.
                let op_id = crate::managed_agents::store_journal::new_operation_id();
                let (current_gen, _) = crate::managed_agents::store_journal::read_generation(
                    journal,
                    &pubkey_for_closure2,
                )?;
                crate::managed_agents::store_journal::insert_operation(
                    journal,
                    &op_id,
                    "update",
                    &pubkey_for_closure2,
                    current_gen,
                )?;
                match crate::managed_agents::store_journal::cas_generation(
                    journal,
                    &pubkey_for_closure2,
                    current_gen,
                )? {
                    crate::managed_agents::store_journal::CasOutcome::Committed { .. } => {}
                    crate::managed_agents::store_journal::CasOutcome::Tombstoned { .. } => {
                        return Err(format!(
                            "agent {pubkey_for_closure2}: tombstoned — cannot update settings"
                        ));
                    }
                    crate::managed_agents::store_journal::CasOutcome::Conflict { current } => {
                        return Err(format!(
                            "agent {pubkey_for_closure2}: generation conflict (expected {}, current {})",
                            current_gen.0, current.0
                        ));
                    }
                }
                record.auto_restart_on_config_change = auto_restart_on_config_change;
                record.updated_at = now_iso();
                let summary = build_managed_agent_summary(
                    &app_for_closure,
                    record,
                    &runtimes,
                    &personas,
                    &global_config,
                )?;
                Ok((instances, (summary, exited)))
            })?;
        for pk in &exited_pubkeys {
            state.clear_agent_session_caches(pk);
        }
        Ok(summary)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}
