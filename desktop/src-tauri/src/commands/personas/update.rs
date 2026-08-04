//! The persona edit command surface: `update_persona` (best-effort enqueue)
//! and the `update_persona_with` seam that `update_persona_and_publish` reuses
//! to await relay acceptance for the same save.

use tauri::AppHandle;

use crate::{
    app_state::AppState,
    managed_agents::{
        apply_persona_behavior, effective_agent_command, load_personas, managed_agent_avatar_url,
        mutate_persona_store, try_regenerate_nest, AgentDefinition, ManagedAgentRecord,
        UpdatePersonaRequest,
    },
    util::now_iso,
};

use super::{pending, retain_persona_pending, trim_optional, trim_required};

#[cfg(test)]
mod name_propagation_tests;

/// Return value of the `update_persona` command. Uses flatten so all
/// `AgentDefinition` fields appear at the top level of the JSON response —
/// backward-compatible with callers that already destructure a raw persona object.
#[derive(Debug, serde::Serialize)]
pub struct UpdatePersonaResult {
    #[serde(flatten)]
    persona: AgentDefinition,
}

/// Propagate a persona definition's display_name rename to linked agent instances.
/// Only instances whose current `name` equals `old_display_name` are updated;
/// pool-named instances (e.g. "Birch", "Compass") keep their individualised name.
/// Updates both `record.name` (relay display name) and `record.display_name`.
/// Returns the pubkeys of the records that were renamed.
fn propagate_persona_name_rename(
    records: &mut [ManagedAgentRecord],
    persona_id: &str,
    old_display_name: &str,
    new_display_name: &str,
) -> Vec<String> {
    let mut renamed = Vec::new();
    for record in records.iter_mut() {
        if record.persona_id.as_deref() != Some(persona_id) {
            continue;
        }
        if record.name != old_display_name {
            continue; // pool-named instance — keep its individualised name
        }
        record.name = new_display_name.to_string();
        record.display_name = Some(new_display_name.to_string());
        renamed.push(record.pubkey.clone());
    }
    renamed
}

/// Profile sync params collected under the store lock for async relay publish.
type ProfileSyncParams = Vec<(nostr::Keys, String, String, Option<String>, Option<String>)>;

#[tauri::command]
pub async fn update_persona(
    input: UpdatePersonaRequest,
    app: AppHandle,
) -> Result<UpdatePersonaResult, String> {
    let (persona, ()) = update_persona_with(input, app, |app, state, persona| {
        retain_persona_pending(app, state, persona);
        Ok(())
    })
    .await?;
    Ok(UpdatePersonaResult { persona })
}

/// Save an edited persona, hand the saved record to `retain` while the store
/// lock is still held, then sync the relay profiles of linked agent instances.
///
/// `retain` is the only difference between the two update commands:
/// [`update_persona`] enqueues best-effort, while
/// [`sharing::update_persona_and_publish`] prepares a strict publication and
/// returns the event so the caller can await relay acceptance.
pub(super) async fn update_persona_with<R: Send + 'static>(
    input: UpdatePersonaRequest,
    app: AppHandle,
    retain: impl FnOnce(&AppHandle, &AppState, &AgentDefinition) -> Result<R, String> + Send + 'static,
) -> Result<(AgentDefinition, R), String> {
    use tauri::Manager;

    // Phase 1: synchronous save (persona record + linked agent avatar updates)
    let (result, retained, profile_sync_params) = tokio::task::spawn_blocking({
        let app = app.clone();
        move || -> Result<(AgentDefinition, R, ProfileSyncParams), String> {
            let state = app.state::<AppState>();
            let display_name = trim_required(&input.display_name, "Display name")?;
            let system_prompt = input.system_prompt.clone();
            let avatar_url = trim_optional(input.avatar_url);
            let runtime = trim_optional(input.runtime);
            let model = trim_optional(input.model);
            let provider = trim_optional(input.provider);

            let store_guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|error| error.to_string())?;

            // Load personas for sharing projection before the closure.
            let mut personas_pre = load_personas(&app).unwrap_or_default();
            pending::project_active_persona_sharing(&app, &state, &mut personas_pre);

            // Validate the persona exists and capture pre-mutation context.
            let input_id = input.id.clone();
            let pre_persona = personas_pre
                .iter()
                .find(|record| record.id == input_id)
                .ok_or_else(|| format!("agent {} not found", input_id))?
                .clone();
            let avatar_changed = pre_persona.avatar_url != avatar_url;
            let name_changed = pre_persona.display_name != display_name;
            let old_display_name = pre_persona.display_name.clone();

            let input_id_c = input.id.clone();
            let display_name_c = display_name.clone();
            let avatar_url_c = avatar_url.clone();
            let system_prompt_c = system_prompt.clone();
            let runtime_c = runtime.clone();
            let model_c = model.clone();
            let provider_c = provider.clone();
            let name_pool_c = input
                .name_pool
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            let env_vars_c = input.env_vars.clone();
            let behavior_c = input.behavior.clone();
            let now_c = now_iso();

            let (result, store_guard_after_persona) =
                mutate_persona_store(&app, store_guard, move |mut defs| {
                    let persona = defs
                        .iter_mut()
                        .find(|record| record.id == input_id_c)
                        .ok_or_else(|| format!("agent {} not found", input_id_c))?;

                    persona.display_name = display_name_c;
                    persona.avatar_url = avatar_url_c;
                    persona.system_prompt = system_prompt_c;
                    persona.runtime = runtime_c;
                    persona.model = model_c;
                    persona.provider = provider_c;
                    persona.name_pool = name_pool_c;
                    if let Some(env_vars) = env_vars_c {
                        crate::managed_agents::validate_user_env_keys(&env_vars)?;
                        persona.env_vars = env_vars;
                    }
                    apply_persona_behavior(persona, behavior_c)?;
                    persona.updated_at = now_c;

                    let result = persona.clone();
                    Ok((defs, result))
                })?;

            let retained = retain(&app, &state, &result)?;
            try_regenerate_nest(&app);

            // If the avatar or display_name changed, propagate to linked agent
            // records and collect relay profile sync params for the async phase.
            let sync_params: ProfileSyncParams = if avatar_changed || name_changed {
                let mut params: ProfileSyncParams = Vec::new();
                let workspace_relay = crate::relay::relay_ws_url_with_override(&state);
                let result_clone = result.clone();
                let workspace_relay_clone = workspace_relay.clone();

                // Drop the persona-store guard before acquiring a fresh agent-store guard.
                drop(store_guard_after_persona);
                let store_guard2 = state
                    .managed_agents_store_lock
                    .lock()
                    .map_err(|e| e.to_string())?;

                let ((renamed, agent_sync_params), _guard) =
                    crate::managed_agents::mutate_agent_store(
                        &app,
                        store_guard2,
                        move |mut instances, _journal| {
                            let renamed: Vec<String> = if name_changed {
                                propagate_persona_name_rename(
                                    &mut instances,
                                    &result_clone.id,
                                    &old_display_name,
                                    &result_clone.display_name,
                                )
                            } else {
                                Vec::new()
                            };

                            let mut agent_params: ProfileSyncParams = Vec::new();
                            for record in instances.iter_mut() {
                                if record.persona_id.as_deref() != Some(&result_clone.id) {
                                    continue;
                                }
                                let mut record_changed = renamed.contains(&record.pubkey);

                                if avatar_changed {
                                    let effective_cmd = effective_agent_command(
                                        record.persona_id.as_deref(),
                                        std::slice::from_ref(&result_clone),
                                        record.agent_command_override.as_deref(),
                                    );
                                    record.avatar_url = result_clone
                                        .avatar_url
                                        .clone()
                                        .or_else(|| managed_agent_avatar_url(&effective_cmd));
                                    record_changed = true;
                                }

                                if record_changed {
                                    if let Ok(agent_keys) =
                                        nostr::Keys::parse(&record.private_key_nsec)
                                    {
                                        let relay_url = crate::relay::effective_agent_relay_url(
                                            &record.relay_url,
                                            &workspace_relay_clone,
                                        );
                                        agent_params.push((
                                            agent_keys,
                                            relay_url,
                                            record.name.clone(),
                                            record.avatar_url.clone(),
                                            record.auth_tag.clone(),
                                        ));
                                    }
                                }
                            }
                            Ok((instances, (renamed, agent_params)))
                        },
                    )?;

                if !renamed.is_empty() || avatar_changed {
                    // Load the fresh records for retain calls.
                    let fresh_records =
                        crate::managed_agents::load_managed_agents(&app).unwrap_or_default();
                    for record in fresh_records.iter().filter(|r| renamed.contains(&r.pubkey)) {
                        crate::commands::agents::retain_managed_agent_pending(
                            &app, &state, record, None,
                        );
                    }
                }
                params.extend(agent_sync_params);
                params
            } else {
                Vec::new()
            };

            Ok((result, retained, sync_params))
        }
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))??;

    // Phase 2: await relay profile sync for linked agents whose avatar or
    // display_name was just updated. We await (rather than fire-and-forget)
    // so the frontend cache invalidation that follows the mutation settlement
    // sees the fresh relay profile. Best-effort — failures are logged, not surfaced.
    if !profile_sync_params.is_empty() {
        let state = app.state::<AppState>();
        for (agent_keys, relay_url, display_name, avatar_url, auth_tag) in profile_sync_params {
            if let Err(e) = crate::relay::sync_managed_agent_profile(
                &state,
                &relay_url,
                &agent_keys,
                &display_name,
                avatar_url.as_deref(),
                auth_tag.as_deref(),
            )
            .await
            {
                eprintln!("buzz-desktop: relay profile sync failed after persona update: {e}");
            }
        }
    }

    Ok((result, retained))
}
