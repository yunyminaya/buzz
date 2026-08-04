use tauri::AppHandle;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    managed_agents::{
        delete_team_with_cascade, ensure_persona_ids_are_active, load_personas, load_teams,
        storage::mutate_team_store, try_regenerate_nest, CreateTeamRequest, TeamRecord,
        UpdateTeamRequest,
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

/// Retain a freshly authored team event in the local store, flagged for relay
/// sync. Called inside a command's `managed_agents_store_lock`-held body after
/// saving teams; the background flush loop publishes it out-of-band.
///
/// Mirrors `commands::personas::retain_persona_pending`. Built-in teams are not
/// owner-authored, so the caller skips them — this helper assumes the team is
/// publishable.
///
/// Internal ordering (B1 journal protocol): outbox evidence inserted first via
/// `prepare_publication` before the retention row is set flushable.
pub(super) fn retain_team_pending(app: &AppHandle, state: &AppState, team: &TeamRecord) {
    use crate::managed_agents::{
        persona_events::monotonic_created_at,
        retention::{get_retained_event, open_retention_db},
        team_events::build_team_event,
    };
    use buzz_core_pkg::kind::KIND_TEAM;
    use nostr::JsonUtil;

    let result = (|| -> Result<(), String> {
        let scope = crate::managed_agents::retention::active_retention_scope(app, state)?;
        let conn = open_retention_db(&scope.db_path)?;
        let pubkey = scope.owner_keys.public_key().to_hex();
        // Monotonic created_at: bump past the retained head (NIP-AP step 3).
        let prior =
            get_retained_event(&conn, KIND_TEAM, &pubkey, &team.id)?.map(|row| row.created_at);
        let event = build_team_event(team)?
            .custom_created_at(monotonic_created_at(prior))
            .sign_with_keys(&scope.owner_keys)
            .map_err(|e| format!("failed to sign team event: {e}"))?;
        let event_id = event.id.to_hex();
        let raw_json = event.as_json();

        // B1 journal outbox: record immutable event identity before retention.
        let anchor = crate::managed_agents::store_journal::store_anchor_dir(app)?;
        std::fs::create_dir_all(&anchor)
            .map_err(|e| format!("create anchor dir for team outbox: {e}"))?;
        let journal = crate::managed_agents::store_journal::open_journal(&anchor)?;
        let pub_op_id = crate::managed_agents::store_journal::new_operation_id();
        crate::managed_agents::store_journal::insert_operation(
            &journal,
            &pub_op_id,
            "publish",
            &team.id,
            crate::managed_agents::store_journal::Generation::zero(),
        )?;

        crate::managed_agents::store_journal::prepare_publication(
            &journal,
            &conn,
            &pub_op_id,
            &event_id,
            &raw_json,
            KIND_TEAM,
            &pubkey,
            &team.id,
            &event.content,
            event.created_at.as_secs() as i64,
        )
    })();
    if let Err(e) = result {
        eprintln!("buzz-desktop: team-retain: {e}");
    }
}

/// Purge a deleted team's pending row and enqueue a NIP-09 tombstone, both
/// inside the `managed_agents_store_lock`-held delete body.
///
/// Mirrors `commands::personas::tombstone_persona_pending`: the team row is
/// purged first so an unpublished edit can never resurrect it after the
/// tombstone publishes, then the kind:5 tombstone is retained at its own
/// `(5, pubkey, d_tag)` coordinate with `pending_sync = 1`. Best-effort: a
/// failure is logged and swallowed so a retention hiccup never blocks the
/// disk-authoritative delete.
///
/// Internal ordering (B1 journal protocol): outbox evidence inserted first via
/// `prepare_publication` before the retention row is set flushable.
fn tombstone_team_pending(app: &AppHandle, state: &AppState, d_tag: &str) -> Result<(), String> {
    use crate::managed_agents::{
        retention::{delete_retained_event, open_retention_db, tombstone_retention_d_tag},
        team_events::build_team_delete,
    };
    use buzz_core_pkg::kind::KIND_TEAM;
    use nostr::JsonUtil;

    const KIND_DELETE: u32 = 5;

    let scope = crate::managed_agents::retention::active_retention_scope(app, state)?;
    let pubkey = scope.owner_keys.public_key().to_hex();
    let event = build_team_delete(d_tag, &pubkey)?
        .sign_with_keys(&scope.owner_keys)
        .map_err(|e| format!("failed to sign team tombstone: {e}"))?;
    let event_id = event.id.to_hex();
    let raw_json = event.as_json();
    let tombstone_d_tag = tombstone_retention_d_tag(KIND_TEAM, d_tag);

    let conn = open_retention_db(&scope.db_path)?;
    delete_retained_event(&conn, KIND_TEAM, &pubkey, d_tag)?;

    // B1 journal outbox: record immutable tombstone identity before retention.
    let anchor = crate::managed_agents::store_journal::store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor)
        .map_err(|e| format!("create anchor dir for team tombstone outbox: {e}"))?;
    let journal = crate::managed_agents::store_journal::open_journal(&anchor)?;
    let pub_op_id = crate::managed_agents::store_journal::new_operation_id();
    crate::managed_agents::store_journal::insert_operation(
        &journal,
        &pub_op_id,
        "tombstone",
        d_tag,
        crate::managed_agents::store_journal::Generation::zero(),
    )?;

    crate::managed_agents::store_journal::prepare_publication(
        &journal,
        &conn,
        &pub_op_id,
        &event_id,
        &raw_json,
        KIND_DELETE,
        &pubkey,
        &tombstone_d_tag,
        &event.content,
        event.created_at.as_secs() as i64,
    )
}

#[tauri::command]
pub async fn list_teams(app: AppHandle) -> Result<Vec<TeamRecord>, String> {
    use tauri::Manager;
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        load_teams(&app)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}

#[tauri::command]
pub async fn create_team(input: CreateTeamRequest, app: AppHandle) -> Result<TeamRecord, String> {
    use tauri::Manager;
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let name = trim_required(&input.name, "Team name")?;
        let description = trim_optional(input.description);
        let instructions = trim_optional(input.instructions);
        let now = now_iso();

        let store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let personas = load_personas(&app)?;
        ensure_persona_ids_are_active(&personas, &input.persona_ids)?;
        let team = TeamRecord {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            instructions,
            persona_ids: input.persona_ids,
            is_builtin: false,
            source_dir: None,
            is_symlink: false,
            symlink_target: None,
            version: None,
            created_at: now.clone(),
            updated_at: now,
        };
        let team_for_closure = team.clone();
        let team_id_for_closure = team.id.clone();
        let ((), _guard) = mutate_team_store(&app, store_guard, move |mut teams, journal| {
            // Journal: record create operation + CAS generation for this team id.
            let op_id = crate::managed_agents::store_journal::new_operation_id();
            crate::managed_agents::store_journal::insert_operation(
                journal,
                &op_id,
                "create",
                &team_id_for_closure,
                crate::managed_agents::store_journal::Generation::zero(),
            )?;
            match crate::managed_agents::store_journal::cas_generation(
                journal,
                &team_id_for_closure,
                crate::managed_agents::store_journal::Generation::zero(),
            )? {
                crate::managed_agents::store_journal::CasOutcome::Committed { .. } => {}
                crate::managed_agents::store_journal::CasOutcome::Tombstoned { .. } => {
                    return Err(format!(
                        "team {team_id_for_closure}: id previously tombstoned — cannot recreate"
                    ));
                }
                crate::managed_agents::store_journal::CasOutcome::Conflict { current } => {
                    return Err(format!(
                        "team {team_id_for_closure}: generation conflict (expected 0, current {})",
                        current.0
                    ));
                }
            }
            teams.push(team_for_closure);
            Ok((teams, ()))
        })?;
        // Created teams are always non-builtin; publish to the relay.
        retain_team_pending(&app, &state, &team);
        Ok(team)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}

#[tauri::command]
pub async fn update_team(input: UpdateTeamRequest, app: AppHandle) -> Result<TeamRecord, String> {
    use tauri::Manager;
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let name = trim_required(&input.name, "Team name")?;
        let description = trim_optional(input.description);
        let instructions = trim_optional(input.instructions);

        let store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let personas = load_personas(&app)?;
        ensure_persona_ids_are_active(&personas, &input.persona_ids)?;
        let target_id = input.id.clone();
        let now2 = now_iso();
        let (updated, _guard) = mutate_team_store(&app, store_guard, move |mut teams, journal| {
            let team = teams
                .iter_mut()
                .find(|record| record.id == target_id)
                .ok_or_else(|| format!("team {target_id} not found"))?;
            // Read the current generation and CAS to next — detects concurrent
            // writes from another process holding the same advisory lock.
            let op_id = crate::managed_agents::store_journal::new_operation_id();
            let (current_gen, _) =
                crate::managed_agents::store_journal::read_generation(journal, &target_id)?;
            crate::managed_agents::store_journal::insert_operation(
                journal,
                &op_id,
                "update",
                &target_id,
                current_gen,
            )?;
            match crate::managed_agents::store_journal::cas_generation(
                journal,
                &target_id,
                current_gen,
            )? {
                crate::managed_agents::store_journal::CasOutcome::Committed { .. } => {}
                crate::managed_agents::store_journal::CasOutcome::Tombstoned { .. } => {
                    return Err(format!("team {target_id}: tombstoned — cannot update"));
                }
                crate::managed_agents::store_journal::CasOutcome::Conflict { current } => {
                    return Err(format!(
                        "team {target_id}: generation conflict (expected {}, current {})",
                        current_gen.0, current.0
                    ));
                }
            }
            team.name = name;
            team.description = description;
            team.instructions = instructions;
            team.persona_ids = input.persona_ids;
            team.updated_at = now2;
            let updated = team.clone();
            Ok((teams, updated))
        })?;
        // Built-in teams are not owner-authored — never publish them.
        if !updated.is_builtin {
            retain_team_pending(&app, &state, &updated);
        }
        Ok(updated)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}

#[tauri::command]
pub async fn delete_team(id: String, app: AppHandle) -> Result<(), String> {
    use tauri::Manager;
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let store_guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        let (cascaded_persona_d_tags, _guard) = delete_team_with_cascade(&app, &id, store_guard)?;
        // delete_team_with_cascade rejects built-in teams via validate_team_deletion,
        // so reaching here means this team was owner-published — tombstone it. The
        // d_tag is the team id, captured before the record left the store.
        // Propagate: no boot-reconcile fallback for tombstones.
        tombstone_team_pending(&app, &state, &id).map_err(|e| {
            format!("team deleted but tombstone failed — relay record may persist: {e}")
        })?;
        // Tombstone the cascaded personas too, so their orphaned kind:30175 heads
        // don't linger on the relay (F4). Each d-tag was captured pre-removal.
        for persona_d_tag in &cascaded_persona_d_tags {
            super::personas::tombstone_persona_pending(&app, &state, persona_d_tag).map_err(
                |e| format!("team-delete: persona tombstone failed for {persona_d_tag}: {e}"),
            )?;
        }
        try_regenerate_nest(&app);
        Ok(())
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))?
}
