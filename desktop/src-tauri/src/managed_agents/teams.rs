use std::{fs, path::PathBuf};

use tauri::AppHandle;

use crate::{
    managed_agents::{ManagedAgentRecord, TeamRecord},
    util::now_iso,
};

use super::team_repair::team_persona_key;

pub(crate) fn teams_store_path(app: &AppHandle) -> Result<PathBuf, String> {
    // Resolve through the B1 anchor so dev worktrees use the canonical shared
    // path and standalone bundles use their own — never derived from a
    // possibly-absent managed-agents.json.
    let anchor = crate::managed_agents::store_journal::store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor).map_err(|e| format!("failed to create anchor dir: {e}"))?;
    Ok(anchor.join("teams.json"))
}

fn sort_teams(records: &mut [TeamRecord]) {
    records.sort_by(|left, right| {
        let left_builtin = if left.is_builtin { 0 } else { 1 };
        let right_builtin = if right.is_builtin { 0 } else { 1 };
        left_builtin
            .cmp(&right_builtin)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.id.cmp(&right.id))
    });
}

struct BuiltInTeam {
    id: &'static str,
    name: &'static str,
    description: Option<&'static str>,
    persona_ids: &'static [&'static str],
}

const BUILT_IN_TEAMS: &[BuiltInTeam] = &[BuiltInTeam {
    id: "builtin-team:welcome",
    name: "Welcome Team",
    description: Some("A friendly starter trio ready to help you plan, create, and ship."),
    persona_ids: &["builtin:fizz", "builtin:honey", "builtin:bumble"],
}];

// Built-in teams that have been retired. A stored copy that still exactly
// matches its seed is purged on load (the user never touched it); customized
// copies are demoted to user-owned teams by the retirement loop in
// merge_teams_impl.
const RETIRED_BUILT_IN_TEAMS: &[BuiltInTeam] = &[BuiltInTeam {
    id: "builtin-team:fizz",
    name: "Fizz",
    description: Some("Fizz works carefully and collaboratively."),
    persona_ids: &["builtin:fizz"],
}];

fn built_in_team_records(built_ins: &[BuiltInTeam], now: &str) -> Vec<TeamRecord> {
    built_ins
        .iter()
        .map(|team| TeamRecord {
            id: team.id.to_string(),
            name: team.name.to_string(),
            description: team.description.map(|s| s.to_string()),
            instructions: None,
            persona_ids: team.persona_ids.iter().map(|s| s.to_string()).collect(),
            is_builtin: true,
            source_dir: None,
            is_symlink: false,
            symlink_target: None,
            version: None,
            created_at: now.to_string(),
            updated_at: now.to_string(),
        })
        .collect()
}

fn built_in_team_order(built_ins: &[BuiltInTeam], id: &str) -> Option<usize> {
    built_ins.iter().position(|team| team.id == id)
}

/// Add missing built-in teams, purge pristine retired teams, demote stale
/// built-ins, and preserve any user customizations to existing built-in teams
/// (name, description, persona membership). Returns the merged list and whether
/// the store changed.
fn merge_teams(stored: Vec<TeamRecord>, now: &str) -> (Vec<TeamRecord>, bool) {
    merge_teams_impl(BUILT_IN_TEAMS, RETIRED_BUILT_IN_TEAMS, stored, now)
}

fn merge_teams_impl(
    built_ins: &[BuiltInTeam],
    retired: &[BuiltInTeam],
    mut stored: Vec<TeamRecord>,
    now: &str,
) -> (Vec<TeamRecord>, bool) {
    let mut changed = false;

    // Seed missing built-ins / re-promote existing ones that were downgraded.
    for built_in in built_in_team_records(built_ins, now) {
        if let Some(existing) = stored.iter_mut().find(|record| record.id == built_in.id) {
            if !existing.is_builtin {
                existing.is_builtin = true;
                existing.updated_at = now.to_string();
                changed = true;
            }
        } else {
            stored.push(built_in);
            changed = true;
        }
    }

    // Purge stored copies that are still pristine w.r.t. a retired seed. The
    // user never touched them, so there is nothing to preserve.
    let before = stored.len();
    stored.retain(|record| {
        !retired.iter().any(|seed| {
            record.is_builtin
                && record.id == seed.id
                && record.name == seed.name
                && record.description.as_deref() == seed.description
                && record
                    .persona_ids
                    .iter()
                    .map(String::as_str)
                    .eq(seed.persona_ids.iter().copied())
                && record.source_dir.is_none()
                && !record.is_symlink
        })
    });
    if stored.len() != before {
        changed = true;
    }

    // Demote any stored team flagged as built-in whose id is no longer in
    // built_ins (e.g. a built-in that has been retired). The record stays so
    // existing references keep working; it becomes a user-owned custom team
    // they can edit or delete.
    for record in stored.iter_mut() {
        if record.is_builtin && built_in_team_order(built_ins, &record.id).is_none() {
            record.is_builtin = false;
            record.updated_at = now.to_string();
            changed = true;
        }
    }

    (stored, changed)
}

/// Reject deletion of built-in teams. Mirrors `validate_persona_deletion`
/// for personas — built-ins always come back via `merge_teams` on the
/// next load, so blocking the delete avoids a confusing "keeps coming
/// back" UX.
pub fn validate_team_deletion(team: &TeamRecord) -> Result<(), String> {
    if team.is_builtin {
        return Err("Built-in teams cannot be deleted.".to_string());
    }
    Ok(())
}

/// Read and merge built-in teams without persisting changes.
///
/// Returns the merged, sorted team list. No file is written — callers that
/// only need the current logical state (e.g. the snapshot-import pre-read)
/// use this to avoid a write-on-load side effect.
#[allow(dead_code)]
pub(crate) fn load_teams_readonly(path: &std::path::Path) -> Result<Vec<TeamRecord>, String> {
    let now = now_iso();

    let records = if path.exists() {
        let bytes =
            fs::read(path).map_err(|error| format!("failed to read teams store: {error}"))?;
        crate::managed_agents::store_journal::decode_team_store(&bytes)
            .map_err(|error| format!("failed to parse teams store: {}", error.message))?
    } else {
        Vec::new()
    };

    let (mut records, _changed) = merge_teams(records, &now);
    sort_teams(&mut records);
    Ok(records)
}

pub fn load_teams(app: &AppHandle) -> Result<Vec<TeamRecord>, String> {
    let path = teams_store_path(app)?;
    let now = now_iso();

    // Acquire the interprocess advisory lock before reading (the parent dir
    // is the B1 anchor — same lock file as the agent-store lock).
    let anchor = crate::managed_agents::store_journal::store_anchor_dir(app)?;
    std::fs::create_dir_all(&anchor).map_err(|e| format!("failed to create anchor dir: {e}"))?;
    let _advisory = crate::managed_agents::store_journal::JournalLockGuard::acquire(&anchor)?;

    let records = if path.exists() {
        let bytes =
            fs::read(&path).map_err(|error| format!("failed to read teams store: {error}"))?;
        crate::managed_agents::store_journal::decode_team_store(&bytes)
            .map_err(|error| format!("failed to parse teams store: {}", error.message))?
    } else {
        Vec::new()
    };

    let (mut records, changed) = merge_teams(records, &now);
    sort_teams(&mut records);

    if changed || !path.exists() {
        // Advisory lock already held; call the inner write helper directly
        // to avoid a double-lock on the same fd.
        save_teams_locked(&path, &records)?;
    }

    Ok(records)
}

/// Write `records` to `path` using the fail-closed atomic fsync write.
/// Called from `load_teams` (already holds the advisory lock).
fn save_teams_locked(path: &std::path::Path, records: &[TeamRecord]) -> Result<(), String> {
    let mut sorted = records.to_vec();
    sort_teams(&mut sorted);
    let payload = serde_json::to_vec_pretty(&sorted)
        .map_err(|error| format!("failed to serialize teams store: {error}"))?;
    crate::managed_agents::store_journal::atomic_write_with_fsync(path, &payload)
}

/// Names of managed agents that still reference `team` — either via the
/// legacy `persona_team_dir` link (directory-backed teams only) or the
/// `team_id` field (every team kind, all agents created after the team_id
/// seam landed). Used to block team deletion while agents still depend on it.
fn agents_referencing_team<'a>(
    agents: &'a [ManagedAgentRecord],
    team: &TeamRecord,
) -> Vec<&'a str> {
    let persona_key = team_persona_key(team);
    agents
        .iter()
        .filter(|a| {
            a.persona_team_dir
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                == Some(persona_key)
                || a.team_id.as_deref() == Some(team.id.as_str())
        })
        .map(|a| a.name.as_str())
        .collect()
}

/// Delete a team, cascading removal of its sourced personas and backing dir.
///
/// Returns the d-tags of the personas removed by the cascade so the caller can
/// enqueue NIP-09 tombstones for them — without this, the team coordinate is
/// tombstoned but the orphaned kind:30175 persona heads stay live on the relay.
/// For JSON-only teams (no `source_dir`), nothing cascades and the returned
/// vec is empty.
///
/// `store_guard` is the caller-held in-process mutex guard.  It is returned so
/// the caller can continue holding the lock after the delete (e.g. to enqueue
/// tombstone retention events).  The agents and teams JSON are written
/// atomically in a single `mutate_store` closure, eliminating the TOCTOU window
/// between the former `save_personas` + `save_teams` call sequence.
pub fn delete_team_with_cascade<'g>(
    app: &AppHandle,
    team_id: &str,
    store_guard: std::sync::MutexGuard<'g, ()>,
) -> Result<(Vec<String>, std::sync::MutexGuard<'g, ()>), String> {
    // Pre-validate outside the advisory lock (read-only).
    let agents = crate::managed_agents::load_managed_agents(app)?;

    // Perform the atomic delete inside a single mutate_store closure.
    let team_id = team_id.to_owned();
    let (cascaded_persona_d_tags, guard) =
        crate::managed_agents::store_journal::mutate_store(app, store_guard, move |st| {
            let crate::managed_agents::store_journal::StoreState {
                agents: mut all_agents,
                mut teams,
                ..
            } = st;

            let team = teams
                .iter()
                .find(|record| record.id == team_id)
                .ok_or_else(|| format!("team {team_id} not found"))?;

            validate_team_deletion(team)?;

            let referencing = agents_referencing_team(&agents, team);
            if !referencing.is_empty() {
                return Err(format!(
                    "Cannot delete team \"{team_id}\": {} agent(s) still reference it ({}). \
                     Delete or reconfigure them first.",
                    referencing.len(),
                    referencing.join(", ")
                ));
            }

            let mut cascaded_persona_d_tags = Vec::new();

            if team.source_dir.is_some() {
                // Directory-backed team: cascade persona definitions from the
                // unified agents array.  Match on the shared persona key.
                let persona_key = team_persona_key(team).to_string();

                // Capture d-tags before removal so the caller can tombstone them.
                cascaded_persona_d_tags = all_agents
                    .iter()
                    .filter(|r| {
                        r.pubkey.is_empty()
                            && r.source_team.as_deref() == Some(persona_key.as_str())
                    })
                    .map(|r| {
                        // d-tag derivation mirrors persona_events::persona_d_tag:
                        // use source_team_persona_slug if present, else persona_id.
                        let raw = r
                            .source_team_persona_slug
                            .as_deref()
                            .or(r.persona_id.as_deref())
                            .unwrap_or("");
                        crate::managed_agents::persona_events::normalize_d_tag_pub(raw)
                    })
                    .collect();

                // Remove the cascaded persona definition records.
                all_agents.retain(|r| {
                    !r.pubkey.is_empty() || r.source_team.as_deref() != Some(persona_key.as_str())
                });
            }

            // Remove the TeamRecord.
            teams.retain(|record| record.id != team_id);

            Ok((all_agents, teams, cascaded_persona_d_tags))
        })?;

    Ok((cascaded_persona_d_tags, guard))
}

#[cfg(test)]
#[path = "teams_tests.rs"]
mod tests;
