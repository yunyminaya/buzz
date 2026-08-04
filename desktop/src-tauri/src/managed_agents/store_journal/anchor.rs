//! Store-family anchor resolution.
//!
//! The anchor is the directory that holds `managed-agents.json`, `teams.json`,
//! `store-journal.sqlite`, and `store-journal.lock`.  Lock identity is NEVER
//! derived from a possibly-absent file; the anchor is resolved from the app
//! identity unconditionally so two cooperating processes always converge to the
//! same authority.

use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager};

use crate::migration::is_dev_data_dir_name;

pub(super) const CANONICAL_DEV_IDENTIFIER: &str = "xyz.block.buzz.app.dev";
/// Journal filename beside `managed-agents.json`.
pub(super) const JOURNAL_FILENAME: &str = "store-journal.sqlite";
/// Advisory lockfile name beside `managed-agents.json`.
pub(super) const ADVISORY_LOCK_FILENAME: &str = "store-journal.lock";

/// Resolve the store-family anchor directory.
///
/// For shared dev worktrees (`BUZZ_SHARE_IDENTITY=1`): the canonical dev
/// `agents/` dir, returned **unconditionally** regardless of whether it
/// exists yet.  Lock acquisition calls `create_dir_all`, so absent-on-first-
/// boot is not a reason to fall back.  Falling back on absence would let two
/// simultaneous first-boot processes each choose their own local dir, giving
/// them different lock/journal authorities and making shared-state recovery
/// impossible (v34.1 §1).
///
/// For standalone: `app_data_dir()/agents`.  Never derived from
/// `managed-agents.json` — an absent file must never determine lock identity.
pub fn store_anchor_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let local_agents = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("failed to resolve app data dir: {e}"))?
        .join("agents");

    // Only redirect to the canonical dev anchor when identity-sharing is active.
    let is_shared = std::env::var("BUZZ_SHARE_IDENTITY")
        .map(|v| v == "1")
        .unwrap_or(false);

    if is_shared {
        if let Some(anchor) = canonical_dev_anchor(&local_agents) {
            // Return the canonical dev path UNCONDITIONALLY — do not branch on
            // anchor.exists().  Lock acquisition will create the directory.
            return Ok(anchor);
        }
    }

    Ok(local_agents)
}

/// Compute the canonical dev anchor from a local `agents/` path.
/// Returns `None` when the path structure is unexpected.
/// Exposed as `canonical_dev_anchor_pub` for tests.
#[cfg(test)]
pub fn canonical_dev_anchor_pub(local_agents: &Path) -> Option<PathBuf> {
    canonical_dev_anchor(local_agents)
}

pub(super) fn canonical_dev_anchor(local_agents: &Path) -> Option<PathBuf> {
    // local_agents = <AppDataDir>/agents
    // AppDataDir   = <parent>/<identifier>
    // canonical    = <parent>/<CANONICAL_DEV_IDENTIFIER>/agents
    let app_data_dir = local_agents.parent()?;
    let data_parent = app_data_dir.parent()?;
    let name = app_data_dir.file_name()?.to_str()?;

    if !is_dev_data_dir_name(name) {
        return None;
    }

    Some(data_parent.join(CANONICAL_DEV_IDENTIFIER).join("agents"))
}
