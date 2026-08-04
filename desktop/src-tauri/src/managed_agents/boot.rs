//! Boot-time recovery: spawn background task to re-drive nonterminal journal ops.

use tauri::{AppHandle, Manager};

/// Spawn a background task that opens the journal, re-drives any nonterminal
/// operations left from a previous crash or interrupted publication, and then
/// calls the flush loop to publish any pending outbox events.
///
/// Best-effort: any error is logged to stderr and never blocks launch.
pub fn spawn_boot_recovery(app: &AppHandle) {
    let recovery_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = recovery_app.state::<crate::app_state::AppState>();
        // Synchronous journal inspection first (re-classify operations).
        if let Err(e) = super::store_journal::run_boot_recovery(&recovery_app, &state) {
            eprintln!("buzz-desktop: boot-recovery: journal scan: {e}");
        }

        // Then drive the flush loop to actually publish any pending outbox events.
        // This re-submits events whose outbox rows are still pending_state=0.
        match super::persona_events::flush_active_pending_events(&recovery_app, &state).await {
            Ok(n) if n > 0 => {
                eprintln!("buzz-desktop: boot-recovery: flushed {n} pending event(s)");
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("buzz-desktop: boot-recovery: flush: {e}");
            }
        }
    });
}
