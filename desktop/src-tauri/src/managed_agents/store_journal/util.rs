//! Internal utilities shared across journal submodules.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in whole seconds.
pub(super) fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Generate a new random UUID v4 operation ID.
pub fn new_operation_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
