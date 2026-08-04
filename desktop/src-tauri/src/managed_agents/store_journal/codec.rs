//! Fail-closed store codec (v6).
//!
//! Unknown or malformed content produces an error; no file write, no journal
//! transition, no relay enqueue may proceed after a failed decode.

use crate::managed_agents::{ManagedAgentRecord, TeamRecord};

/// Parse error type. The raw bytes are never silently discarded — callers
/// receive this error and MUST NOT proceed with mutation.
#[derive(Debug)]
pub struct StoreDecodeError {
    pub message: String,
}

impl std::fmt::Display for StoreDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Decode `managed-agents.json` bytes using the fail-closed codec.
///
/// Returns `Ok(records)` or `Err(StoreDecodeError)`.
/// On error the raw bytes are preserved in place (see `backup_invalid_store`).
/// The caller MUST NOT proceed with any mutation when this returns `Err`.
pub fn decode_agent_store(bytes: &[u8]) -> Result<Vec<ManagedAgentRecord>, StoreDecodeError> {
    // Fail-closed: unknown/malformed content ⇒ error, zero mutation.
    serde_json::from_slice(bytes).map_err(|e| StoreDecodeError {
        message: format!("agent store decode failed: {e}"),
    })
}

/// Decode `teams.json` bytes using the fail-closed codec.
pub fn decode_team_store(bytes: &[u8]) -> Result<Vec<TeamRecord>, StoreDecodeError> {
    serde_json::from_slice(bytes).map_err(|e| StoreDecodeError {
        message: format!("team store decode failed: {e}"),
    })
}

/// Leniently decode a single `ManagedAgentRecord` from a `serde_json::Value`
/// that may contain unknown fields from a future schema version.
///
/// Intended for **read-only** migration helpers that compute hashes or
/// inspect existing store records — not for decoding user-provided or
/// externally-sourced data (use `decode_agent_store` for those paths).
///
/// Repeatedly strips unrecognized fields (identified from the serde error
/// message) and retries until decode succeeds or we've exhausted 32 attempts.
/// Returns `None` when the record is structurally invalid (missing required
/// fields, wrong types) after stripping.
pub fn decode_agent_record_permissive(mut v: serde_json::Value) -> Option<ManagedAgentRecord> {
    for _ in 0..32 {
        match serde_json::from_value::<ManagedAgentRecord>(v.clone()) {
            Ok(r) => return Some(r),
            Err(e) => {
                // serde_json formats unknown-field errors as
                // `unknown field `<NAME>`, expected ...`
                let msg = e.to_string();
                if let Some(name) = msg
                    .strip_prefix("unknown field `")
                    .and_then(|s| s.split('`').next())
                {
                    let field = name.to_string();
                    if let Some(obj) = v.as_object_mut() {
                        obj.remove(&field);
                    } else {
                        return None;
                    }
                } else {
                    // Not an unknown-field error (missing required field, type
                    // mismatch, etc.) — cannot recover.
                    return None;
                }
            }
        }
    }
    None
}
