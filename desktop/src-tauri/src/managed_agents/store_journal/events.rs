//! Immutable inbox/outbox row insertion and publication-state CAS.

use rusqlite::{params, Connection, OptionalExtension};

use super::util::unix_now_secs;

/// Outcome of an immutable-row insertion.
#[derive(Debug, PartialEq, Eq)]
pub enum InsertEventOutcome {
    /// New row inserted.
    Inserted,
    /// A row with this `event_id` already exists and is byte-identical
    /// (safe exact-replay idempotency).
    ExactDuplicate,
    /// A row with this `event_id` already exists but has different
    /// `operation_id` or `payload` — identity collision, fail closed.
    IdentityCollision,
}

/// Insert an immutable outbox row.  Fail-closed on identity collision:
/// a duplicate event_id is only accepted when operation_id and payload
/// are byte-identical.
///
/// `retention_d_tag` is the exact d_tag used in the retention coordinate at
/// enqueue time — persisted so boot recovery can re-insert at the same
/// `(kind, pubkey, d_tag)` without re-parsing the event payload.
pub fn insert_outbox_event(
    conn: &Connection,
    event_id: &str,
    operation_id: &str,
    payload: &[u8],
    retention_d_tag: &str,
) -> Result<InsertEventOutcome, String> {
    let now = unix_now_secs();
    // Try an unconditional insert first.
    let affected = conn
        .execute(
            "INSERT OR IGNORE INTO outbox_events
                 (event_id, operation_id, payload, published_state, retention_d_tag, created_at)
             VALUES (?1, ?2, ?3, 0, ?4, ?5)",
            params![event_id, operation_id, payload, retention_d_tag, now],
        )
        .map_err(|e| format!("insert_outbox_event({event_id}): {e}"))?;

    if affected == 1 {
        return Ok(InsertEventOutcome::Inserted);
    }

    // Row already exists — check identity.
    let existing: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT operation_id, payload FROM outbox_events WHERE event_id = ?1",
            params![event_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("read existing outbox_event({event_id}): {e}"))?;

    match existing {
        Some((op, pl)) if op == operation_id && pl == payload => {
            Ok(InsertEventOutcome::ExactDuplicate)
        }
        _ => Ok(InsertEventOutcome::IdentityCollision),
    }
}

/// Advance publication state of an outbox event via CAS on
/// `expected_state → new_state`.  Requires exactly one affected row.
pub fn mark_outbox_published(
    conn: &Connection,
    event_id: &str,
    expected_state: i64,
    new_state: i64,
) -> Result<bool, String> {
    let affected = conn
        .execute(
            "UPDATE outbox_events SET published_state = ?1
             WHERE event_id = ?2 AND published_state = ?3",
            params![new_state, event_id, expected_state],
        )
        .map_err(|e| format!("mark_outbox_published({event_id}): {e}"))?;
    Ok(affected == 1)
}

/// Insert an immutable inbox row.  Fail-closed on identity collision.
#[allow(dead_code)] // B1 substrate — used in compensation and recovery paths
pub fn insert_inbox_event(
    conn: &Connection,
    event_id: &str,
    operation_id: &str,
    payload: &[u8],
) -> Result<InsertEventOutcome, String> {
    let now = unix_now_secs();
    let affected = conn
        .execute(
            "INSERT OR IGNORE INTO inbox_events
                 (event_id, operation_id, payload, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![event_id, operation_id, payload, now],
        )
        .map_err(|e| format!("insert_inbox_event({event_id}): {e}"))?;

    if affected == 1 {
        return Ok(InsertEventOutcome::Inserted);
    }

    let existing: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT operation_id, payload FROM inbox_events WHERE event_id = ?1",
            params![event_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("read existing inbox_event({event_id}): {e}"))?;

    match existing {
        Some((op, pl)) if op == operation_id && pl == payload => {
            Ok(InsertEventOutcome::ExactDuplicate)
        }
        _ => Ok(InsertEventOutcome::IdentityCollision),
    }
}

/// Read outbox events for `operation_id`.
#[allow(clippy::type_complexity)]
pub fn read_outbox_events(
    conn: &Connection,
    operation_id: &str,
) -> Result<Vec<(String, Vec<u8>, i64, String)>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, payload, published_state, retention_d_tag FROM outbox_events
             WHERE operation_id = ?1 ORDER BY created_at",
        )
        .map_err(|e| format!("prepare outbox query: {e}"))?;
    let rows = stmt
        .query_map(params![operation_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|e| format!("query outbox: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read outbox row: {e}"))
}

/// Read inbox events for `operation_id`.
#[allow(dead_code)] // B1 substrate — used in recovery path tests and compensation
pub fn read_inbox_events(
    conn: &Connection,
    operation_id: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, payload FROM inbox_events
             WHERE operation_id = ?1 ORDER BY received_at",
        )
        .map_err(|e| format!("prepare inbox query: {e}"))?;
    let rows = stmt
        .query_map(params![operation_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| format!("query inbox: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read inbox row: {e}"))
}
