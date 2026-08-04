//! Per-key generation CAS and tombstone metadata.

use rusqlite::{params, Connection, OptionalExtension};

use super::util::unix_now_secs;

/// Generation counter (u64 stored as TEXT to avoid SQLite's i64 ceiling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub u64);

impl Generation {
    pub fn zero() -> Self {
        Generation(0)
    }
    pub fn next(self) -> Result<Self, String> {
        self.0
            .checked_add(1)
            .map(Generation)
            .ok_or_else(|| format!("generation overflow at {}: CAS cannot advance", self.0))
    }
    pub(super) fn from_str(s: &str) -> Result<Self, String> {
        s.parse::<u64>()
            .map(Generation)
            .map_err(|e| format!("parse generation '{s}': {e}"))
    }
    pub(super) fn to_db_str(self) -> String {
        self.0.to_string()
    }
}

/// Outcome of a generation CAS attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome {
    /// CAS succeeded; `new_generation` is the committed value.
    Committed { new_generation: Generation },
    /// The stored generation did not match `expected`; the current value
    /// is returned so the caller can decide how to proceed.
    Conflict { current: Generation },
    /// The key has a tombstone; ABA rejected.
    Tombstoned { tombstone_generation: Generation },
}

/// Read the current generation for `key_id`.
/// Returns `(Generation::zero(), false)` when no row exists.
pub fn read_generation(conn: &Connection, key_id: &str) -> Result<(Generation, bool), String> {
    let row: Option<(String, bool)> = conn
        .query_row(
            "SELECT generation, is_tombstone FROM key_generations WHERE key_id = ?1",
            params![key_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("read_generation({key_id}): {e}"))?;

    match row {
        None => Ok((Generation::zero(), false)),
        Some((gen_str, is_tombstone)) => Ok((Generation::from_str(&gen_str)?, is_tombstone)),
    }
}

/// Attempt a generation CAS on `key_id`.
///
/// If `expected` matches the stored generation (or key is absent and
/// `expected` is zero), advance to `expected.next()` and return
/// `CasOutcome::Committed`.  Tombstoned keys return `CasOutcome::Tombstoned`.
pub fn cas_generation(
    conn: &Connection,
    key_id: &str,
    expected: Generation,
) -> Result<CasOutcome, String> {
    let (current, is_tombstone) = read_generation(conn, key_id)?;

    if is_tombstone {
        return Ok(CasOutcome::Tombstoned {
            tombstone_generation: current,
        });
    }

    if current != expected {
        return Ok(CasOutcome::Conflict { current });
    }

    let new_gen = expected.next()?;
    let now = unix_now_secs();
    conn.execute(
        "INSERT INTO key_generations (key_id, generation, is_tombstone, updated_at)
         VALUES (?1, ?2, 0, ?3)
         ON CONFLICT(key_id) DO UPDATE SET
             generation  = excluded.generation,
             is_tombstone = 0,
             updated_at  = excluded.updated_at",
        params![key_id, new_gen.to_db_str(), now],
    )
    .map_err(|e| format!("cas_generation({key_id}): {e}"))?;

    Ok(CasOutcome::Committed {
        new_generation: new_gen,
    })
}

/// Write a tombstone for `key_id` at `expected` generation.
/// Kept forever; `cas_generation` respects it to prevent ABA.
pub fn tombstone_key(
    conn: &Connection,
    key_id: &str,
    expected: Generation,
) -> Result<CasOutcome, String> {
    let (current, is_tombstone) = read_generation(conn, key_id)?;

    if is_tombstone {
        return Ok(CasOutcome::Tombstoned {
            tombstone_generation: current,
        });
    }

    if current != expected {
        return Ok(CasOutcome::Conflict { current });
    }

    let tombstone_gen = expected.next()?;
    let now = unix_now_secs();
    conn.execute(
        "INSERT INTO key_generations (key_id, generation, is_tombstone, updated_at)
         VALUES (?1, ?2, 1, ?3)
         ON CONFLICT(key_id) DO UPDATE SET
             generation   = excluded.generation,
             is_tombstone = 1,
             updated_at   = excluded.updated_at",
        params![key_id, tombstone_gen.to_db_str(), now],
    )
    .map_err(|e| format!("tombstone_key({key_id}): {e}"))?;

    Ok(CasOutcome::Committed {
        new_generation: tombstone_gen,
    })
}
