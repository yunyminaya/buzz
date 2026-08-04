//! Operation (saga spine): insert, read, disposition CAS fences.

use rusqlite::{params, Connection, OptionalExtension};

use super::generations::Generation;
use super::util::unix_now_secs;

/// Operation disposition values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Pending,
    Committed,
    Compensating,
    Compensated,
    Failed,
    /// Published to relay but outcome unknown (network outage).
    Uncertain,
    /// Accepted by relay; final state reached without full confirmation.
    Accepted,
}

impl Disposition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Disposition::Pending => "pending",
            Disposition::Committed => "committed",
            Disposition::Compensating => "compensating",
            Disposition::Compensated => "compensated",
            Disposition::Failed => "failed",
            Disposition::Uncertain => "uncertain",
            Disposition::Accepted => "accepted",
        }
    }

    pub(super) fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Disposition::Pending),
            "committed" => Some(Disposition::Committed),
            "compensating" => Some(Disposition::Compensating),
            "compensated" => Some(Disposition::Compensated),
            "failed" => Some(Disposition::Failed),
            "uncertain" => Some(Disposition::Uncertain),
            "accepted" => Some(Disposition::Accepted),
            _ => None,
        }
    }

    /// True when the operation is in a terminal state requiring no further
    /// progression.
    #[allow(dead_code)] // B2 substrate — used in recovery path tests
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Disposition::Committed | Disposition::Compensated | Disposition::Failed
        )
    }

    /// True when the operation may require a nonterminal follow-up check
    /// (uncertain or accepted publication outcome).
    #[allow(dead_code)] // B2 substrate — used in recovery path tests
    pub fn requires_follow_up(&self) -> bool {
        matches!(self, Disposition::Uncertain | Disposition::Accepted)
    }
}

/// A record from the `operations` table.
#[derive(Debug, Clone)]
pub struct OperationRecord {
    pub operation_id: String,
    pub kind: String,
    pub key_id: String,
    pub disposition: Disposition,
    /// Current committed generation at operation record time.
    #[allow(dead_code)] // B2 substrate — exposed for recovery integration tests
    pub generation: Generation,
    /// UUID of the active compensation event, if in `Compensating` state.
    #[allow(dead_code)] // B2 substrate — compensation claim fence
    pub compensation_id: Option<String>,
    /// Generation snapshot at compensation start.
    #[allow(dead_code)] // B2 substrate — compensation claim fence
    pub compensation_generation: Option<Generation>,
    /// Whether a nonterminal follow-up is pending (uncertain/accepted publication).
    #[allow(dead_code)] // B2 substrate — saga follow-up gate
    pub nonterminal_follow_up: bool,
}

/// Insert a new `pending` operation record.
pub fn insert_operation(
    conn: &Connection,
    operation_id: &str,
    kind: &str,
    key_id: &str,
    generation: Generation,
) -> Result<(), String> {
    let now = unix_now_secs();
    conn.execute(
        "INSERT INTO operations
             (operation_id, kind, key_id, disposition, generation, created_at, updated_at)
         VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?5)",
        params![operation_id, kind, key_id, generation.to_db_str(), now],
    )
    .map_err(|e| format!("insert_operation({operation_id}): {e}"))?;
    Ok(())
}

/// Read one operation record.  Returns `None` when not found.
#[allow(clippy::type_complexity)]
pub fn read_operation(
    conn: &Connection,
    operation_id: &str,
) -> Result<Option<OperationRecord>, String> {
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
    )> = conn
        .query_row(
            "SELECT operation_id, kind, key_id, disposition, generation,
                    compensation_id, compensation_generation, nonterminal_follow_up
             FROM operations WHERE operation_id = ?1",
            params![operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("read_operation({operation_id}): {e}"))?;

    row.map(
        |(op_id, kind, key_id, disp_str, gen_str, comp_id, comp_gen_str, nf)| {
            let disposition = Disposition::from_str(&disp_str)
                .ok_or_else(|| format!("unknown disposition '{disp_str}'"))?;
            let generation = Generation::from_str(&gen_str)?;
            let compensation_generation =
                comp_gen_str.map(|s| Generation::from_str(&s)).transpose()?;
            Ok(OperationRecord {
                operation_id: op_id,
                kind,
                key_id,
                disposition,
                generation,
                compensation_id: comp_id,
                compensation_generation,
                nonterminal_follow_up: nf,
            })
        },
    )
    .transpose()
}

/// Outcome of a fenced disposition transition.
#[derive(Debug, PartialEq, Eq)]
pub enum TransitionOutcome {
    /// Transition succeeded; operation is now in `new_disposition`.
    Advanced,
    /// The stored disposition did not match `expected_disposition`; the
    /// operation is in `actual_disposition`.
    Conflict { actual_disposition: String },
    /// The operation was not found.
    NotFound,
}

/// Advance an operation's disposition via SQL CAS on (operation_id,
/// expected_disposition).  Requires exactly one affected row and reports
/// `Conflict` or `NotFound` distinctly — never a silent no-op.
pub fn advance_disposition(
    conn: &Connection,
    operation_id: &str,
    expected_disposition: &Disposition,
    new_disposition: &Disposition,
) -> Result<TransitionOutcome, String> {
    let now = unix_now_secs();
    let affected = conn
        .execute(
            "UPDATE operations SET disposition = ?1, updated_at = ?2
             WHERE operation_id = ?3 AND disposition = ?4",
            params![
                new_disposition.as_str(),
                now,
                operation_id,
                expected_disposition.as_str(),
            ],
        )
        .map_err(|e| format!("advance_disposition({operation_id}): {e}"))?;

    if affected == 1 {
        return Ok(TransitionOutcome::Advanced);
    }

    // Distinguish NotFound from Conflict by reading the current row.
    match read_operation(conn, operation_id)? {
        None => Ok(TransitionOutcome::NotFound),
        Some(op) => Ok(TransitionOutcome::Conflict {
            actual_disposition: op.disposition.as_str().to_owned(),
        }),
    }
}

/// Pin the active compensation event for an operation (v10 claim fence).
/// Only allowed when disposition is exactly `Pending` — transitions to
/// `Compensating`.  Requires exactly one affected row.
#[allow(dead_code)]
pub fn pin_compensation(
    conn: &Connection,
    operation_id: &str,
    compensation_id: &str,
    compensation_generation: Generation,
) -> Result<TransitionOutcome, String> {
    let now = unix_now_secs();
    let affected = conn
        .execute(
            "UPDATE operations
             SET disposition            = 'compensating',
                 compensation_id        = ?1,
                 compensation_generation = ?2,
                 updated_at             = ?3
             WHERE operation_id = ?4 AND disposition = 'pending'",
            params![
                compensation_id,
                compensation_generation.to_db_str(),
                now,
                operation_id,
            ],
        )
        .map_err(|e| format!("pin_compensation({operation_id}): {e}"))?;

    if affected == 1 {
        return Ok(TransitionOutcome::Advanced);
    }

    match read_operation(conn, operation_id)? {
        None => Ok(TransitionOutcome::NotFound),
        Some(op) => Ok(TransitionOutcome::Conflict {
            actual_disposition: op.disposition.as_str().to_owned(),
        }),
    }
}

/// Mark that a nonterminal follow-up is required (uncertain/accepted
/// publication outcome — v12).  CAS on expected disposition.
#[allow(dead_code)]
pub fn set_nonterminal_follow_up(
    conn: &Connection,
    operation_id: &str,
    expected_disposition: &Disposition,
    required: bool,
) -> Result<TransitionOutcome, String> {
    let now = unix_now_secs();
    let affected = conn
        .execute(
            "UPDATE operations SET nonterminal_follow_up = ?1, updated_at = ?2
             WHERE operation_id = ?3 AND disposition = ?4",
            params![
                required as i64,
                now,
                operation_id,
                expected_disposition.as_str(),
            ],
        )
        .map_err(|e| format!("set_nonterminal_follow_up({operation_id}): {e}"))?;

    if affected == 1 {
        return Ok(TransitionOutcome::Advanced);
    }

    match read_operation(conn, operation_id)? {
        None => Ok(TransitionOutcome::NotFound),
        Some(op) => Ok(TransitionOutcome::Conflict {
            actual_disposition: op.disposition.as_str().to_owned(),
        }),
    }
}

/// Read all non-terminal operations for recovery.
pub fn read_nonterminal_operations(conn: &Connection) -> Result<Vec<OperationRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT operation_id, kind, key_id, disposition, generation,
                    compensation_id, compensation_generation, nonterminal_follow_up
             FROM operations
             WHERE disposition NOT IN ('committed', 'compensated', 'failed')",
        )
        .map_err(|e| format!("prepare nonterminal ops: {e}"))?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, bool>(7)?,
            ))
        })
        .map_err(|e| format!("query nonterminal ops: {e}"))?;

    let mut out = Vec::new();
    for row in rows {
        let (op_id, kind, key_id, disp_str, gen_str, comp_id, comp_gen_str, nf) =
            row.map_err(|e| format!("read nonterminal op row: {e}"))?;
        let disposition = Disposition::from_str(&disp_str)
            .ok_or_else(|| format!("unknown disposition '{disp_str}'"))?;
        let generation = Generation::from_str(&gen_str)?;
        let compensation_generation = comp_gen_str.map(|s| Generation::from_str(&s)).transpose()?;
        out.push(OperationRecord {
            operation_id: op_id,
            kind,
            key_id,
            disposition,
            generation,
            compensation_id: comp_id,
            compensation_generation,
            nonterminal_follow_up: nf,
        });
    }
    Ok(out)
}
