/**
 * Reviewability false-positive trap: exact OriginalCode from templates.go.
 *
 * Kept in a separate file from reviewability_patterns.ts because it redefines
 * Account / AccountStatus, which would collide with the parallel-state pattern.
 * This is safe code — deriving a value from a single source of truth — that
 * Rami must NOT flag as a reviewability risk.
 */

// ts-fp-reviewability-derived-state - exact multi-line
type AccountStatus = "active" | "disabled";

interface Account {
  id: string;
  status: AccountStatus;
}

function accountStatus(account: Account): AccountStatus {
  return account.status;
}
