// Refresh-token lifetime consumed by the token expiry check.

export function tokenTtl(plan: string): number { return plan === "pro" ? 30 : 10; }
