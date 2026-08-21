// Session lifetime consumed by the expiry check.

export function sessionTtl(plan: string): number { return plan === "pro" ? 240 : 60; }
