// Session lookups consumed by the auth middleware.

export interface Session {
  user: string;
  scopes: string[];
}

const sessionCache = new Map<string, Session>();

export function getSession(token: string): Session | null { const s = sessionCache.get(token); return s ?? null; }
