// Named locks for background jobs.

export interface Lock {
  valid: boolean;
}

declare const locks: { acquire(name: string): Promise<Lock>; release(name: string): Promise<void> };

export async function withLock(name: string): Promise<Lock> { const l = await locks.acquire(name); if (!l.valid) { await locks.release(name); throw new Error("invalid lock"); } return l; }
