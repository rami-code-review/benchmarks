/**
 * Correctness and maintainability baselines: guarded property writes, narrowed
 * types, named constants, indexed lookups, and errors that keep their context.
 */

interface User {
  id: string;
  name: string;
  profile?: {
    lastLogin?: Date;
  };
}

interface UserProfile {
  firstName: string;
  lastName: string;
}

interface Item {
  id: string;
  name: string;
}

interface Ref {
  id: string;
}

declare const users: User[];
declare const logger: { debug: (msg: string, ctx: object) => void; error: (msg: string, err: unknown) => void };
declare const id: string;
declare function isUser(value: unknown): value is User;

// ts-logic-optional-chain-assign-medium
export function touchLastLogin(user: User): void {
  if (user.profile) {
    user.profile.lastLogin = new Date();
  }
}

// ts-logic-tag-trim-missing-medium
function normalizeTags(tags: string[]): string[] {
  return tags.map((t) => t.trim()).filter((t) => t.length > 0);
}

// ts-logic-typeof-null-easy
function isObject(val: unknown): val is Record<string, unknown> {
  return val !== null && typeof val === "object";
}

// ts-maint-any-cast-easy
function getUser(id: string): User | undefined {
  return users.find(u => u.id === id);
}

// ts-maint-any-param-easy
function formatUser(user: UserProfile): string {
  return user.firstName + " " + user.lastName;
}

// ts-maint-console-log-easy
export function traceRequest(): void {
  logger.debug("request received", { id });
}

// ts-maint-magic-timeout-easy
export async function fetchWithTimeout(url: string): Promise<Response> {
  const REQUEST_TIMEOUT_MS = 30000;
  const response = await fetch(url, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  return response;
}

// ts-perf-nested-loop-unsafe
export function resolveRefs(items: Item[], refs: Ref[]): void {
  const lookup = new Map(items.map(i => [i.id, i]));
  for (const ref of refs) {
    const item = lookup.get(ref.id);
  }
}

// ts-type-cast-unsafe
export function narrowUser(data: unknown): void {
  if (isUser(data)) {
    const user = data;
  }
}

// ts-err-empty-catch-unsafe
export async function persistUser(user: User): Promise<void> {
  try {
    await saveUser(user);
  } catch (error) {
    logger.error("Failed", error);
    throw error;
  }
}

declare function saveUser(user: User): Promise<void>;

export { normalizeTags, isObject, getUser, formatUser };
