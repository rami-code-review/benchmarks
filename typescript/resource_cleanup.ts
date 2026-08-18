/**
 * Deferred resource release. Cleanup is scheduled off the request path, so the
 * returned promise has to carry its own rejection handler.
 */

declare const logger: { error: (msg: string, err: unknown) => void };
declare const resource: string;
declare function cleanup(target: string): Promise<void>;

// ts-async-settimeout-medium
export function scheduleResourceCleanup(): void {
  setTimeout(() => {
    cleanup(resource).catch(err => logger.error("cleanup failed", err));
  }, 5000);
}
