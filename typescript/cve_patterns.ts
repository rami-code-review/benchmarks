/**
 * CVE-derived vulnerability patterns for benchmark testing.
 *
 * These patterns are inspired by real CVEs to test detection of
 * production-grade security issues.
 */

// =============================================================================
// Types and Interfaces
// =============================================================================

interface Request {
  query: { [key: string]: string };
  body: { [key: string]: unknown };
}

interface Response {
  send: (data: string) => void;
  redirect: (url: string) => void;
}

interface User {
  id: string;
  name: string;
  email: string;
  isAdmin?: boolean;
}

interface DatabaseClient {
  update(table: string, id: string, data: unknown): Promise<void>;
  findById(table: string, id: string): Promise<unknown>;
}

// =============================================================================
// CVE-2023-24488 (Citrix Gateway) - Reflected XSS
// =============================================================================

function encodeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Render alert message with HTML encoding.
 *
 * Matches template: ts-cve-xss-reflected
 */
export function renderAlertSafe(req: Request, res: Response): void {
  // Safe: encode user input before rendering
  const safeMessage = encodeHtml(req.query.message || '');
  res.send(`<div class="alert">${safeMessage}</div>`);
}

// =============================================================================
// CVE-style Mass Assignment
// =============================================================================

const allowedUserFields = ['name', 'email'];

/**
 * Update user with filtered fields.
 *
 * Matches template: ts-cve-mass-assignment
 */
export async function updateUserSafe(
  db: DatabaseClient,
  userId: string,
  body: { [key: string]: unknown }
): Promise<void> {
  // Safe: only assign allowed fields
  const { name, email } = body;
  await db.update('users', userId, { name, email });
}

// =============================================================================
// CVE-style Prototype Pollution
// =============================================================================

/**
 * Safely merge objects without prototype pollution.
 *
 * Matches template: ts-cve-prototype-pollution
 */
export function safeMerge<T extends object>(
  target: T,
  source: { [key: string]: unknown },
  allowedKeys: string[]
): T {
  // Safe: use structured clone or validated merge
  const result = { ...target };
  for (const key of allowedKeys) {
    if (key in source && !key.includes('__proto__') && !key.includes('constructor')) {
      (result as Record<string, unknown>)[key] = source[key];
    }
  }
  return result;
}

// =============================================================================
// CVE-style Open Redirect
// =============================================================================

function isInternalUrl(url: string): boolean {
  // Only allow relative paths, not protocol-relative or absolute URLs
  return url.startsWith('/') && !url.startsWith('//') && !url.includes('://');
}

/**
 * Handle redirect with URL validation.
 *
 * Inspired by various open redirect CVEs.
 */
export function handleRedirectSafe(req: Request, res: Response): void {
  const nextUrl = req.query.next || '/home';

  if (!isInternalUrl(nextUrl)) {
    res.redirect('/home');
    return;
  }

  res.redirect(nextUrl);
}

// =============================================================================
// CVE-style IDOR (Insecure Direct Object Reference)
// =============================================================================

/**
 * Get user data with ownership verification.
 *
 * Inspired by IDOR CVEs.
 */
export async function getUserDataSafe(
  db: DatabaseClient,
  requestedUserId: string,
  currentUserId: string,
  isAdmin: boolean
): Promise<User | null> {
  // Safe: verify access rights
  if (requestedUserId !== currentUserId && !isAdmin) {
    throw new Error('Access denied');
  }

  const user = (await db.findById('users', requestedUserId)) as User | null;
  return user;
}

// =============================================================================
// CVE-style Timing Attack Prevention
// =============================================================================

/**
 * Constant-time string comparison to prevent timing attacks.
 *
 * Inspired by timing attack CVEs.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Validate API token using constant-time comparison.
 */
export function validateApiTokenSafe(
  providedToken: string,
  expectedToken: string
): boolean {
  return constantTimeCompare(providedToken, expectedToken);
}

// =============================================================================
// CVE-style Path Traversal Prevention
// =============================================================================

import * as path from 'path';

/**
 * Resolve file path safely within base directory.
 *
 * Inspired by path traversal CVEs.
 */
export function resolvePathSafe(baseDir: string, userPath: string): string {
  // Normalize and resolve the path
  const normalizedPath = path.normalize(userPath);

  // Remove leading slashes and path traversal sequences
  const cleanPath = normalizedPath.replace(/^[/\\]+/, '').replace(/\.\./g, '');

  // Join with base directory
  const fullPath = path.join(baseDir, cleanPath);

  // Verify the resolved path is within base directory
  const resolvedBase = path.resolve(baseDir);
  const resolvedPath = path.resolve(fullPath);

  if (!resolvedPath.startsWith(resolvedBase)) {
    throw new Error('Path traversal attempt detected');
  }

  return resolvedPath;
}

// =============================================================================
// CVE-style SSRF Prevention
// =============================================================================

const allowedHosts = new Set(['api.example.com', 'cdn.example.com']);

function isAllowedHost(url: string): boolean {
  try {
    const parsed = new URL(url);
    return allowedHosts.has(parsed.hostname);
  } catch {
    return false;
  }
}

/**
 * Fetch URL with host validation.
 *
 * Inspired by SSRF CVEs.
 */
export async function fetchUrlSafe(targetUrl: string): Promise<Response> {
  if (!isAllowedHost(targetUrl)) {
    throw new Error('URL not allowed');
  }

  return fetch(targetUrl);
}

// =============================================================================
// CVE-style Authentication Check
// =============================================================================

interface AuthenticatedRequest extends Request {
  user?: { id: string; isAdmin: boolean };
}

/**
 * Middleware to verify authentication.
 *
 * Inspired by authentication bypass CVEs.
 */
export function requireAuth(
  req: AuthenticatedRequest,
  handler: () => void
): void {
  if (!req.user) {
    throw new Error('Unauthorized');
  }

  handler();
}

/**
 * Middleware to verify admin access.
 */
export function requireAdmin(
  req: AuthenticatedRequest,
  handler: () => void
): void {
  if (!req.user?.isAdmin) {
    throw new Error('Forbidden');
  }

  handler();
}
