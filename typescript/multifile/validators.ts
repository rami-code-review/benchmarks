/**
 * Input validation utilities.
 */

/**
 * Validate that userId is a positive integer string.
 *
 * Matches template: ts-multifile-sqli-safe (validator)
 */
export function validateUserId(userId: string): boolean {
  if (!userId) {
    return false;
  }

  // Must be numeric only
  if (!/^\d+$/.test(userId)) {
    return false;
  }

  // Must be positive
  const num = parseInt(userId, 10);
  if (num <= 0 || !Number.isFinite(num)) {
    return false;
  }

  return true;
}

/**
 * Sanitize search query by removing special characters.
 *
 * Matches template: ts-multifile-sqli-search-safe (sanitizer)
 */
export function sanitizeSearchQuery(query: string): string {
  if (!query) {
    return '';
  }

  // Remove SQL special characters
  // This is defense-in-depth; parameterized queries are the primary protection
  const sanitized = query.replace(/[;'"\\]/g, '');

  // Limit length
  return sanitized.slice(0, 100);
}

/**
 * Validate email format.
 */
export function validateEmail(email: string): boolean {
  if (!email) {
    return false;
  }

  // Basic email pattern
  const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return pattern.test(email);
}

/**
 * Validate filename doesn't contain path traversal.
 *
 * Matches template: ts-multifile-pathtraversal-safe (validator)
 */
export function validateFilename(filename: string): boolean {
  if (!filename) {
    return false;
  }

  // No path separators
  if (filename.includes('/') || filename.includes('\\')) {
    return false;
  }

  // No parent directory references
  if (filename.includes('..')) {
    return false;
  }

  // Only alphanumeric, dash, underscore, and single dot
  const pattern = /^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9]+)?$/;
  return pattern.test(filename);
}

/**
 * Sanitize HTML to prevent XSS.
 *
 * Matches template: ts-multifile-xss-safe (sanitizer)
 */
export function sanitizeHtml(html: string): string {
  if (!html) {
    return '';
  }

  return html
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Validate command key is in allowlist.
 */
export function validateCommandKey(key: string, allowedKeys: Set<string>): boolean {
  return allowedKeys.has(key);
}
