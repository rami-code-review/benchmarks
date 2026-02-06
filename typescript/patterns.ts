/**
 * Exact template patterns for benchmark testing.
 *
 * Each function contains the EXACT OriginalCode from templates.go.
 */

// Mock objects and types for pattern matching
declare const db: { query: (sql: string, params?: unknown[]) => Promise<unknown> };
declare const userId: string;
declare const execFile: (cmd: string, args: string[], callback: (err: Error | null) => void) => void;
declare const spawn: (cmd: string, args: string[] | { shell: boolean }) => void;
declare const repoUrl: string;
declare const packageName: string;
declare const baseDir: string;
declare const userInput: string;
declare const element: HTMLElement;
declare const userContent: string;
declare const sanitize: (input: string) => string;
declare const data: string;
declare const jsonString: string;
declare const logger: { error: (msg: string, error: unknown) => void };
declare const user: { profile?: { name?: string } } | null;
declare const defaultValue: string;
declare const value: unknown;
declare const callback: (err: Error | null) => void;

import * as path from 'path';

// =============================================================================
// SQL INJECTION PATTERNS
// =============================================================================

function sqliTemplateEasy(): void {
  // ts-sqli-template-easy
  db.query("SELECT * FROM users WHERE id = $1", [userId]);
}

// =============================================================================
// COMMAND INJECTION PATTERNS
// =============================================================================

function cmdiExecEasy(): void {
  // ts-cmdi-exec-easy
  execFile("git", ["clone", repoUrl], callback);
}

function cmdiSpawnEasy(): void {
  // ts-cmdi-spawn-easy
  spawn("npm", ["install", packageName]);
}

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================

function pathTraversalJoinEasy(): string {
  // ts-pathtraversal-join-easy
  const safePath = path.join(baseDir, path.basename(userInput));
  return safePath;
}

// =============================================================================
// XSS PATTERNS
// =============================================================================

function xssInnerHtmlEasy(): void {
  // ts-xss-innerhtml-easy
  element.textContent = userInput;
}

function xssDangerouslyEasy(): JSX.Element {
  // ts-xss-dangerously-easy
  return <div>{sanitize(userContent)}</div>;
}

function xssDocumentWriteEasy(): void {
  // ts-xss-docwrite-easy
  document.getElementById("output").textContent = data;
}

function xssEvalEasy(): unknown {
  // ts-xss-eval-easy
  const result = JSON.parse(jsonString);
  return result;
}

// =============================================================================
// SECRETS PATTERNS
// =============================================================================

function secretApiKeyEasy(): string {
  // ts-secret-apikey-easy
  const apiKey = process.env.API_KEY;
  return apiKey || '';
}

// =============================================================================
// ERROR HANDLING PATTERNS
// =============================================================================

function errEmptyCatchEasy(): void {
  // ts-err-empty-catch-easy
  try {
    // operation
  } catch (error) {
    logger.error("Operation failed", error);
    throw error;
  }
}

// =============================================================================
// NULL SAFETY PATTERNS
// =============================================================================

function nullOptionalChainEasy(): string {
  // ts-null-optional-chain-easy
  const name = user?.profile?.name ?? "Unknown";
  return name;
}

function nullNonNullAssertionEasy(): string {
  // ts-null-non-null-assertion-easy
  const value = data?.result ?? defaultValue;
  return value;
}

// =============================================================================
// LOGIC PATTERNS
// =============================================================================

function logicLooseEqualityEasy(): boolean {
  // ts-logic-loose-equality-easy
  if (value === null || value === undefined) {
    return true;
  }
  return false;
}

// =============================================================================
// FALSE POSITIVE PATTERNS
// =============================================================================

declare const DOMPurify: { sanitize: (input: string) => string };

function fpInnerHtmlSanitized(): void {
  // ts-fp-innerhtml-sanitized - FALSE POSITIVE: properly sanitized
  const clean = DOMPurify.sanitize(userInput);
  element.innerHTML = clean;
}

// Export to avoid unused warnings
export {
  sqliTemplateEasy,
  cmdiExecEasy,
  cmdiSpawnEasy,
  pathTraversalJoinEasy,
  xssInnerHtmlEasy,
  xssDangerouslyEasy,
  xssDocumentWriteEasy,
  xssEvalEasy,
  secretApiKeyEasy,
  errEmptyCatchEasy,
  nullOptionalChainEasy,
  nullNonNullAssertionEasy,
  logicLooseEqualityEasy,
  fpInnerHtmlSanitized,
};
