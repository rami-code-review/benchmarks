/**
 * Benchmark patterns for TypeScript security and quality detection.
 *
 * Each function represents a template pattern for testing code review capabilities.
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
declare const logger: { error: (msg: string, error: unknown) => void; info: (msg: string) => void };
declare const user: { profile?: { name?: string } } | null;
declare const defaultValue: string;
declare const value: unknown;
declare const callback: (err: Error | null) => void;
declare const DOMPurify: { sanitize: (input: string) => string };

import * as path from 'path';
import * as fs from 'fs';

// =============================================================================
// SQL INJECTION PATTERNS
// =============================================================================

function sqliTemplateEasy(): void {
  // ts-sqli-template-easy
  db.query("SELECT * FROM users WHERE id = $1", [userId]);
}

function sqliTemplateLiteralUnsafe(userId: string): Promise<unknown> {
  // ts-sqli-template-literal-unsafe: UNSAFE template literal in SQL
  return db.query(`SELECT * FROM users WHERE id = '${userId}'`);
}

function sqliTemplateLiteralFix(userId: string): Promise<unknown> {
  // ts-sqli-template-literal-fix: Parameterized query
  return db.query("SELECT * FROM users WHERE id = $1", [userId]);
}

function sqliConcatUnsafe(name: string): Promise<unknown> {
  // ts-sqli-concat-unsafe: UNSAFE string concatenation
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  return db.query(query);
}

// Prisma patterns
interface PrismaClient {
  $queryRaw: (query: TemplateStringsArray, ...values: unknown[]) => Promise<unknown>;
  $queryRawUnsafe: (query: string) => Promise<unknown>;
  user: {
    findMany: (args?: { where?: object; orderBy?: object }) => Promise<unknown[]>;
  };
}

declare const prisma: PrismaClient;

function prismaRawUnsafe(userId: string): Promise<unknown> {
  // ts-sqli-prisma-raw-unsafe: UNSAFE raw query
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${userId}'`);
}

function prismaRawSafe(userId: string): Promise<unknown> {
  // ts-sqli-prisma-raw-safe: Safe tagged template
  return prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
}

// TypeORM patterns
interface EntityManager {
  query: (sql: string, params?: unknown[]) => Promise<unknown>;
}

declare const entityManager: EntityManager;

function typeormQueryUnsafe(status: string): Promise<unknown> {
  // ts-sqli-typeorm-unsafe: UNSAFE raw query
  return entityManager.query(`SELECT * FROM orders WHERE status = '${status}'`);
}

function typeormQuerySafe(status: string): Promise<unknown> {
  // ts-sqli-typeorm-safe: Parameterized query
  return entityManager.query("SELECT * FROM orders WHERE status = $1", [status]);
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

import { exec, execSync } from 'child_process';

function cmdiExecUnsafe(filename: string): void {
  // ts-cmdi-exec-unsafe: UNSAFE exec with user input
  exec(`cat ${filename}`, (err, stdout) => {
    console.log(stdout);
  });
}

function cmdiExecFix(filename: string): void {
  // ts-cmdi-exec-fix: Safe execFile with args array
  if (!/^[\w.-]+$/.test(filename)) {
    throw new Error("Invalid filename");
  }
  execFile("cat", [filename], (err, stdout) => {
    if (err) throw err;
    console.log(stdout);
  });
}

function cmdiSpawnShellUnsafe(command: string): void {
  // ts-cmdi-spawn-shell-unsafe: UNSAFE spawn with shell
  spawn(command, { shell: true });
}

function cmdiExecSyncUnsafe(userArg: string): string {
  // ts-cmdi-execsync-unsafe: UNSAFE execSync with template
  return execSync(`grep ${userArg} /var/log/app.log`).toString();
}

function cmdiExecSyncFix(userArg: string): string {
  // ts-cmdi-execsync-fix: Safe spawn with args
  if (!/^[a-zA-Z0-9]+$/.test(userArg)) {
    throw new Error("Invalid argument");
  }
  return execSync("grep", { input: userArg }).toString();
}

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================

function pathTraversalJoinEasy(): string {
  // ts-pathtraversal-join-easy
  const safePath = path.join(baseDir, path.basename(userInput));
  return safePath;
}

function pathTraversalJoinUnsafe(filename: string): string {
  // ts-pathtraversal-join-unsafe: UNSAFE path join
  const filePath = path.join("/uploads", filename);
  return fs.readFileSync(filePath, 'utf8');
}

function pathTraversalJoinFix(filename: string): string {
  // ts-pathtraversal-join-fix: Validated path
  const base = path.resolve("/uploads");
  const full = path.resolve(base, filename);

  if (!full.startsWith(base + path.sep)) {
    throw new Error("Path traversal detected");
  }
  return fs.readFileSync(full, 'utf8');
}

// Express patterns
interface Request {
  query: { [key: string]: string | undefined };
  params: { [key: string]: string };
  body: unknown;
}

interface Response {
  sendFile: (path: string) => void;
  send: (body: string) => void;
  json: (body: object) => void;
  status: (code: number) => Response;
}

function expressPathUnsafe(req: Request, res: Response): void {
  // ts-pathtraversal-express-unsafe: UNSAFE express file serving
  const file = req.query.file;
  res.sendFile(path.join(__dirname, "public", file));
}

function expressPathFix(req: Request, res: Response): void {
  // ts-pathtraversal-express-fix: Validated express file serving
  const file = req.query.file;

  // Only allow alphanumeric with extension
  if (!/^[\w-]+\.\w+$/.test(file)) {
    res.status(400).send("Invalid filename");
    return;
  }

  const base = path.resolve(__dirname, "public");
  const full = path.resolve(base, file);

  if (!full.startsWith(base + path.sep)) {
    res.status(403).send("Access denied");
    return;
  }

  res.sendFile(full);
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

function xssInnerHtmlUnsafe(content: string): void {
  // ts-xss-innerhtml-unsafe: UNSAFE innerHTML
  document.getElementById("output").innerHTML = content;
}

function xssInnerHtmlFix(content: string): void {
  // ts-xss-innerhtml-fix: Safe textContent
  document.getElementById("output").textContent = content;
}

// React patterns
interface ReactProps {
  content: string;
  htmlContent: string;
}

function reactDangerouslyUnsafe(props: ReactProps): JSX.Element {
  // ts-xss-react-dangerous-unsafe: UNSAFE dangerouslySetInnerHTML
  return <div dangerouslySetInnerHTML={{ __html: props.htmlContent }} />;
}

function reactDangerousFix(props: ReactProps): JSX.Element {
  // ts-xss-react-dangerous-fix: Safe text or sanitized HTML
  const clean = DOMPurify.sanitize(props.htmlContent);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

function reactHrefUnsafe(url: string): JSX.Element {
  // ts-xss-react-href-unsafe: UNSAFE user-controlled href
  return <a href={url}>Click here</a>;
}

function reactHrefFix(url: string): JSX.Element {
  // ts-xss-react-href-fix: Validated URL
  let safeUrl = url;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      safeUrl = '#';
    }
  } catch {
    safeUrl = '#';
  }
  return <a href={safeUrl}>Click here</a>;
}

// =============================================================================
// SECRETS PATTERNS
// =============================================================================

function secretApiKeyEasy(): string {
  // ts-secret-apikey-easy
  const apiKey = process.env.API_KEY;
  return apiKey || '';
}

const HARDCODED_SECRET = "sk_live_abc123xyz789";

function secretHardcodedUnsafe(): string {
  // ts-secret-hardcoded-unsafe: UNSAFE hardcoded secret
  return HARDCODED_SECRET;
}

function secretHardcodedFix(): string {
  // ts-secret-hardcoded-fix: Environment variable
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    throw new Error("API_KEY not configured");
  }
  return apiKey;
}

function secretLoggingUnsafe(apiKey: string, userId: string): void {
  // ts-secret-logging-unsafe: UNSAFE logging sensitive data
  logger.info(`Request with API key: ${apiKey} for user: ${userId}`);
}

function secretLoggingFix(apiKey: string, userId: string): void {
  // ts-secret-logging-fix: Redacted logging
  const masked = apiKey.substring(0, 4) + "...";
  logger.info(`Request with API key: ${masked} for user: ${userId}`);
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

function errEmptyCatchUnsafe(): void {
  // ts-err-empty-catch-unsafe: UNSAFE empty catch
  try {
    doSomething();
  } catch {
    // UNSAFE: Error swallowed
  }
}

function errEmptyCatchFix(): void {
  // ts-err-empty-catch-fix: Proper error handling
  try {
    doSomething();
  } catch (error) {
    logger.error("Operation failed", error);
    throw error;
  }
}

async function errUnhandledPromiseUnsafe(): Promise<void> {
  // ts-err-unhandled-promise-unsafe: UNSAFE fire-and-forget
  fetchData(); // No await, no catch
}

async function errUnhandledPromiseFix(): Promise<void> {
  // ts-err-unhandled-promise-fix: Proper async handling
  try {
    await fetchData();
  } catch (error) {
    logger.error("Fetch failed", error);
    throw error;
  }
}

function errInfoLeakUnsafe(error: Error, res: Response): void {
  // ts-err-info-leak-unsafe: UNSAFE error info leak
  res.status(500).json({
    error: error.message,
    stack: error.stack
  });
}

function errInfoLeakFix(error: Error, res: Response): void {
  // ts-err-info-leak-fix: Generic error message
  logger.error("Internal error", error);
  res.status(500).json({ error: "An internal error occurred" });
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

interface User {
  name?: string;
  profile?: {
    email?: string;
  };
}

function nullDerefUnsafe(user: User | null): string {
  // ts-null-deref-unsafe: UNSAFE null dereference
  return user.name.toUpperCase();
}

function nullDerefFix(user: User | null): string {
  // ts-null-deref-fix: Safe access
  return user?.name?.toUpperCase() ?? "Anonymous";
}

function nullNonNullAssertUnsafe(user: User | undefined): string {
  // ts-null-non-null-assert-unsafe: UNSAFE non-null assertion
  return user!.name!;
}

function nullNonNullAssertFix(user: User | undefined): string {
  // ts-null-non-null-assert-fix: Proper null handling
  return user?.name ?? "";
}

// =============================================================================
// TYPE SAFETY PATTERNS
// =============================================================================

function typeAnyUnsafe(data: any): string {
  // ts-type-any-unsafe: UNSAFE any type
  return data.name.toUpperCase();
}

function typeAnyFix(data: unknown): string {
  // ts-type-any-fix: Proper type narrowing
  if (typeof data === 'object' && data !== null && 'name' in data) {
    const name = (data as { name: unknown }).name;
    if (typeof name === 'string') {
      return name.toUpperCase();
    }
  }
  return "";
}

function typeCastUnsafe(value: unknown): number {
  // ts-type-cast-unsafe: UNSAFE type cast
  return (value as number) + 1;
}

function typeCastFix(value: unknown): number | null {
  // ts-type-cast-fix: Type guard
  if (typeof value === 'number') {
    return value + 1;
  }
  return null;
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

function logicLooseEqualityUnsafe(a: unknown, b: unknown): boolean {
  // ts-logic-loose-equality-unsafe: UNSAFE loose equality
  return a == b;
}

function logicLooseEqualityFix(a: unknown, b: unknown): boolean {
  // ts-logic-loose-equality-fix: Strict equality
  return a === b;
}

function logicNullishUnsafe(value: string | null): string {
  // ts-logic-nullish-unsafe: UNSAFE || for default
  return value || "default"; // Treats "" as falsy
}

function logicNullishFix(value: string | null): string {
  // ts-logic-nullish-fix: Nullish coalescing
  return value ?? "default"; // Only null/undefined
}

// =============================================================================
// ASYNC PATTERNS
// =============================================================================

async function asyncFloatingPromiseUnsafe(): Promise<void> {
  // ts-async-floating-unsafe: UNSAFE floating promise
  riskyOperation(); // Not awaited
}

async function asyncFloatingPromiseFix(): Promise<void> {
  // ts-async-floating-fix: Awaited promise
  await riskyOperation();
}

function asyncCallbackMixUnsafe(items: string[]): void {
  // ts-async-callback-mix-unsafe: UNSAFE async in forEach
  items.forEach(async (item) => {
    await processItem(item);
  });
}

async function asyncCallbackMixFix(items: string[]): Promise<void> {
  // ts-async-callback-mix-fix: Proper async iteration
  for (const item of items) {
    await processItem(item);
  }
}

// =============================================================================
// SSRF PATTERNS
// =============================================================================

async function ssrfFetchUnsafe(url: string): Promise<string> {
  // ts-ssrf-fetch-unsafe: UNSAFE unvalidated fetch
  const response = await fetch(url);
  return response.text();
}

async function ssrfFetchFix(url: string): Promise<string> {
  // ts-ssrf-fetch-fix: Validated fetch
  const parsed = new URL(url);
  const allowedHosts = ['api.example.com', 'cdn.example.com'];

  if (!allowedHosts.includes(parsed.hostname)) {
    throw new Error("Host not allowed");
  }

  // Block internal IPs
  if (parsed.hostname === 'localhost' ||
      parsed.hostname.startsWith('127.') ||
      parsed.hostname.startsWith('10.') ||
      parsed.hostname.startsWith('192.168.')) {
    throw new Error("Internal addresses not allowed");
  }

  const response = await fetch(url);
  return response.text();
}

// =============================================================================
// OPEN REDIRECT PATTERNS
// =============================================================================

function redirectUnsafe(req: Request, res: Response): void {
  // ts-redirect-unsafe: UNSAFE unvalidated redirect
  const next = req.query.next;
  res.redirect(next);
}

function redirectFix(req: Request, res: Response): void {
  // ts-redirect-fix: Validated redirect
  let next = req.query.next || '/';

  try {
    const parsed = new URL(next, 'http://localhost');
    // Only allow relative paths
    if (parsed.origin !== 'http://localhost') {
      next = '/';
    } else {
      next = parsed.pathname + parsed.search;
    }
  } catch {
    next = '/';
  }

  res.redirect(next);
}

// =============================================================================
// VALIDATION PATTERNS (Zod/Yup)
// =============================================================================

interface ZodSchema<T> {
  parse: (data: unknown) => T;
  safeParse: (data: unknown) => { success: boolean; data?: T; error?: Error };
}

declare const userSchema: ZodSchema<{ name: string; email: string }>;

function zodParseUnsafe(data: unknown): { name: string; email: string } {
  // ts-zod-parse-unsafe: UNSAFE uncaught parse error
  return userSchema.parse(data); // Throws on invalid
}

function zodParseFix(data: unknown): { name: string; email: string } | null {
  // ts-zod-parse-fix: Safe parse with error handling
  const result = userSchema.safeParse(data);
  if (!result.success) {
    logger.error("Validation failed", result.error);
    return null;
  }
  return result.data;
}

// =============================================================================
// EXPRESS MIDDLEWARE PATTERNS
// =============================================================================

type NextFunction = (err?: Error) => void;

function expressAsyncHandlerUnsafe(
  handler: (req: Request, res: Response) => Promise<void>
) {
  // ts-express-async-unsafe: UNSAFE async handler
  return (req: Request, res: Response, next: NextFunction) => {
    // UNSAFE: Promise errors not caught
    handler(req, res);
  };
}

function expressAsyncHandlerFix(
  handler: (req: Request, res: Response) => Promise<void>
) {
  // ts-express-async-fix: Proper async error handling
  return (req: Request, res: Response, next: NextFunction) => {
    handler(req, res).catch(next);
  };
}

// =============================================================================
// PERFORMANCE PATTERNS
// =============================================================================

function perfStringConcatUnsafe(items: string[]): string {
  // ts-perf-string-concat-unsafe: UNSAFE string concatenation
  let result = "";
  for (const item of items) {
    result += item + ",";
  }
  return result;
}

function perfStringConcatFix(items: string[]): string {
  // ts-perf-string-concat-fix: Array join
  return items.join(",");
}

function perfNestedLoopUnsafe(items: number[], targets: number[]): number[] {
  // ts-perf-nested-loop-unsafe: UNSAFE O(n²) lookup
  const result: number[] = [];
  for (const item of items) {
    if (targets.includes(item)) {
      result.push(item);
    }
  }
  return result;
}

function perfNestedLoopFix(items: number[], targets: number[]): number[] {
  // ts-perf-nested-loop-fix: O(n) with Set
  const targetSet = new Set(targets);
  return items.filter(item => targetSet.has(item));
}

// =============================================================================
// TIMING ATTACK PATTERNS
// =============================================================================

import * as crypto from 'crypto';

function timingCompareUnsafe(provided: string, expected: string): boolean {
  // ts-timing-compare-unsafe: UNSAFE non-constant-time comparison
  return provided === expected;
}

function timingCompareFix(provided: string, expected: string): boolean {
  // ts-timing-compare-fix: Constant-time comparison
  return crypto.timingSafeEqual(
    Buffer.from(provided),
    Buffer.from(expected)
  );
}

// =============================================================================
// FALSE POSITIVE PATTERNS
// =============================================================================

function fpInnerHtmlSanitized(): void {
  // ts-fp-innerhtml-sanitized: FALSE POSITIVE - properly sanitized
  const clean = DOMPurify.sanitize(userInput);
  element.innerHTML = clean;
}

function fpExecConstant(): void {
  // ts-fp-exec-constant: FALSE POSITIVE - constant command
  exec("ls -la /var/log", (err, stdout) => {
    console.log(stdout);
  });
}

function fpValidatedPath(filename: string): string {
  // ts-fp-validated-path: FALSE POSITIVE - path validated
  const safeName = path.basename(filename);
  if (!safeName || safeName.startsWith('.')) {
    throw new Error("Invalid filename");
  }
  return path.join("/uploads", safeName);
}

// Helper functions
function doSomething(): void {}
async function fetchData(): Promise<void> {}
async function riskyOperation(): Promise<void> {}
async function processItem(item: string): Promise<void> {}

// Export to avoid unused warnings
export {
  sqliTemplateEasy,
  sqliTemplateLiteralUnsafe,
  sqliTemplateLiteralFix,
  cmdiExecEasy,
  cmdiSpawnEasy,
  cmdiExecUnsafe,
  cmdiExecFix,
  pathTraversalJoinEasy,
  pathTraversalJoinUnsafe,
  pathTraversalJoinFix,
  xssInnerHtmlEasy,
  xssDangerouslyEasy,
  xssDocumentWriteEasy,
  xssEvalEasy,
  xssInnerHtmlUnsafe,
  xssInnerHtmlFix,
  secretApiKeyEasy,
  secretHardcodedUnsafe,
  secretHardcodedFix,
  errEmptyCatchEasy,
  errEmptyCatchUnsafe,
  errEmptyCatchFix,
  nullOptionalChainEasy,
  nullNonNullAssertionEasy,
  nullDerefUnsafe,
  nullDerefFix,
  logicLooseEqualityEasy,
  logicLooseEqualityUnsafe,
  logicLooseEqualityFix,
  asyncFloatingPromiseUnsafe,
  asyncFloatingPromiseFix,
  ssrfFetchUnsafe,
  ssrfFetchFix,
  redirectUnsafe,
  redirectFix,
  perfStringConcatUnsafe,
  perfStringConcatFix,
  timingCompareUnsafe,
  timingCompareFix,
  fpInnerHtmlSanitized,
  fpExecConstant,
  fpValidatedPath,
};
