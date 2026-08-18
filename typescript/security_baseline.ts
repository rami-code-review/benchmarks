/**
 * Security baselines: process execution, filesystem access, database queries,
 * DOM writes, redirects, and credential handling.
 *
 * Every block passes untrusted input through validation, argument arrays, or
 * parameter binding rather than into an interpreter.
 */

import * as path from 'path';
import * as fs from 'fs';
import { execFile, spawn, spawnSync } from 'child_process';

interface QueryResult {
  rows: unknown[];
}

interface UserRow {
  id: string;
  name: string;
  email: string;
}

interface Request {
  params: Record<string, string>;
  query: Record<string, string>;
  body: { name: string; email: string; [key: string]: unknown };
}

interface Response {
  status(code: number): Response;
  send(body: string): void;
  sendFile(p: string): void;
  redirect(target: string): void;
  json(body: unknown): void;
}

declare const db: { query: (sql: string, params?: unknown[]) => Promise<QueryResult> };
declare const prisma: {
  $queryRaw: (query: unknown) => Promise<UserRow[]>;
};
declare const Prisma: { sql: (strings: TemplateStringsArray, ...values: unknown[]) => unknown };
declare const repo: {
  createQueryBuilder(alias: string): {
    where(clause: string, params: Record<string, unknown>): {
      getMany(): Promise<UserRow[]>;
    };
  };
};
declare const User: { update(id: string, patch: Partial<UserRow>): Promise<void> };
declare const logger: { info: (msg: string) => void };
declare function isSafeUrl(candidate: string): boolean;
declare const defaultConfig: Record<string, unknown>;
declare const allowedKeys: string[];

// ts-cmdi-exec-easy
export function readNamedFile(filename: string): void {
  if (!/^[\w.-]+$/.test(filename)) {
      throw new Error('Invalid filename');
  }
  execFile('cat', [filename], (err, stdout) => {
      console.log(stdout);
  });
}

// ts-cmdi-exec-unsafe
export function grepDirectory(pattern: string, directory: string): Promise<string> {
  return new Promise((resolve) => {
    execFile('grep', ['-r', pattern, directory], (err, stdout) => {
        resolve(stdout);
    });
  });
}

// ts-cmdi-execsync-unsafe
export function findByName(directory: string, pattern: string): string {
  const result = spawnSync('find', [directory, '-name', pattern]);
  return result.stdout.toString();
}

// ts-cmdi-spawn-shell-unsafe
export function listDirectory(directory: string): void {
  const child = spawn('ls', ['-la', directory]);
  child.unref();
}

// ts-pathtraversal-express-unsafe
export function servePublicFile(req: Request, res: Response): void {
  const file = req.params.file;
  if (!/^[\w-]+\.\w+$/.test(file)) {
      return res.status(400).send('Invalid filename');
  }
  const baseDir = path.resolve(__dirname, 'public');
  const filePath = path.resolve(baseDir, file);
  if (!filePath.startsWith(baseDir + path.sep)) {
      return res.status(403).send('Access denied');
  }
  res.sendFile(filePath);
}

// ts-pathtraversal-join-unsafe
export function readUpload(filename: string): string {
  const baseDir = path.resolve(__dirname, 'uploads');
  const filePath = path.resolve(baseDir, filename);
  if (!filePath.startsWith(baseDir + path.sep)) {
      throw new Error('Path traversal detected');
  }
  return fs.readFileSync(filePath, 'utf8');
}

// ts-sqli-concat-unsafe
export async function findUserByName(name: string): Promise<QueryResult> {
  const result = await db.query('SELECT * FROM users WHERE name = $1', [name]);
  return result;
}

// ts-sqli-template-literal-unsafe
export async function findUserById(userId: string): Promise<QueryResult> {
  const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
  return result;
}

// ts-sqli-prisma-raw-unsafe
export async function findUserByEmail(email: string): Promise<UserRow[]> {
  const users = await prisma.$queryRaw(Prisma.sql`SELECT * FROM users WHERE email = ${email}`);
  return users;
}

// ts-sqli-typeorm-unsafe
export async function searchUsersByName(name: string): Promise<UserRow[]> {
  const users = await repo.createQueryBuilder('user').where('user.name = :name', { name }).getMany();
  return users;
}

// ts-secret-hardcoded-unsafe
export function requireApiKey(): string {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
      throw new Error('API_KEY not configured');
  }
  return apiKey;
}

// ts-secret-logging-unsafe
export function recordAuthentication(userId: string): void {
  logger.info(`User ${userId} authenticated`);
}

// ts-redirect-unsafe
export function redirectAfterLogin(res: Response, nextUrl: string): void {
  if (isSafeUrl(nextUrl)) res.redirect(nextUrl);
  else res.redirect("/")
}

// ts-xss-innerhtml-easy
export function renderMessage(element: HTMLElement, userMessage: string): void {
  element.textContent = userMessage;
}

// ts-xss-innerhtml-unsafe
export function buildNameBadge(name: string): HTMLElement {
  const div = document.createElement('div'); div.textContent = name;
  return div;
}

// ts-cve-mass-assignment
export async function updateProfile(req: Request, userId: string): Promise<void> {
  // Safe: only assign allowed fields
  const { name, email } = req.body;
  await User.update(userId, { name, email });
}

// ts-cve-prototype-pollution
export function mergeUserConfig(userConfig: Record<string, unknown>): Record<string, unknown> {
  // Safe: use structured clone or validated merge
  const safeConfig = { ...defaultConfig };
  for (const key of allowedKeys) {
    if (key in userConfig) {
      safeConfig[key] = userConfig[key];
    }
  }
  return safeConfig;
}
