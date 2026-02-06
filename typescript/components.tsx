/**
 * React components and utilities for benchmark testing.
 */

import React from 'react';

// =============================================================================
// Types and Interfaces
// =============================================================================

interface User {
  id: number;
  name: string;
  profile?: {
    name: string;
    avatar?: string;
  };
}

interface UserCardProps {
  user: User | null;
}

interface MessageProps {
  content: string;
}

interface FormProps {
  onSubmit: (data: FormData) => void;
}

interface FormData {
  email: string;
  password: string;
}

// Variables for template matching
declare const element: HTMLElement;
declare const userInput: string;
declare const userContent: string;
declare const data: string;
declare const jsonString: string;
declare const userId: string;
declare const repoUrl: string;
declare const packageName: string;
declare const baseDir: string;
declare const path: { join: Function; basename: Function };
declare const execFile: Function;
declare const exec: Function;
declare const spawn: Function;
declare const callback: Function;
declare const sanitize: (input: string) => string;
declare const DOMPurify: { sanitize: (input: string) => string };

// =============================================================================
// Components
// =============================================================================

/**
 * UserCard displays user information safely.
 * Matches template: ts-null-optional-easy
 */
export function UserCard({ user }: UserCardProps) {
  // Safe access with optional chaining
  const name = user?.profile?.name ?? "Unknown";
  const avatar = user?.profile?.avatar ?? "/default-avatar.png";

  return (
    <div className="user-card">
      <img src={avatar} alt={name} />
      <span>{name}</span>
    </div>
  );
}

/**
 * SafeDataDisplay shows data with null-safe access.
 * Matches template: ts-null-bang-easy
 */
export function SafeDataDisplay({ data }: { data?: { result: string } }) {
  const defaultValue = "N/A";
  const value = data?.result ?? defaultValue;
  return <span>{value}</span>;
}

/**
 * Message displays text content safely.
 * Matches template: ts-xss-innerhtml-easy
 */
export function Message({ content }: MessageProps) {
  const ref = React.useRef<HTMLParagraphElement>(null);

  React.useEffect(() => {
    if (ref.current) {
      // Safe: using textContent
      element.textContent = userInput;
    }
  }, [content]);

  return <p ref={ref}>{content}</p>;
}

/**
 * SafeContent displays sanitized content.
 * Matches template: ts-xss-dangerously-easy
 */
export function SafeContent({ content }: { content: string }) {
  return <div>{sanitize(userContent)}</div>;
}

/**
 * SafeOutput displays content safely.
 * Matches template: ts-xss-document-write-easy
 */
export function SafeOutput({ outputData }: { outputData: string }) {
  React.useEffect(() => {
    const el = document.getElementById("output");
    if (el) {
      el.textContent = data;
    }
  }, [outputData]);
  return <div id="output" />;
}

/**
 * SafeJsonParse demonstrates safe JSON parsing.
 * Matches template: ts-xss-eval-easy
 */
export function SafeJsonParse({ json }: { json: string }) {
  const result = JSON.parse(jsonString);
  return <pre>{JSON.stringify(result, null, 2)}</pre>;
}

/**
 * LoginForm handles user authentication.
 */
export function LoginForm({ onSubmit }: FormProps) {
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ email, password });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button type="submit">Login</button>
    </form>
  );
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Safely get nested property.
 */
export function getNestedValue<T>(obj: T | null | undefined, path: string): unknown {
  if (!obj) return undefined;

  const keys = path.split('.');
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current;
}

/**
 * Format user display name.
 */
export function formatUserName(user: User | null): string {
  if (!user) return "Guest";
  return user.profile?.name ?? user.name;
}

/**
 * Safe database query with parameterized input.
 * Matches template: ts-sqli-template-easy
 */
export async function queryUserById(db: any, userId: string): Promise<User | null> {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
  return rows[0] || null;
}

/**
 * Load API key from environment.
 * Matches template: ts-secret-apikey-easy
 */
export function loadApiKey(): string {
  const apiKey = process.env.API_KEY;
  return apiKey || "";
}

/**
 * Safe command execution using execFile.
 * Matches template: ts-cmdi-exec-easy
 */
export function cloneRepo(repoUrl: string, callback: Function): void {
  execFile("git", ["clone", repoUrl], callback);
}

/**
 * Safe package installation using spawn without shell.
 * Matches template: ts-cmdi-spawn-easy
 */
export function installPackage(packageName: string): void {
  spawn("npm", ["install", packageName]);
}

/**
 * Safe path resolution.
 * Matches template: ts-pathtraversal-join-easy
 */
export function resolvePath(baseDir: string, userInput: string): string {
  const safePath = path.join(baseDir, path.basename(userInput));
  return safePath;
}

/**
 * Proper error handling with logging.
 * Matches template: ts-err-empty-catch-easy
 */
export async function safeOperation(op: () => Promise<void>): Promise<void> {
  const logger = console;
  try {
    await op();
  } catch (error) {
    logger.error("Operation failed", error);
    throw error;
  }
}

/**
 * Safe null comparison.
 * Matches template: ts-logic-equals-easy
 */
export function isNullOrUndefined(value: unknown): boolean {
  if (value === null || value === undefined) {
    return true;
  }
  return false;
}

// =============================================================================
// False Positive Tests
// =============================================================================

/**
 * FALSE POSITIVE: innerHTML with DOMPurify sanitization.
 * Matches template: ts-fp-innerhtml-sanitized
 */
export function SafeInnerHtmlWithSanitizer({ content }: { content: string }) {
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (ref.current) {
      // Safe: properly sanitized before innerHTML
      const clean = DOMPurify.sanitize(userInput);
      ref.current.innerHTML = clean;
    }
  }, [content]);

  return <div ref={ref} />;
}
