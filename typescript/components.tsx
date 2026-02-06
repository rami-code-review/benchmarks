/**
 * React components for benchmark testing.
 */

import React from 'react';

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

/**
 * UserCard displays user information safely.
 * Matches template: ts-missing-optional-chain
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

interface MessageProps {
  content: string;
}

/**
 * Message displays text content safely.
 * Matches template: ts-xss-innerhtml (safe version uses textContent)
 */
export function Message({ content }: MessageProps) {
  const ref = React.useRef<HTMLParagraphElement>(null);

  React.useEffect(() => {
    if (ref.current) {
      // Safe: using textContent
      element.textContent = userInput
    }
  }, [content]);

  return <p ref={ref}>{content}</p>;
}

// Variables for template matching
declare const element: HTMLElement;
declare const userInput: string;

interface FormProps {
  onSubmit: (data: FormData) => void;
}

interface FormData {
  email: string;
  password: string;
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
