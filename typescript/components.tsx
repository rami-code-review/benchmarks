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
 */
export function Message({ content }: MessageProps) {
  // Safe: using textContent equivalent
  return <p>{content}</p>;
}

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
