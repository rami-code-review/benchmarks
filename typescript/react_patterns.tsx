/**
 * React patterns: unconditional hooks, a single state container for list
 * selection, context instead of hand-threaded props, and direct module imports.
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
// Direct imports - tree-shakeable
import { UserService } from './services/UserService';
import { validateEmail } from './utils/validators';
import { Button } from '@/components/Button';

interface User {
  id: string;
  name: string;
}

interface Item {
  id: string;
  name: string;
}

interface Theme {
  primary: string;
}

declare const defaultTheme: Theme;
declare function fetchUser(userId: string): Promise<User>;
declare function Page(): JSX.Element;

// ts-react-conditional-hook-easy
function UserProfile({ userId }: { userId: string | null }) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    if (userId) {
      fetchUser(userId).then(setUser);
    }
  }, [userId]);

  if (!userId) return <div>No user selected</div>;
  return <div>{user?.name}</div>;
}

// ts-react-usestate-loop-easy
function ItemList({ items }: { items: Item[] }) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const toggleItem = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <ul>
      {items.map(item => (
        <li key={item.id} onClick={() => toggleItem(item.id)}>
          {item.name}
        </li>
      ))}
    </ul>
  );
}

// ts-design-prop-drilling-medium
const ThemeContext = createContext<Theme>(defaultTheme);

function App() {
  const [theme, setTheme] = useState<Theme>(defaultTheme);
  return (
    <ThemeContext.Provider value={theme}>
      <Page />
    </ThemeContext.Provider>
  );
}

function DeepComponent() {
  const theme = useContext(ThemeContext);
  return <div style={{ color: theme.primary }}>Content</div>;
}

// ts-xss-react-href-unsafe
export function ExternalLink({ url, text }: { url: string; text: string }) {
  const safeUrl = url.startsWith('http://') || url.startsWith('https://') ? url : '#';
  return <a href={safeUrl}>{text}</a>;
}

export function SignupForm({ email }: { email: string }) {
  const valid = validateEmail(email);
  return (
    <form>
      <Button disabled={!valid}>Create account</Button>
    </form>
  );
}

export async function loadCurrentUser(userId: string): Promise<User> {
  return UserService.findById(userId);
}

export { UserProfile, ItemList, App, DeepComponent };
