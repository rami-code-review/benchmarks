/**
 * FRAMEWORK MISUSE - LLM-ADVANTAGE PATTERNS
 *
 * Framework-specific patterns requiring semantic understanding.
 * SAST tools score ~10% on these patterns.
 */

import { createContext, useContext, useEffect, useState } from 'react';
import express, { Request, Response, NextFunction } from 'express';

// =============================================================================
// REACT FRAMEWORK ISSUES
// =============================================================================

// -----------------------------------------------------------------------------
// ts-react-useeffect-deps-easy: useEffect missing dependencies
// -----------------------------------------------------------------------------

interface User {
  id: string;
  name: string;
}

// SAFE: All dependencies listed
function UserProfileSafe({ userId }: { userId: string }) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    fetchUser(userId).then(setUser);
  }, [userId]); // userId is in dependency array

  return <div>{user?.name}</div>;
}

// VULNERABLE: Missing userId dependency - stale closure
function UserProfileBad({ userId }: { userId: string }) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    fetchUser(userId).then(setUser);
  }, []); // Missing userId dependency!

  return <div>{user?.name}</div>;
}

// -----------------------------------------------------------------------------
// ts-react-usestate-loop-easy: useState called in loop
// -----------------------------------------------------------------------------

interface Item {
  id: string;
  name: string;
}

// SAFE: Single state for all items
function ItemListSafe({ items }: { items: Item[] }) {
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

// VULNERABLE: Hook called in loop - violates Rules of Hooks
function ItemListBad({ items }: { items: Item[] }) {
  return (
    <ul>
      {items.map(item => {
        const [selected, setSelected] = useState(false); // Hook in loop!
        return (
          <li key={item.id} onClick={() => setSelected(!selected)}>
            {item.name}
          </li>
        );
      })}
    </ul>
  );
}

// -----------------------------------------------------------------------------
// ts-react-conditional-hook-easy: Hook called conditionally
// -----------------------------------------------------------------------------

// SAFE: Hook called unconditionally, early return after
function UserProfileConditionalSafe({ userId }: { userId: string | null }) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    if (userId) {
      fetchUser(userId).then(setUser);
    }
  }, [userId]);

  if (!userId) return <div>No user selected</div>;
  return <div>{user?.name}</div>;
}

// VULNERABLE: Hook after early return - conditional hook!
function UserProfileConditionalBad({ userId }: { userId: string | null }) {
  if (!userId) return <div>No user selected</div>;

  const [user, setUser] = useState<User | null>(null); // Hook after early return!

  useEffect(() => {
    fetchUser(userId).then(setUser);
  }, [userId]);

  return <div>{user?.name}</div>;
}

// -----------------------------------------------------------------------------
// ts-design-prop-drilling-medium: Excessive prop drilling
// -----------------------------------------------------------------------------

interface Theme {
  primary: string;
  secondary: string;
}

const defaultTheme: Theme = { primary: '#000', secondary: '#fff' };
const ThemeContext = createContext<Theme>(defaultTheme);

// SAFE: Uses context to avoid prop drilling
function AppSafe() {
  const [theme] = useState<Theme>(defaultTheme);
  return (
    <ThemeContext.Provider value={theme}>
      <PageSafe />
    </ThemeContext.Provider>
  );
}

function PageSafe() {
  return <SectionSafe />;
}

function SectionSafe() {
  return <DeepComponentSafe />;
}

function DeepComponentSafe() {
  const theme = useContext(ThemeContext);
  return <div style={{ color: theme.primary }}>Content</div>;
}

// VULNERABLE: Excessive prop drilling through many levels
function AppBad({ theme }: { theme: Theme }) {
  return <PageBad theme={theme} />;
}

function PageBad({ theme }: { theme: Theme }) {
  return <SectionBad theme={theme} />;
}

function SectionBad({ theme }: { theme: Theme }) {
  return <ComponentBad theme={theme} />;
}

function ComponentBad({ theme }: { theme: Theme }) {
  return <DeepComponentBad theme={theme} />;
}

function DeepComponentBad({ theme }: { theme: Theme }) {
  return <div style={{ color: theme.primary }}>Content</div>;
}

// =============================================================================
// EXPRESS FRAMEWORK ISSUES
// =============================================================================

const app = express();

// -----------------------------------------------------------------------------
// ts-express-next-missing-easy: Middleware not calling next()
// -----------------------------------------------------------------------------

// SAFE: Middleware calls next()
app.use((req: Request, res: Response, next: NextFunction) => {
  (req as any).startTime = Date.now();
  next();
});

// VULNERABLE: Middleware doesn't call next() - request hangs
app.use((req: Request, res: Response, next: NextFunction) => {
  (req as any).startTime = Date.now();
  // Forgot to call next() - request hangs!
});

// -----------------------------------------------------------------------------
// ts-express-async-error-medium: Async middleware without error handling
// -----------------------------------------------------------------------------

interface UserService {
  findById(id: string): Promise<User>;
}

const userService: UserService = {
  findById: async (id: string) => ({ id, name: 'Test' })
};

// Helper for safe async handlers
const asyncHandler = (fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

// SAFE: Uses asyncHandler wrapper
app.get('/users/:id/safe', asyncHandler(async (req: Request, res: Response) => {
  const user = await userService.findById(req.params.id);
  res.json(user);
}));

// VULNERABLE: Async handler without error handling - unhandled rejection
app.get('/users/:id/bad', async (req: Request, res: Response) => {
  const user = await userService.findById(req.params.id); // Unhandled rejection
  res.json(user);
});

// =============================================================================
// ASYNC/CONCURRENCY ISSUES
// =============================================================================

// -----------------------------------------------------------------------------
// ts-async-fire-forget-easy: Promise not awaited
// -----------------------------------------------------------------------------

interface Order {
  id: string;
  userId: string;
  paymentId: string;
}

async function validateOrder(order: Order): Promise<void> {}
async function chargePayment(paymentId: string): Promise<void> {}
async function sendConfirmationEmail(userId: string): Promise<void> {}

// SAFE: All promises awaited
async function processOrderSafe(order: Order) {
  await validateOrder(order);
  await chargePayment(order.paymentId);
  await sendConfirmationEmail(order.userId);
}

// VULNERABLE: Last promise not awaited - errors lost
async function processOrderBad(order: Order) {
  await validateOrder(order);
  await chargePayment(order.paymentId);
  sendConfirmationEmail(order.userId); // Fire-and-forget - errors lost!
}

// -----------------------------------------------------------------------------
// ts-async-callback-error-medium: Missing error handling in async callback
// -----------------------------------------------------------------------------

async function processFile(file: string): Promise<string> {
  return `processed: ${file}`;
}

const files = ['a.txt', 'b.txt', 'c.txt'];

// SAFE: Error handling in callback
files.forEach(file => {
  processFile(file)
    .then(result => console.log('Processed:', result))
    .catch(err => console.error('Failed to process:', file, err));
});

// VULNERABLE: No .catch() - errors silently lost
files.forEach(file => {
  processFile(file).then(result => {
    console.log('Processed:', result);
  }); // No .catch() - errors silently lost
});

// Helper function
async function fetchUser(userId: string): Promise<User> {
  return { id: userId, name: 'Test User' };
}

export {
  UserProfileSafe,
  UserProfileBad,
  ItemListSafe,
  ItemListBad,
  AppSafe,
  AppBad,
  processOrderSafe,
  processOrderBad,
};
