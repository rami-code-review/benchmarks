/**
 * Express wiring. Async route handlers are wrapped so a rejected promise
 * reaches the error middleware, and request-scoped middleware always yields
 * control with next().
 */

interface Req {
  params: Record<string, string>;
  startTime?: number;
}

interface Res {
  json(body: unknown): void;
}

type Next = () => void;
type Handler = (req: Req, res: Res) => Promise<void>;

interface App {
  get(route: string, handler: (req: Req, res: Res) => void): void;
  use(handler: (req: Req, res: Res, next: Next) => void): void;
}

export interface UserRecord {
  id: string;
  name: string;
}

declare const app: App;
declare const userService: { findById(id: string): Promise<UserRecord> };
declare function asyncHandler(handler: Handler): (req: Req, res: Res) => void;

// ts-express-async-error-medium
app.get('/users/:id', asyncHandler(async (req, res) => {
  const user = await userService.findById(req.params.id);
  res.json(user);
}));

// ts-express-next-missing-easy
app.use((req, res, next) => {
  req.startTime = Date.now();
  next();
});
