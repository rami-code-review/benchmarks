/**
 * Asynchronous control-flow patterns: awaiting sequential work, settling
 * batches, and keeping rejections attached to a handler.
 */

interface Order {
  id: string;
  userId: string;
  paymentId: string;
}

interface Item {
  id: string;
  payload: string;
}

interface Result {
  taskId: string;
  output: string;
}

interface Task {
  id: string;
}

interface UserRecord {
  id: string;
  email: string;
}

interface Mutex {
  acquire(): Promise<() => void>;
}

declare const Mutex: { new (): Mutex };
declare const logger: {
  warn: (msg: string, err: unknown) => void;
  error: (msg: string, err: unknown) => void;
};
declare function asyncOp(cb: (err: Error | null, result: unknown) => void): void;
declare function validateOrder(order: Order): Promise<void>;
declare function chargePayment(paymentId: string): Promise<void>;
declare function sendConfirmationEmail(userId: string): Promise<void>;
declare function sendNotification(target: UserRecord | Result): Promise<void>;
declare function saveItem(item: Item): Promise<void>;
declare function processTask(task: Task): Promise<Result>;
declare function deleteTemporaryFiles(): Promise<void>;
declare function fetchUser(id: string): Promise<UserRecord>;
declare function updateProfile(user: UserRecord): Promise<Result>;
declare const users: UserRecord[];
declare const id: string;

// ts-async-callback-mix-unsafe
export function promisifyAsyncOp(): Promise<unknown> {
  return new Promise((resolve, reject) => {
    asyncOp((err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  })
}

// ts-async-fire-forget-easy
async function processOrder(order: Order) {
  await validateOrder(order);
  await chargePayment(order.paymentId);
  await sendConfirmationEmail(order.userId);
}

// ts-async-foreach-await-easy
export async function notifyEveryUser(): Promise<void> {
  for (const user of users) {
    await sendNotification(user);
  }
}

// ts-async-foreach-easy
async function processItems(items: Item[]) {
  await Promise.all(items.map(async (item) => {
    await saveItem(item);
  }));
}

// ts-async-promise-all-no-catch-medium
async function fetchAll(urls: string[]): Promise<Response[]> {
  const results = await Promise.allSettled(urls.map(url => fetch(url)));
  return results
    .filter((r): r is PromiseFulfilledResult<Response> => r.status === "fulfilled")
    .map(r => r.value);
}

// ts-async-race-shared-state-hard
class Counter {
  private value = 0;
  private mutex = new Mutex();

  async increment(): Promise<number> {
    const release = await this.mutex.acquire();
    try {
      this.value++;
      return this.value;
    } finally {
      release();
    }
  }
}

// ts-async-then-no-return-medium
export function refreshProfile(): void {
  fetchUser(id)
    .then(user => {
      return updateProfile(user);
    })
    .then(result => sendNotification(result));
}

// ts-async-unhandled-rejection-medium
async function cleanup() {
  try {
    await deleteTemporaryFiles();
  } catch (err) {
    logger.warn('cleanup failed', err);
  }
}

cleanup();

// ts-logic-promise-all-settle-hard
export async function runTasks(tasks: Task[]): Promise<Result[]> {
  const results = await Promise.allSettled(tasks.map(t => processTask(t)));
  const successes = results
    .filter((r): r is PromiseFulfilledResult<Result> => r.status === 'fulfilled')
    .map(r => r.value);
  return successes;
}

export { processOrder, processItems, fetchAll, Counter, cleanup };
