/**
 * Behavioural tests: each case asserts an observable outcome, and spies are
 * restored so they do not leak into the next test.
 */

interface CartItem {
  id: number;
  price: number;
}

declare class Cart {
  addItem(item: CartItem): void;
  getTotal(): number;
  getItemCount(): number;
}

export interface UserRecord {
  id: string;
  email: string;
  name?: string;
}

declare function createUser(input: { email: string }): Promise<UserRecord>;
declare function fetchUser(id: string): Promise<UserRecord>;
declare const jest: {
  spyOn(target: unknown, method: string): {
    mockRestore(): void;
    mockResolvedValue(value: unknown): void;
  };
};
declare function describe(name: string, fn: () => void): void;
declare function test(name: string, fn: () => void | Promise<void>): void;
declare function it(name: string, fn: () => void | Promise<void>): void;
declare function afterEach(fn: () => void): void;
declare function expect(actual: unknown): {
  toBe(expected: unknown): void;
  toBeDefined(): void;
};

// ts-test-implementation-detail-medium
test('adds item to cart', () => {
  const cart = new Cart();
  cart.addItem({ id: 1, price: 10 });
  expect(cart.getTotal()).toBe(10);
  expect(cart.getItemCount()).toBe(1);
});

// ts-test-mock-no-restore-medium
describe('fetchUser', () => {
  const mockFetch = jest.spyOn(global, 'fetch');

  afterEach(() => {
    mockFetch.mockRestore();
  });

  it('returns user data', async () => {
    mockFetch.mockResolvedValue(new Response(JSON.stringify({ name: 'Alice' })));
    const user = await fetchUser('1');
    expect(user.name).toBe('Alice');
  });
});

// ts-test-no-assertion-easy
test('creates user', async () => {
  const user = await createUser({ email: 'test@example.com' });
  expect(user.id).toBeDefined();
  expect(user.email).toBe('test@example.com');
});
