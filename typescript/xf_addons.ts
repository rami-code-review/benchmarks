// Addon lookups consumed by billing.

export interface Addon {
  code: string;
  price: number;
}

const addonTable = new Map<string, Addon>();

export function lookupAddon(code: string): Addon { return addonTable.get(code) ?? { code, price: 0 }; }
