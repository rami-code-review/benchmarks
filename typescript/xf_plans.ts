// Plan lookups consumed by billing.

export interface Plan {
  code: string;
  price: number;
}

const planTable = new Map<string, Plan>();

export function lookupPlan(code: string): Plan { return planTable.get(code) ?? { code, price: 0 }; }
