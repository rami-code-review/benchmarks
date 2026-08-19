/**
 * Allotment society ledger: row validation, due-date ordering and the
 * page arithmetic behind the subscriptions table.
 */

export interface LedgerRow {
  id: string;
  plotRef: string;
  amountCents: number;
  dueOn: string;
}

export interface LedgerPage {
  rows: LedgerRow[];
  page: number;
  perPage: number;
}

export function isLedgerRow(value: unknown): value is LedgerRow {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const row = value as Partial<LedgerRow>;
  return (
    typeof row.id === 'string' &&
    typeof row.plotRef === 'string' &&
    typeof row.amountCents === 'number' &&
    typeof row.dueOn === 'string'
  );
}

export function sortByDueDate(rows: LedgerRow[]): LedgerRow[] {
  return [...rows].sort((a, b) => a.dueOn.localeCompare(b.dueOn));
}

export function hasNextPage(total: number, page: number, perPage: number): boolean {
  return page * perPage < total;
}

export function takePage(rows: LedgerRow[], page: number, perPage: number): LedgerPage {
  const start = (page - 1) * perPage;
  return { rows: rows.slice(start, start + perPage), page, perPage };
}

export function outstandingCents(rows: LedgerRow[]): number {
  return rows.reduce((sum, row) => sum + row.amountCents, 0);
}
