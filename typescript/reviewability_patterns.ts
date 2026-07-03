/**
 * Benchmark patterns for TypeScript reviewability (future-maintainer change risk).
 *
 * Each block contains the EXACT OriginalCode from templates.go.
 */

// Mock service for pattern matching
declare const invoiceService: { execute(command: InvoiceCommand): unknown };

// ts-reviewability-parallel-state-medium - exact multi-line
type AccountStatus = "active" | "disabled";

interface Account {
  id: string;
  status: AccountStatus;
}

function isActive(account: Account): boolean {
  return account.status === "active";
}

// ts-reviewability-opaque-workflow-hard - exact multi-line
type InvoiceAction = "send" | "void";

interface InvoiceCommand {
  action: InvoiceAction;
  invoiceId: string;
  actorId: string;
}

function executeInvoiceCommand(command: InvoiceCommand) {
  return invoiceService.execute(command);
}
