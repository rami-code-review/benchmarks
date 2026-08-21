// Export file handles.

export interface Handle {
  writable: boolean;
  writeAll(rows: string[]): Promise<void>;
}

declare const files: { open(name: string): Promise<Handle>; close(h: Handle): Promise<void> };

export async function openExport(name: string): Promise<Handle> { const h = await files.open(name); if (!h.writable) { await files.close(h); throw new Error("not writable"); } return h; }
