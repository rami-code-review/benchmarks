// Theme lookups consumed by the renderer.

export interface Theme {
  name: string;
  dark: boolean;
}

const themeCache = new Map<string, Theme>();

export function getTheme(id: string): Theme | null { const t = themeCache.get(id); return t ?? null; }
