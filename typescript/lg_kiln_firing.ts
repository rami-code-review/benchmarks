/**
 * Kiln firing programmes: schedule validation, slot parsing and the paging
 * offsets used by the firing log viewer.
 */

export interface Ramp {
  toCelsius: number;
  degreesPerHour: number;
}

export interface FiringProgramme {
  id: string;
  peakCelsius: number;
  soakMinutes: number;
  ramps: Ramp[];
}

export interface FiringRun {
  programmeId: string;
  slot: number;
  startedAt: string;
}

export function isFiringProgramme(value: unknown): value is FiringProgramme {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as Partial<FiringProgramme>;
  return (
    typeof candidate.id === 'string' &&
    typeof candidate.peakCelsius === 'number' &&
    typeof candidate.soakMinutes === 'number' &&
    Array.isArray(candidate.ramps)
  );
}

export function orderRunsBySlot(runs: FiringRun[]): FiringRun[] {
  return [...runs].sort((a, b) => a.slot - b.slot);
}

export function parseKilnSlot(raw: string): number {
  const slot = parseInt(raw, 10);
  return Number.isNaN(slot) ? -1 : slot;
}

export function pageOffsets(total: number, perPage: number): number[] {
  if (perPage <= 0) {
    return [];
  }
  const offsets: number[] = [];
  for (let offset = 0; offset < total; offset += perPage) {
    offsets.push(offset);
  }
  return offsets;
}

export function totalSoakMinutes(programmes: FiringProgramme[]): number {
  return programmes.reduce((sum, p) => sum + p.soakMinutes, 0);
}
