/**
 * Orchard harvest dashboard: a window of rows anchored to a stable timestamp
 * and a grade panel whose counts are refetched only when the filter changes.
 */

import React, { useEffect, useMemo, useState } from 'react';

export interface HarvestRow {
  blockId: string;
  variety: string;
  bins: number;
}

export interface GradeCount {
  grade: string;
  bins: number;
}

export interface GradeFilter {
  grades: string[];
  orchardId: string;
}

declare function fetchHarvestRows(orchardId: string, asOf: Date): Promise<HarvestRow[]>;
declare function loadGradeCounts(filter: GradeFilter): Promise<GradeCount[]>;
declare function HarvestTable(props: { rows: HarvestRow[] }): JSX.Element;
declare function GradeCounts(props: { counts: GradeCount[] }): JSX.Element;

export function HarvestWindow({ orchardId }: { orchardId: string }): JSX.Element {
  const [rows, setRows] = useState<HarvestRow[]>([]);
  const asOf = useMemo(() => new Date(), [orchardId]);

  useEffect(() => {
    let cancelled = false;
    fetchHarvestRows(orchardId, asOf).then((next) => {
      if (!cancelled) {
        setRows(next);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [orchardId, asOf]);

  return <HarvestTable rows={rows} />;
}

export function GradePanel({ orchardId, grades }: GradeFilter): JSX.Element {
  const [counts, setCounts] = useState<GradeCount[]>([]);
  const filter = useMemo(() => ({ grades, orchardId }), [grades, orchardId]);

  useEffect(() => {
    loadGradeCounts(filter).then(setCounts);
  }, [filter]);

  return <GradeCounts counts={counts} />;
}
