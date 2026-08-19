/**
 * Aviary monitor: a ringed-bird list whose visible subset is memoised, and a
 * header that re-summarises zones only when the zone set actually changes.
 */

import React, { useEffect, useMemo, useState } from 'react';

export interface Bird {
  ring: string;
  species: string;
  zoneId: string;
}

export interface AviaryZone {
  id: string;
  label: string;
  occupancy: number;
}

export interface RingedBirdListProps {
  birds: Bird[];
  ringPrefix: string;
}

declare function RingTable(props: { birds: Bird[]; selected: string[] }): JSX.Element;
declare function summariseZones(zoneIds: string[]): string;

export function RingedBirdList({ birds, ringPrefix }: RingedBirdListProps): JSX.Element {
  const [selected, setSelected] = useState<string[]>([]);
  const visible = useMemo(() => birds.filter((b) => b.ring.startsWith(ringPrefix)), [birds, ringPrefix]);

  useEffect(() => {
    setSelected(visible.map((b) => b.ring));
  }, [visible]);

  return <RingTable birds={visible} selected={selected} />;
}

export function AviaryHeader({ zones }: { zones: AviaryZone[] }): JSX.Element {
  const [summary, setSummary] = useState('');
  const zoneIds = useMemo(() => zones.map((z) => z.id).sort(), [zones]);

  useEffect(() => {
    setSummary(summariseZones(zoneIds));
  }, [zoneIds]);

  return <h2>{summary}</h2>;
}
