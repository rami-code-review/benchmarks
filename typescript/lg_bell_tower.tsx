/**
 * Bell tower peal board: renders the tower name as the heading and the method
 * and change count as separate labelled cells.
 */

import React from 'react';

export interface PealSummaryProps {
  tower: string;
  method: string;
  changes: number;
}

export function PealSummary({ tower, method, changes }: PealSummaryProps): JSX.Element {
  return (
    <section>
      <h3>{tower}</h3>
      <dl>
        <dt>Method</dt>
        <dd data-testid="method">{method}</dd>
        <dt>Changes</dt>
        <dd data-testid="changes">{changes}</dd>
      </dl>
    </section>
  );
}
