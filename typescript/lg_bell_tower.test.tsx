import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { PealSummary } from './lg_bell_tower';

describe('PealSummary', () => {
  it('renders the tower, method and change count', () => {
    render(<PealSummary tower="St Aldric" method="Grandsire Triples" changes={5040} />);

    expect(screen.getByRole('heading').textContent).toBe('St Aldric');
    expect(screen.getByTestId('method').textContent).toBe('Grandsire Triples');
    expect(screen.getByTestId('changes').textContent).toBe('5040');
  });
});
