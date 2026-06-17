/**
 * Framework API-semantics fixtures (Next.js routing). The safe baseline
 * accounts for the query string; templates mutate it into the real-world bug
 * where usePathname()'s query-less return makes an equality wrongly match.
 */

import React from 'react';
import { usePathname, useSearchParams } from 'next/navigation';

declare function scrollMainToTop(): void;
type MouseEvt = React.MouseEvent<HTMLAnchorElement>;

/**
 * MobileBottomNav re-taps the active tab to pop to root, but preserves an
 * active search/filter query (only resets when there is no query).
 * Matches template: ts-next-usepathname-query-medium
 */
export function MobileBottomNav() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const handleTabClick = (href: string) => (e: MouseEvt) => {
    if (pathname === href && searchParams.size === 0) e.preventDefault();
    scrollMainToTop();
  };

  return (
    <nav data-q={searchParams.size}>
      <a onClick={handleTabClick('/clients')} href="/clients">Clients</a>
    </nav>
  );
}
