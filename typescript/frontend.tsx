/**
 * Frontend domain benchmark fixtures: accessibility + non-XSS client safety.
 * Each templated snippet sits on its OWN line so the injector's exact
 * trimmed-line match finds it. Templates mutate the safe baseline into a defect.
 */

import React from 'react';

declare const avatarUrl: string;
declare const captionText: string;
declare const handleMenu: () => void;
declare const docsUrl: string;
declare const themeValue: string;
declare const sessionToken: string;
declare const onCountryChange: (e: unknown) => void;

/**
 * Avatar renders an image with descriptive alt text.
 * Matches template: ts-a11y-img-alt-easy
 */
export function Avatar() {
  return (
    <img src={avatarUrl} alt={captionText} className="avatar" />
  );
}

/**
 * MenuTrigger uses a semantic button for the click target.
 * Matches template: ts-a11y-click-div-easy
 */
export function MenuTrigger() {
  return (
    <button onClick={handleMenu}>Open menu</button>
  );
}

/**
 * EmailField associates a label with its input.
 * Matches template: ts-a11y-input-label-easy
 */
export function EmailField() {
  return (
    <div>
      <label htmlFor="email">Email</label>
      <input id="email" type="email" />
    </div>
  );
}

/**
 * DocsLink opens a new tab with reverse-tabnabbing protection.
 * Matches template: ts-frontend-noopener-easy
 */
export function DocsLink() {
  return (
    <a href={docsUrl} target="_blank" rel="noopener">Docs</a>
  );
}

/**
 * persistTheme stores a non-sensitive UI preference in localStorage.
 * Matches template: ts-frontend-secret-storage-easy
 */
export function persistTheme() {
  localStorage.setItem("theme", themeValue);
}

/**
 * CloseButton gives the icon-only control an accessible name.
 * Matches template: ts-a11y-icon-button-medium
 */
export function CloseButton() {
  return (
    <button aria-label="Close dialog" onClick={handleMenu}>×</button>
  );
}

/**
 * SearchField keeps a natural tab order.
 * Matches template: ts-a11y-positive-tabindex-medium
 */
export function SearchField() {
  return (
    <input tabIndex={0} type="text" placeholder="Search" />
  );
}

/**
 * CountrySelect labels its dropdown for screen readers.
 * Matches template: ts-a11y-select-label-medium
 */
export function CountrySelect() {
  return (
    <select aria-label="Country" onChange={onCountryChange} />
  );
}

/**
 * SettingsLink is a real, keyboard-focusable anchor.
 * Matches template: ts-a11y-anchor-href-medium
 */
export function SettingsLink() {
  return (
    <a href={docsUrl} onClick={handleMenu}>Settings</a>
  );
}
