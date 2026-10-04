// Color theme: dark by default, light if the system prefers it, or the one
// the person picks (remembered in this browser).

import { h } from './dom.js';
import { icon } from './icons.js';
import { t } from './i18n.js';

const KEY = 'termoak.theme';

export function getTheme() {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'dark' || v === 'light' ? v : 'system';
  } catch {
    return 'system';
  }
}

export function applyTheme(theme = getTheme()) {
  const root = document.documentElement;
  if (theme === 'dark' || theme === 'light') root.dataset.theme = theme;
  else delete root.dataset.theme;
  // Color of the browser bar on mobile.
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    const light = theme === 'light' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: light)').matches);
    meta.setAttribute('content', light ? '#f5f7f2' : '#0c100d');
  }
}

export function setTheme(theme) {
  try {
    if (theme === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch {
    /* no storage: only applied now */
  }
  applyTheme(theme);
  for (const el of document.querySelectorAll('.theme-switch button')) {
    el.setAttribute('aria-pressed', String(el.dataset.theme === theme));
  }
}

/** Theme switch (System / Dark / Light). */
export function themeSwitch() {
  const current = getTheme();
  const opts = [
    ['system', 'monitor', t('theme.system_long')],
    ['dark', 'moon', t('theme.dark_long')],
    ['light', 'sun', t('theme.light_long')],
  ];
  return h('div', { class: 'theme-switch', role: 'group', 'aria-label': t('theme.label') },
    opts.map(([value, ico, label]) => h('button', {
      type: 'button',
      title: label,
      'aria-label': label,
      'aria-pressed': String(current === value),
      dataset: { theme: value },
      onclick: () => setTheme(value),
    }, icon(ico, { size: 15 }))));
}

// When following the system theme, track its changes.
window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
  if (getTheme() === 'system') applyTheme('system');
});
