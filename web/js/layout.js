// Page layouts: auth (centered card) and app (sidebar). The app layout is reused across routes so the sidebar is not
// re-rendered on every navigation.

import { h, clear, replace } from './dom.js';
import { icon } from './icons.js';
import { state, currentUser, needsVerification, signOut, subscribe, loadMe } from './session.js';
import { navigate } from './router.js';
import { api } from './api.js';
import { avatar, dropdown, toast, toastError, busy, languagePicker } from './ui.js';
import { themeSwitch, getTheme, setTheme } from './theme.js';
import { t, tx } from './i18n.js';

const root = () => document.getElementById('app');

let current = null; // {type, main, update}

function brand(href = '/') {
  return h('a', { class: 'brand', href, 'aria-label': t('layout.brand_home') },
    h('img', { src: '/assets/icon.svg', alt: '', width: 30, height: 30 }),
    h('span', { class: 'brand-name' }, 'Term', h('span', null, 'oak')));
}

function skipLink() {
  return h('a', { class: 'skip-link', href: '#content', 'data-external': '', onclick: (e) => {
    e.preventDefault();
    const main = document.getElementById('content');
    if (main) {
      main.setAttribute('tabindex', '-1');
      main.focus();
    }
  } }, t('layout.skip_to_content'));
}

// --- Auth layout ----------------------------------------------------------

function authShell(content) {
  const info = state.info || {};
  return h('div', { class: 'auth' },
    skipLink(),
    h('div', { class: 'auth-top' }, brand('/')),
    h('main', { class: 'auth-main', id: 'content' }, content),
    h('div', { class: 'auth-bottom' },
      `Termoak ${info.version || ''}`,
      info.terms_url ? [' · ', h('a', { href: info.terms_url, target: '_blank', rel: 'noopener noreferrer' }, t('layout.auth.terms'))] : null,
      info.privacy_url ? [' · ', h('a', { href: info.privacy_url, target: '_blank', rel: 'noopener noreferrer' }, t('layout.auth.privacy'))] : null,
      h('div', { class: 'auth-controls' }, languagePicker({ small: true }), themeSwitch())));
}

// --- App layout -----------------------------------------------------------

const appNav = () => [
  ['/app/sessions', t('nav.sessions'), 'terminal', 'sessions'],
  ['/app/teams', t('nav.teams'), 'users', 'teams'],
  ['/app/account', t('nav.account'), 'user', 'account'],
];

function userMenu(placement) {
  const u = currentUser() || {};
  const trigger = placement === 'up'
    ? h('button', { class: 'user-button', type: 'button' },
      avatar(u.name, u.email),
      h('span', { class: 'user-button-text' },
        h('span', { class: 'user-button-name' }, u.name || u.email || t('layout.your_account')),
        h('span', { class: 'user-button-sub' }, h('span', null, u.email || ''))),
      icon('chevron-up-down', { size: 16 }))
    : h('button', { class: 'btn btn-ghost btn-icon', type: 'button', 'aria-label': t('layout.account_menu') }, avatar(u.name, u.email, 'sm'));
  return dropdown({
    button: trigger,
    placement,
    items: () => [
      { header: u.email || '' },
      { label: t('layout.my_account'), icon: 'user', href: '/app/account' },
      { label: t('layout.menu.security'), icon: 'shield', href: '/app/account/security' },
      { separator: true },
      { header: t('theme.title') },
      ...[['system', t('theme.system'), 'monitor'], ['dark', t('theme.dark'), 'moon'], ['light', t('theme.light'), 'sun']].map(([value, label, ico]) => ({
        label: getTheme() === value ? `${label} ✓` : label,
        icon: ico,
        onClick: () => setTheme(value),
      })),
      { separator: true },
      { label: t('common.sign_out'), icon: 'logout', danger: true, onClick: logout },
    ],
  });
}

export async function logout() {
  await signOut();
  toast(t('layout.signed_out'), 'success');
  navigate('/login');
}

function verifyBanner() {
  const u = currentUser();
  const btn = h('button', { class: 'btn btn-sm', type: 'button' }, icon('send', { size: 15 }), t('layout.verify.resend'));
  btn.addEventListener('click', () => busy(btn, async () => {
    try {
      const r = await api.post('/me/verify-email');
      toast(t('layout.verify.sent', { email: r.email }), 'success');
    } catch (e) {
      toastError(e);
    }
  }));
  return h('div', { class: 'app-banner', role: 'region', 'aria-label': t('layout.verify.title') },
    h('div', { class: 'app-banner-inner' },
      icon('mail', { size: 19 }),
      h('div', { class: 'grow' },
        h('strong', null, t('layout.verify.title')), ' ',
        tx('layout.verify.text', { email: h('strong', null, u ? u.email : '') })),
      btn));
}

function appShell() {
  const main = h('div', { class: 'app-content', id: 'content' });
  const banner = h('div');
  const navLinks = appNav().map(([href, label, ico, key]) => h('a', { class: 'side-link', href, dataset: { nav: key } }, icon(ico, { size: 18 }), label));
  const closeBtn = h('button', { class: 'btn btn-ghost btn-icon btn-sm sidebar-close', type: 'button', 'aria-label': t('layout.menu_close') }, icon('x'));
  // The user menus are re-rendered when the name or email changes.
  const userSlot = h('div', null, userMenu('up'));
  const userSlotTop = h('div', { class: 'app-topbar-end' }, userMenu('down'));
  const sidebar = h('aside', { class: 'sidebar', id: 'sidebar', 'aria-label': t('layout.app_nav') },
    h('div', { class: 'sidebar-brand' }, brand('/app'), closeBtn),
    h('nav', { class: 'side-nav', 'aria-label': t('layout.app_nav_short') }, navLinks),
    h('div', { class: 'sidebar-spacer' }),
    userSlot);
  const menuBtn = h('button', { class: 'btn btn-ghost btn-icon', type: 'button', 'aria-label': t('layout.menu_open'), 'aria-controls': 'sidebar', 'aria-expanded': 'false' }, icon('menu', { size: 20 }));
  const topbar = h('div', { class: 'app-topbar' }, menuBtn, brand('/app'), userSlotTop);
  const scrim = h('div', { class: 'scrim' });
  const shell = h('div', { class: 'app' }, skipLink(), sidebar, scrim, h('div', { class: 'app-main' }, topbar, banner, main));

  const setOpen = (open) => {
    shell.classList.toggle('nav-open', open);
    menuBtn.setAttribute('aria-expanded', String(open));
    if (open) closeBtn.focus();
  };
  menuBtn.addEventListener('click', () => setOpen(true));
  closeBtn.addEventListener('click', () => setOpen(false));
  scrim.addEventListener('click', () => setOpen(false));
  sidebar.addEventListener('click', (e) => {
    if (e.target.closest('a')) setOpen(false);
  });
  shell.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && shell.classList.contains('nav-open')) {
      setOpen(false);
      menuBtn.focus();
    }
  });

  let userKey = '';
  const updateBanner = () => {
    replace(banner, needsVerification() ? verifyBanner() : null);
    const me = currentUser() || {};
    const key = `${me.name}|${me.email}`;
    if (userKey && key !== userKey) {
      replace(userSlot, userMenu('up'));
      replace(userSlotTop, userMenu('down'));
    }
    userKey = key;
  };
  updateBanner();
  const unsub = subscribe(updateBanner);

  // When coming back to the tab, check again if the email is still unverified.
  const onFocus = () => {
    if (needsVerification()) loadMe().catch(() => {});
  };
  window.addEventListener('focus', onFocus);

  return {
    el: shell,
    main,
    setActive(key) {
      for (const a of sidebar.querySelectorAll('.side-link')) {
        a.setAttribute('aria-current', a.dataset.nav === key ? 'page' : 'false');
        if (a.dataset.nav !== key) a.removeAttribute('aria-current');
      }
    },
    destroy() {
      unsub();
      window.removeEventListener('focus', onFocus);
    },
  };
}

/**
 * Mounts the content of a page in its layout.
 * - `type`: `auth`, `app` or `bare`.
 * - `nav`: key of the active link.
 * - `full`: in the app, full-width content (terminal).
 */
export function mount(type, content, { nav, full = false, userId } = {}) {
  const app = root();
  if (type === 'app') {
    // The sidebar is reused if the user is the same.
    if (!current || current.type !== 'app' || current.userId !== userId) {
      if (current && current.destroy) current.destroy();
      const shell = appShell();
      current = { type: 'app', userId, ...shell };
      replace(app, shell.el);
    }
    current.setActive(nav);
    current.main.classList.toggle('app-content-full', full);
    replace(current.main, content);
  } else {
    if (current && current.destroy) current.destroy();
    current = { type };
    if (type === 'auth') {
      replace(app, authShell(content));
    } else {
      replace(app, content);
    }
  }
  // Focus the page title for screen readers (only when navigating, not on
  // the first load).
  if (mounted) {
    const title = app.querySelector('[data-page-title]');
    if (title) title.focus({ preventScroll: true });
  }
  mounted = true;
}

let mounted = false;

/** Forces the layout to be rebuilt next time (e.g. after switching user or language). */
export function resetLayout() {
  if (current && current.destroy) current.destroy();
  current = null;
  clear(root());
}
