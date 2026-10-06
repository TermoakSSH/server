// Entry point of the Termoak web.
//
// A basic web app bundled with the server: sign in and sign up, sessions
// (with a terminal in the browser), teams and account settings.
//
// Loads the server information and the translations, starts the router and
// renders each page in its layout. Pages are loaded on demand (dynamic
// import) from js/pages/: the auth pages at the top level, the signed-in app
// in js/pages/app/.

import { h } from './js/dom.js';
import { api, onAuthLost } from './js/api.js';
import { state, loadInfo, loadMe, isLoggedIn, emit, subscribe, onExternalSignOut } from './js/session.js';
import { startRouter, navigate, safeNext, refresh } from './js/router.js';
import { mount, resetLayout } from './js/layout.js';
import { applyTheme } from './js/theme.js';
import { toast, loadingState, emptyState, capitalize } from './js/ui.js';
import { icon } from './js/icons.js';
import { t, errorText, initI18n, setLanguage, onLanguageChange, savedLanguage, matchLanguage, getLanguage } from './js/i18n.js';
import { startNotices } from './js/notify.js';

applyTheme();
// Notices of your sessions (join and keyboard requests...) on any page.
startNotices();

const page = (file, name = 'render') => ({ load: () => import(`./js/pages/${file}`), export: name });

// Redirect: `/` and `/app` go to the sessions (or to sign in, without a
// session).
const redirect = (to) => ({ load: async () => ({ render: () => navigate(to, { replace: true }) }) });

// Routes of the web. `layout`: auth | app | bare. `title`: key of the page
// title.
const ROUTES = [
  { path: '/', ...redirect('/app/sessions'), layout: 'auth', auth: true },
  { path: '/login', ...page('login.js'), layout: 'auth', title: 'title.login', guest: true },
  { path: '/signup', ...page('signup.js'), layout: 'auth', title: 'title.signup', guest: true },
  { path: '/forgot-password', ...page('password.js', 'forgot'), layout: 'auth', title: 'title.forgot_password' },
  { path: '/reset-password', ...page('password.js', 'reset'), layout: 'auth', title: 'title.reset_password' },
  { path: '/verify-email', ...page('email.js', 'verify'), layout: 'auth', title: 'title.verify_email' },
  { path: '/check-email', ...page('verify.js'), layout: 'auth', title: 'title.check_email' },
  { path: '/confirm-email', ...page('email.js', 'confirm'), layout: 'auth', title: 'title.confirm_email' },
  { path: '/invite/:token', ...page('invite.js'), layout: 'auth', title: 'title.invite' },
  { path: '/join/:token', ...page('join.js'), layout: 'bare', title: 'title.join' },
  { path: '/app', ...redirect('/app/sessions'), layout: 'app', auth: true },
  { path: '/app/sessions', ...page('app/sessions.js'), layout: 'app', nav: 'sessions', auth: true, title: 'title.sessions' },
  { path: '/app/sessions/:id', ...page('app/terminal.js'), layout: 'app', nav: 'sessions', auth: true, full: true, title: 'title.terminal' },
  { path: '/app/teams', ...page('app/teams.js'), layout: 'app', nav: 'teams', auth: true, title: 'title.teams' },
  { path: '/app/teams/:id', ...page('app/team.js'), layout: 'app', nav: 'teams', auth: true, title: 'title.team' },
  { path: '/app/vaults', ...page('app/vaults.js'), layout: 'app', nav: 'vaults', auth: true, title: 'title.vaults' },
  { path: '/app/vaults/:id', ...page('app/vault.js'), layout: 'app', nav: 'vaults', auth: true, title: 'title.vault' },
  { path: '/app/account/:tab?', ...page('app/account.js'), layout: 'app', nav: 'account', auth: true, title: 'title.account' },
  { path: '/app/*', load: async () => ({ render: notFound }), layout: 'app', auth: true, title: 'title.not_found' },
  { path: '*', load: async () => ({ render: notFound }), layout: 'auth', title: 'title.not_found' },
];

function notFound() {
  return h('div', { class: 'container' },
    emptyState({
      iconName: 'search',
      title: t('not_found.title'),
      text: t('not_found.text'),
      action: h('a', { class: 'btn btn-primary', href: isLoggedIn() ? '/app' : '/login' }, t('common.back_home')),
    }));
}

/** Sets the document title (an already translated text, or none for the default). */
function setTitle(title) {
  document.title = title ? t('title.format', { title }) : t('title.default');
}

// Description meta tags in the current language.
function setMeta() {
  for (const sel of ['meta[name="description"]', 'meta[property="og:description"]']) {
    const el = document.querySelector(sel);
    if (el) el.setAttribute('content', t('meta.description'));
  }
}

function loginRedirect(ctx) {
  const here = ctx.path + ctx.url.search;
  navigate(here === '/' || here === '/app' ? '/login' : `/login?next=${encodeURIComponent(here)}`, { replace: true });
}

async function renderRoute(ctx) {
  const r = ctx.route;
  // Pages only for signed-out visitors (login, sign-up).
  if (r.guest && isLoggedIn()) {
    navigate(safeNext(ctx.query.get('next')), { replace: true });
    return;
  }
  if (r.auth) {
    if (!isLoggedIn()) {
      loginRedirect(ctx);
      return;
    }
    if (!state.me) {
      try {
        await loadMe();
      } catch (e) {
        if (!isLoggedIn()) {
          loginRedirect(ctx);
          return;
        }
        throw e;
      }
    }
    if (!ctx.alive()) return;
  }
  setTitle(r.title ? t(r.title) : null);
  ctx.setTitle = setTitle;
  const opts = { nav: r.nav, full: r.full, userId: state.me ? state.me.user.id : null };
  const mod = await r.load();
  if (!ctx.alive()) return;
  const result = mod[r.export || 'render'](ctx);
  if (result instanceof Promise) {
    // If the page is slow, show an indicator in the meantime.
    const timer = setTimeout(() => {
      if (ctx.alive()) mount(r.layout, loadingState(), opts);
    }, 150);
    const content = await result.finally(() => clearTimeout(timer));
    if (!ctx.alive() || !content) return;
    mount(r.layout, content, opts);
  } else if (result) {
    mount(r.layout, result, opts);
  }
}

function renderError(err, ctx) {
  // Network failures (e.g. leaving the page in the middle of a request) are
  // already explained on screen.
  if (!(err && err.code === 'network')) console.error(err);
  const layout = ctx.route ? ctx.route.layout : 'auth';
  mount(layout === 'bare' ? 'auth' : layout, h('div', { class: 'container' },
    emptyState({
      iconName: 'alert',
      title: t('page_error.title'),
      text: capitalize(errorText(err)),
      action: h('button', { class: 'btn', type: 'button', onclick: () => location.reload() }, icon('refresh', { size: 15 }), t('common.reload')),
    })), { nav: ctx.route && ctx.route.nav, userId: state.me ? state.me.user.id : null });
}

// The session stopped being valid (refresh token expired or revoked).
onAuthLost(() => {
  const inApp = location.pathname.startsWith('/app');
  const here = location.pathname + location.search;
  state.me = null;
  if (inApp) {
    toast(t('error.session_expired'), 'error');
    resetLayout();
    navigate(`/login?next=${encodeURIComponent(here)}`, { replace: true });
  }
  emit();
});

// Signed out in another tab.
onExternalSignOut(() => {
  if (location.pathname.startsWith('/app')) {
    toast(t('app.signed_out_elsewhere'), 'info');
    resetLayout();
    navigate('/login', { replace: true });
  }
});

// Language changed (picker or account): re-render the page and, if it was
// the person's choice, save it in the account (used for emails).
let routerStarted = false;
onLanguageChange((lang, { save }) => {
  setMeta();
  if (save && isLoggedIn()) {
    api.patch('/me', { locale: lang })
      .then(() => {
        if (state.me && state.me.user) state.me.user.locale = lang;
      })
      .catch((e) => console.warn('locale', e));
  }
  if (routerStarted) {
    resetLayout();
    refresh();
  }
});

// Without an explicit choice in this browser, the account's language wins
// (e.g. after signing in).
subscribe(() => {
  const locale = state.me && state.me.user && state.me.user.locale;
  if (!locale || savedLanguage()) return;
  const lang = matchLanguage(locale);
  if (lang && lang !== getLanguage()) setLanguage(lang, { save: false }).catch(() => {});
});

async function boot() {
  const app = document.getElementById('app');
  // With a session, the account (and its language) is loaded at the same
  // time as the server information.
  const me = isLoggedIn() && !savedLanguage() ? loadMe().catch(() => null) : Promise.resolve(null);
  try {
    await Promise.all([
      me.then((account) => initI18n(account && account.user ? account.user.locale : null)),
      loadInfo(),
    ]);
  } catch (e) {
    await initI18n().catch(() => {});
    app.replaceChildren(h('div', { class: 'boot' },
      h('div', { class: 'stack center' },
        h('img', { src: '/assets/icon.svg', alt: '', width: 56, height: 56, class: 'boot-logo' }),
        h('p', null, t('boot.unreachable')),
        h('p', { class: 'muted small' }, capitalize(errorText(e))),
        h('div', null, h('button', { class: 'btn btn-primary', type: 'button', onclick: () => location.reload() }, t('common.retry'))))));
    return;
  }
  setMeta();
  routerStarted = true;
  startRouter(ROUTES, { render: renderRoute, error: renderError });
}

boot();
