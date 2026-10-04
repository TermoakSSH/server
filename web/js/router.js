// Router based on the History API.
//
// Each route declares its pattern (`/app/teams/:id`), how to load its page
// (dynamic import), the layout it uses and whether it requires a session.
// Internal links are intercepted so the page doesn't reload; since the
// server returns index.html on those routes, reloading works too.

let routes = [];
let hooks = {};
let renderSeq = 0;
let cleanups = [];

/** Turns `/app/teams/:id` into a regular expression with names. */
function compile(pattern) {
  const names = [];
  const re = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\/:(\w+)(\\\?)?/g, (_, name, optional) => {
      names.push(name);
      return optional ? '(?:/([^/]+))?' : '/([^/]+)';
    })
    .replace(/\*$/, '.*');
  return { regex: new RegExp(`^${re}/?$`), names };
}

/** Finds the route for a URL path. */
export function match(pathname) {
  for (const r of routes) {
    const m = r.compiled.regex.exec(pathname);
    if (m) {
      const params = {};
      r.compiled.names.forEach((n, i) => {
        if (m[i + 1] !== undefined) params[n] = decodeURIComponent(m[i + 1]);
      });
      return { route: r, params };
    }
  }
  return null;
}

/**
 * Validates a `?next=` target: same-origin paths only (never
 * `//other.domain`, `javascript:` or absolute URLs).
 */
export function safeNext(raw, fallback = '/app') {
  if (!raw || typeof raw !== 'string') return fallback;
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return fallback;
  try {
    const url = new URL(raw, location.origin);
    if (url.origin !== location.origin) return fallback;
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/assets/')) return fallback;
    return url.pathname + url.search + url.hash;
  } catch {
    return fallback;
  }
}

/** Navigates to another route of the web. */
export function navigate(to, { replace = false } = {}) {
  const url = new URL(to, location.origin);
  if (url.origin !== location.origin) {
    location.href = to;
    return;
  }
  const target = url.pathname + url.search + url.hash;
  if (replace) history.replaceState(null, '', target);
  else history.pushState(null, '', target);
  render();
}

/** Removes parameters from the current URL without reloading (e.g. `token`). */
export function stripQuery(...names) {
  const url = new URL(location.href);
  let changed = false;
  for (const n of names) {
    if (url.searchParams.has(n)) {
      url.searchParams.delete(n);
      changed = true;
    }
  }
  if (changed) history.replaceState(history.state, '', url.pathname + url.search + url.hash);
}

/** Renders the current route again. */
export function refresh() {
  render();
}

function runCleanups() {
  const list = cleanups;
  cleanups = [];
  for (const fn of list) {
    try {
      fn();
    } catch (e) {
      console.warn('page cleanup', e);
    }
  }
}

// Is this link handled by the router?
function isInternal(a) {
  if (!a || !a.href) return false;
  if (a.target && a.target !== '_self') return false;
  if (a.hasAttribute('download') || a.dataset.external !== undefined) return false;
  const url = new URL(a.href, location.href);
  if (url.origin !== location.origin) return false;
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/assets/') || url.pathname.startsWith('/updates/')) return false;
  // Link to an anchor on the same page: default behavior.
  if (url.pathname === location.pathname && url.search === location.search && url.hash) return false;
  return !!match(url.pathname);
}

async function render() {
  const seq = ++renderSeq;
  runCleanups();
  const url = new URL(location.href);
  const found = match(url.pathname) || match('*');
  const ctx = {
    path: url.pathname,
    url,
    query: url.searchParams,
    params: found ? found.params : {},
    route: found ? found.route : null,
    /** Is this still the visible page? (for late responses) */
    alive: () => seq === renderSeq,
    onCleanup: (fn) => cleanups.push(fn),
  };
  try {
    await hooks.render(ctx);
  } catch (e) {
    if (seq === renderSeq && hooks.error) hooks.error(e, ctx);
    else console.error(e);
  }
  if (seq !== renderSeq) return;
  // Anchor (`/#features`) or the top of the page.
  if (url.hash) {
    const el = document.getElementById(decodeURIComponent(url.hash.slice(1)));
    if (el) {
      el.scrollIntoView();
      return;
    }
  }
  window.scrollTo(0, 0);
}

/**
 * Starts the router.
 * - `table`: list of routes `{path, load, layout, auth, admin, nav, title}`.
 * - `render(ctx)`: renders the route (app.js does it with the right layout).
 * - `error(err, ctx)`: renders an error if loading the page fails.
 */
export function startRouter(table, callbacks) {
  routes = table.map((r) => ({ ...r, compiled: compile(r.path) }));
  hooks = callbacks;
  window.addEventListener('popstate', () => render());
  document.addEventListener('click', (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest('a');
    if (!isInternal(a)) return;
    e.preventDefault();
    const url = new URL(a.href, location.href);
    const same = url.pathname + url.search === location.pathname + location.search && !url.hash;
    navigate(url.pathname + url.search + url.hash, { replace: same });
  });
  render();
}
