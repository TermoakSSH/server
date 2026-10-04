// API client (`/api/v1`): tokens, automatic refresh and errors.
//
// Tokens are kept in localStorage (access, refresh and expirations). The
// access token is refreshed shortly before it expires and, if a 401 still
// arrives, it is refreshed once and the request is repeated. If the refresh
// fails, the session is considered lost and `onAuthLost` is notified.
//
// Error messages here are English; the UI shows the translation of
// `error.<code>` when there is one (see `errorText` in i18n.js).

const BASE = '/api/v1';
const KEY = 'termoak.auth';
// Margin to refresh the access token before it expires.
const REFRESH_MARGIN_MS = 30_000;

/** API error with the format `{"error": {"code", "message"}}`. */
export class ApiError extends Error {
  constructor(status, code, message, data = null) {
    super(message || 'Unexpected error.');
    this.name = 'ApiError';
    this.status = status;
    this.code = code || 'error';
    this.data = data;
  }
}

// --- Token storage -----------------------------------------------------------

// In-memory copy in case localStorage is not available.
let memory = null;

function readStore() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return memory;
  }
}

export const tokens = {
  /** Current tokens or `null`. */
  get() {
    const t = readStore();
    return t && t.access_token && t.refresh_token ? t : null;
  },
  /** Saves a token pair (login, registration or refresh response). */
  set(pair) {
    const value = {
      access_token: pair.access_token,
      refresh_token: pair.refresh_token,
      access_expires_at: pair.access_expires_at || 0,
      refresh_expires_at: pair.refresh_expires_at || 0,
      device_id: pair.device_id || null,
    };
    memory = value;
    try {
      localStorage.setItem(KEY, JSON.stringify(value));
    } catch {
      // No storage (strict private mode): the session lasts as long as the tab.
    }
  },
  clear() {
    memory = null;
    try {
      localStorage.removeItem(KEY);
    } catch {
      /* nothing to do */
    }
  },
  key: KEY,
};

// --- Lost session notification -------------------------------------------------

let authLostHandler = null;

/** Registers the function called when the session stops being valid. */
export function onAuthLost(fn) {
  authLostHandler = fn;
}

function authLost() {
  tokens.clear();
  if (authLostHandler) authLostHandler();
}

function sessionExpired() {
  return new ApiError(401, 'session_expired', 'Your session has expired. Please sign in again.');
}

// --- Refresh -------------------------------------------------------------

let refreshing = null;

async function doRefresh(usedAccess) {
  const current = tokens.get();
  if (!current) throw sessionExpired();
  // Another tab already refreshed it: use its tokens.
  if (usedAccess && current.access_token !== usedAccess && current.access_expires_at - Date.now() > REFRESH_MARGIN_MS) {
    return current;
  }
  let res;
  try {
    res = await fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ refresh_token: current.refresh_token }),
      credentials: 'omit',
    });
  } catch {
    throw new ApiError(0, 'network', 'Could not connect to the server. Check your connection.');
  }
  if (!res.ok) {
    // Another tab may have rotated the refresh token at the same time.
    const again = tokens.get();
    if (again && again.refresh_token !== current.refresh_token) return again;
    if (res.status >= 500) {
      throw new ApiError(res.status, 'server', 'The server is not responding. Try again in a moment.');
    }
    authLost();
    throw sessionExpired();
  }
  const pair = await res.json();
  tokens.set(pair);
  return tokens.get();
}

/** Refreshes the tokens (only once even if several requests ask for it). */
export function refreshTokens(usedAccess) {
  if (!refreshing) {
    const run = () => doRefresh(usedAccess);
    // With Web Locks, tabs take turns so they don't spend the same token.
    const task = navigator.locks && navigator.locks.request
      ? navigator.locks.request('termoak-refresh', run)
      : run();
    refreshing = Promise.resolve(task).finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

/** Returns a valid access token (refreshing it if needed). */
export async function freshAccessToken() {
  const t = tokens.get();
  if (!t) throw sessionExpired();
  if (t.access_expires_at && t.access_expires_at - Date.now() < REFRESH_MARGIN_MS) {
    const n = await refreshTokens(t.access_token);
    return n.access_token;
  }
  return t.access_token;
}

// --- Requests -------------------------------------------------------------

function buildUrl(path, query) {
  let url = path.startsWith('/api/') ? path : `${BASE}${path}`;
  if (query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
    }
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  }
  return url;
}

async function parse(res) {
  const type = res.headers.get('content-type') || '';
  let data = null;
  if (type.includes('application/json')) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  }
  if (res.ok) return data;
  const err = data && data.error;
  if (err && err.message) throw new ApiError(res.status, err.code, err.message, data);
  const fallback = {
    404: 'Not found.',
    413: 'The request is too large.',
    429: 'Too many requests; wait a moment.',
    502: 'The server is not available right now.',
    503: 'The server is not available right now.',
  };
  throw new ApiError(res.status, 'http_' + res.status, fallback[res.status] || `Server error (${res.status}).`, data);
}

/**
 * Makes an API request.
 *
 * Options:
 * - `body`: object sent as JSON.
 * - `query`: URL parameters.
 * - `auth` (default `true`): sends the access token.
 * - `credential`: on this route a 401 means "wrong password or code" (not an
 *   expired session), so it neither refreshes nor signs out because of it.
 */
export async function request(method, path, opts = {}) {
  const { body, query, auth = true, credential = false } = opts;
  const url = buildUrl(path, query);
  let t = auth ? tokens.get() : null;
  if (auth && !t) throw sessionExpired();

  if (t && t.access_expires_at && t.access_expires_at - Date.now() < REFRESH_MARGIN_MS) {
    try {
      t = await refreshTokens(t.access_token);
    } catch (e) {
      if (e.code === 'session_expired') throw e;
      // Network error: try anyway with the current token.
    }
  }

  const send = async (tok) => {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (tok) headers.Authorization = `Bearer ${tok.access_token}`;
    try {
      return await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: 'omit',
      });
    } catch {
      throw new ApiError(0, 'network', 'Could not connect to the server. Check your connection.');
    }
  };

  let res = await send(t);
  if (res.status === 401 && t) {
    // On password routes, a 401 is a form error, unless the message is about
    // the token.
    let tokenProblem = !credential;
    if (credential) {
      const copy = res.clone();
      try {
        const data = await copy.json();
        tokenProblem = /token/i.test((data && data.error && data.error.message) || '');
      } catch {
        tokenProblem = false;
      }
    }
    if (tokenProblem) {
      t = await refreshTokens(t.access_token);
      res = await send(t);
      if (res.status === 401 && !credential) {
        authLost();
        throw sessionExpired();
      }
    }
  }
  return parse(res);
}

export const api = {
  get: (path, opts) => request('GET', path, opts),
  post: (path, body, opts = {}) => request('POST', path, { ...opts, body: body === undefined ? {} : body }),
  patch: (path, body, opts = {}) => request('PATCH', path, { ...opts, body }),
  put: (path, body, opts = {}) => request('PUT', path, { ...opts, body }),
  del: (path, body, opts = {}) => request('DELETE', path, { ...opts, body }),
  /** Public request (without token). */
  public: (method, path, body) => request(method, path, { auth: false, body }),
};

/**
 * Downloads an authenticated resource as a Blob (for example, a recording).
 * Returns `{blob, filename}`.
 */
export async function fetchBlob(path) {
  const token = await freshAccessToken();
  let res;
  try {
    res = await fetch(buildUrl(path), { headers: { Authorization: `Bearer ${token}` }, credentials: 'omit' });
  } catch {
    throw new ApiError(0, 'network', 'Could not connect to the server.');
  }
  if (!res.ok) await parse(res);
  const disposition = res.headers.get('content-disposition') || '';
  const m = /filename="?([^";]+)"?/i.exec(disposition);
  return { blob: await res.blob(), filename: m ? m[1] : 'download' };
}
