// Translations of the web (see docs/I18N.md).
//
// Texts live in `web/locales/<lang>.json` (flat keys, `%{name}`
// placeholders, `_one`/`_other`... plural suffixes). English is the source
// and is always loaded as the fallback. The server lists the available files
// in `/assets/locales.json`, so adding a language only takes a new file.
//
// Language choice: the one saved in this browser → the signed-in account's
// `locale` → the browser languages → English.
//
// Call `t()` when rendering, never at module load time: changing the language
// re-renders the current page and module-level texts would not change.

const KEY = 'termoak.locale';
const SOURCE = 'en';

/** Available languages: `[{code, name}]` (from `/assets/locales.json`). */
let available = [{ code: SOURCE, name: 'English' }];
let lang = SOURCE;
let messages = {};
let fallback = {};
let pluralRules = new Intl.PluralRules(SOURCE);
let numberFmt = new Intl.NumberFormat(SOURCE);
const cache = new Map();
const listeners = new Set();

async function fetchJson(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json' }, credentials: 'omit' });
  if (!res.ok) throw new Error(`HTTP ${res.status} (${url})`);
  return res.json();
}

function loadMessages(code) {
  if (!cache.has(code)) {
    const p = fetchJson(`/assets/locales/${encodeURIComponent(code)}.json?v=${version()}`).catch((e) => {
      cache.delete(code);
      throw e;
    });
    cache.set(code, p);
  }
  return cache.get(code);
}

// Same `?v=` as the other assets, so a new release invalidates the cache.
function version() {
  const link = document.querySelector('link[rel="icon"]');
  const m = link && /[?&]v=([^&]+)/.exec(link.getAttribute('href') || '');
  return m ? m[1] : '';
}

/** Best available language for a BCP 47 tag (`es-ES` → `es`), or `null`. */
export function matchLanguage(tag) {
  if (!tag || typeof tag !== 'string') return null;
  const want = tag.toLowerCase();
  const codes = available.map((l) => l.code);
  const exact = codes.find((c) => c.toLowerCase() === want);
  if (exact) return exact;
  const base = want.split('-')[0];
  return codes.find((c) => c.toLowerCase() === base)
    || codes.find((c) => c.toLowerCase().split('-')[0] === base)
    || null;
}

/** Language saved in this browser (explicit choice), or `null`. */
export function savedLanguage() {
  try {
    return matchLanguage(localStorage.getItem(KEY));
  } catch {
    return null;
  }
}

function saveLanguage(code) {
  try {
    localStorage.setItem(KEY, code);
  } catch {
    /* no storage: the choice lasts until the tab is closed */
  }
}

/** Language from the browser preferences (or English). */
export function browserLanguage() {
  const list = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language];
  for (const tag of list) {
    const m = matchLanguage(tag);
    if (m) return m;
  }
  return SOURCE;
}

async function apply(code) {
  const [source, own] = await Promise.all([
    loadMessages(SOURCE).catch((e) => {
      console.warn('locale', SOURCE, e);
      return null;
    }),
    code === SOURCE ? null : loadMessages(code).catch((e) => {
      console.warn('locale', code, e);
      return null;
    }),
  ]);
  fallback = source || {};
  messages = own || fallback;
  lang = own || code === SOURCE ? code : SOURCE;
  pluralRules = new Intl.PluralRules(lang);
  numberFmt = new Intl.NumberFormat(lang);
  document.documentElement.lang = lang;
}

/**
 * Loads the list of languages and the starting language. `accountLocale` is
 * the signed-in account's `locale`, if already known.
 */
export async function initI18n(accountLocale = null) {
  try {
    const list = await fetchJson(`/assets/locales.json?v=${version()}`);
    if (Array.isArray(list) && list.length) available = list;
  } catch (e) {
    console.warn('locales', e);
  }
  const code = savedLanguage() || matchLanguage(accountLocale) || browserLanguage();
  await apply(code);
}

/** Current language code (`en`, `es`...). Also the locale for `Intl`. */
export function getLanguage() {
  return lang;
}

/** Languages a picker can offer: `[{code, name}]`. */
export function languages() {
  return available;
}

/**
 * Changes the language. `save`: remember it as an explicit choice (picker).
 * Listeners (see `onLanguageChange`) re-render the page and update the
 * account.
 */
export async function setLanguage(code, { save = true } = {}) {
  const target = matchLanguage(code) || SOURCE;
  if (save) saveLanguage(target);
  if (target === lang) return;
  await apply(target);
  for (const fn of [...listeners]) {
    try {
      fn(lang, { save });
    } catch (e) {
      console.warn('language listener', e);
    }
  }
}

/** Subscribes to language changes. Returns the unsubscribe function. */
export function onLanguageChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function lookup(key) {
  if (Object.prototype.hasOwnProperty.call(messages, key)) return messages[key];
  if (Object.prototype.hasOwnProperty.call(fallback, key)) return fallback[key];
  return undefined;
}

// Text for a key, choosing the plural form when `params.count` is a number.
function resolve(key, params) {
  if (params && typeof params.count === 'number') {
    const category = pluralRules.select(params.count);
    const own = messages[`${key}_${category}`] ?? messages[`${key}_other`];
    if (own !== undefined) return own;
    const en = fallback[`${key}_${new Intl.PluralRules(SOURCE).select(params.count)}`] ?? fallback[`${key}_other`];
    if (en !== undefined) return en;
  }
  return lookup(key);
}

function paramText(name, value) {
  if (name === 'count' && typeof value === 'number') return numberFmt.format(value);
  return String(value ?? '');
}

/** Is there a text for this key (in the current language or in English)? */
export function has(key) {
  return lookup(key) !== undefined || lookup(`${key}_other`) !== undefined;
}

/**
 * Translates a key. `%{name}` placeholders take `params.name`; with a
 * numeric `params.count`, the `key_one`/`key_other`... form is chosen with
 * `Intl.PluralRules` and `%{count}` is formatted for the language. Other
 * numbers are inserted as they are (format them first if needed). Missing
 * keys fall back to English and then to the key itself.
 */
export function t(key, params) {
  const text = resolve(key, params);
  if (text === undefined) return key;
  if (!params) return text;
  return text.replace(/%\{(\w+)\}/g, (m, name) => (name in params ? paramText(name, params[name]) : m));
}

/**
 * Like `t`, but parameters may be DOM nodes: returns a list of strings and
 * nodes to pass as children to `h()`.
 *
 *   h('p', null, tx('layout.verify.text', { email: h('strong', null, email) }))
 */
export function tx(key, params = {}) {
  const text = resolve(key, params) ?? key;
  const out = [];
  let last = 0;
  text.replace(/%\{(\w+)\}/g, (m, name, offset) => {
    if (offset > last) out.push(text.slice(last, offset));
    if (name in params) {
      const v = params[name];
      out.push(v instanceof Node ? v : paramText(name, v));
    } else {
      out.push(m);
    }
    last = offset + m.length;
    return m;
  });
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/**
 * Message of an error for the user: the translation of `error.<code>` if
 * there is one, else the (English) message from the server.
 */
export function errorText(err, fallbackKey = 'error.unexpected') {
  if (!err) return t(fallbackKey);
  if (typeof err === 'string') return err;
  if (err.code && has(`error.${err.code}`)) return t(`error.${err.code}`);
  return err.message || t(fallbackKey);
}
