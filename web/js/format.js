// Formatting in the current language: dates, durations, roles, permissions,
// session states, platforms and the name of this device.

import { t, has, getLanguage } from './i18n.js';

// Intl formatters, rebuilt when the language changes.
const formatters = new Map();
function formatter(kind, make) {
  const key = `${kind}|${getLanguage()}`;
  if (!formatters.has(key)) formatters.set(key, make(getLanguage()));
  return formatters.get(key);
}
const rtf = () => formatter('rel', (l) => new Intl.RelativeTimeFormat(l, { numeric: 'auto' }));
const dtf = () => formatter('datetime', (l) => new Intl.DateTimeFormat(l, { dateStyle: 'medium', timeStyle: 'short' }));

const UNITS = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];

/** "5 minutes ago", "yesterday", "in 3 days"... (`ms` in milliseconds). */
export function relTime(ms) {
  if (ms === null || ms === undefined || !Number.isFinite(Number(ms))) return '—';
  const diff = (Number(ms) - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return diff <= 0 ? t('time.just_now') : t('time.in_a_moment');
  for (const [unit, secs] of UNITS) {
    if (abs >= secs || unit === 'minute') {
      return rtf().format(Math.round(diff / secs), unit);
    }
  }
  return '—';
}

/** Full date and time. */
export function absTime(ms) {
  if (!ms) return '—';
  return dtf().format(new Date(Number(ms)));
}

/** Readable duration between two instants. */
export function duration(fromMs, toMs = Date.now()) {
  const secs = Math.max(0, Math.round((toMs - fromMs) / 1000));
  if (secs < 60) return t('duration.seconds', { s: secs });
  const mins = Math.floor(secs / 60);
  if (mins < 60) return t('duration.minutes', { m: mins });
  const hours = Math.floor(mins / 60);
  if (hours < 24) return t('duration.hours', { h: hours, m: mins % 60 });
  const days = Math.floor(hours / 24);
  return t('duration.days', { d: days, h: hours % 24 });
}

export const ROLE_RANK = { member: 1, admin: 2, owner: 3 };

/** Team role: owner, admin or member. */
export function roleLabel(role) {
  if (role && has(`role.${role}`)) return t(`role.${role}`);
  return role || '—';
}

/** Permission on a shared session: view, control or owner. */
export function permissionLabel(p) {
  return p && has(`permission.${p}`) ? t(`permission.${p}`) : p;
}

/** State of a server session (`state` of SessionView or `status` of SessionInfo). */
export function sessionStateInfo(state) {
  const key = typeof state === 'string' ? state : state && state.state;
  const kinds = { running: 'accent', connecting: 'info', host_offline: 'warn', failed: 'danger', closed: '' };
  if (key && key in kinds) {
    return { label: t(`session_state.${key}`), kind: kinds[key], live: key === 'running' };
  }
  return { label: key || t('session_state.unknown'), kind: '' };
}

/** Readable name of a device platform. */
export function platformLabel(p) {
  const names = {
    'desktop-windows': 'Windows',
    'desktop-macos': 'macOS',
    'desktop-linux': 'Linux',
    ios: 'iOS',
    android: 'Android',
  };
  if (names[p]) return names[p];
  if (p === 'web') return t('platform.web');
  if (p === 'cli') return t('platform.cli');
  return p || t('platform.unknown');
}

/** Icon of a device platform. */
export function platformIcon(p) {
  if (!p) return 'monitor';
  if (p === 'web') return 'globe';
  if (p === 'ios' || p === 'android') return 'phone';
  if (p === 'cli') return 'terminal';
  return 'laptop';
}

/** Visitor's operating system: `windows`, `macos`, `linux`, `ios`, `android` or `other`. */
export function detectOS() {
  const uaData = navigator.userAgentData;
  const platform = ((uaData && uaData.platform) || navigator.platform || '').toLowerCase();
  const ua = (navigator.userAgent || '').toLowerCase();
  if (/android/.test(ua)) return 'android';
  if (/iphone|ipad|ipod/.test(ua) || (platform === 'macintel' && navigator.maxTouchPoints > 1)) return 'ios';
  if (platform.startsWith('win') || /windows/.test(ua)) return 'windows';
  if (platform.startsWith('mac') || /mac os x/.test(ua)) return 'macos';
  if (platform.includes('linux') || /linux|x11/.test(ua)) return 'linux';
  return 'other';
}

const OS_NAMES = { windows: 'Windows', macos: 'macOS', linux: 'Linux', ios: 'iOS', android: 'Android' };

/** Name of this device for the server ("Web · Chrome on macOS"). */
export function deviceName() {
  const ua = navigator.userAgent || '';
  let browser = t('platform.web');
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/OPR\//.test(ua)) browser = 'Opera';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Chrome\//.test(ua) || /Chromium\//.test(ua)) browser = 'Chrome';
  else if (/Safari\//.test(ua)) browser = 'Safari';
  const os = OS_NAMES[detectOS()] || 'web';
  return t('device.web_name', { browser, os });
}

/** Initials for the avatar. */
export function initials(name, email) {
  const base = (name || '').trim() || (email || '').split('@')[0] || '?';
  const parts = base.split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return base.slice(0, 2).toUpperCase();
}

/** Stable hue (1-6) from a text, to color avatars. */
export function hue(text) {
  let n = 0;
  for (const ch of String(text || '')) n = (n * 31 + ch.codePointAt(0)) >>> 0;
  return (n % 6) + 1;
}

/** Shortens a long id for display ("3f2a…"). */
export function shortId(id) {
  const s = String(id || '');
  return s.length > 12 ? `${s.slice(0, 8)}…` : s;
}
