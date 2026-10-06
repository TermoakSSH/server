// Notices of your sessions while you use the web app: the user events
// WebSocket (`/api/v1/events/ws`, see docs/WEBSOCKET-PROTOCOL.md) shows a
// toast when someone waits to enter one of your sessions, asks for its
// keyboard, a session waits for an answer, you get or lose the keyboard of a
// session shared with you, or someone shares a session with you.
//
// On the terminal page of that same session the terminal shows it already
// (banners and the keyboard bar), so no toast there. Started by app.js: it
// connects while there is a signed-in account and reconnects by itself.
//
// When this device is signed out from another one (`signed_out`, close code
// 4007), the next request finds the session lost and goes to sign in.

import { h } from './dom.js';
import { icon } from './icons.js';
import { freshAccessToken } from './api.js';
import { state, subscribe, isLoggedIn, loadMe } from './session.js';
import { toast } from './ui.js';
import { t } from './i18n.js';

let ws = null;
let userId = null;
let retryTimer = null;
let retries = 0;
let stopped = true;

const sessionPath = (id) => `/app/sessions/${id}`;
const watching = (id) => !!id && location.pathname === sessionPath(id);

function notice(text, sessionId, type = 'info', timeout = 12000) {
  const open = sessionId && !watching(sessionId)
    ? h('a', { class: 'btn btn-sm toast-action', href: sessionPath(sessionId) }, icon('terminal', { size: 14 }), t('notify.open'))
    : null;
  toast(h('span', { class: 'toast-notice' }, h('span', null, text), open ? ' ' : null, open), type, { timeout });
}

function onSessionNotice(n) {
  const id = n.session_id || (n.session && n.session.id);
  if (watching(id)) return;
  const who = (n.participant && n.participant.name) || t('notify.someone');
  const title = n.title || (n.session && n.session.title) || t('notify.a_session');
  switch (n.type) {
    case 'join_request':
      notice(t('notify.join_request', { name: who, title }), id, 'info', 20000);
      break;
    case 'control_request':
      notice(t('notify.control_request', { name: who, title }), id, 'info', 20000);
      break;
    case 'prompt_pending':
      notice(t('notify.prompt_pending', { host: (n.prompt && n.prompt.host) || title }), id, 'info', 20000);
      break;
    case 'control_granted':
      notice(t('notify.control_granted'), id, 'success');
      break;
    case 'control_revoked':
      notice(t('notify.control_revoked'), id, 'info');
      break;
    case 'session_shared':
      notice(n.team ? t('notify.shared_team', { name: n.by || who, title, team: n.team }) : t('notify.shared', { name: n.by || who, title }), id, 'info');
      break;
    default:
      break;
  }
}

// Close code of `signed_out`: this device was signed out.
const SIGNED_OUT = 4007;

/** This device was signed out on the server: check the session (a 401 sends to sign in). */
function signedOut() {
  disconnect();
  // A moment for this tab's own "sign out everywhere" to finish first.
  setTimeout(() => {
    if (!isLoggedIn()) return;
    loadMe().then(() => {
      // Still signed in after all: listen again.
      if (userId && !ws) {
        stopped = false;
        retry();
      }
    }).catch(() => {});
  }, 400);
}

function disconnect() {
  stopped = true;
  clearTimeout(retryTimer);
  if (ws) {
    const s = ws;
    ws = null;
    try {
      s.close();
    } catch {
      /* already closed */
    }
  }
}

async function connect() {
  if (stopped || ws) return;
  let token;
  try {
    token = await freshAccessToken();
  } catch {
    retry();
    return;
  }
  if (stopped || ws || !token) return;
  const base = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;
  const sock = new WebSocket(`${base}/api/v1/events/ws?access_token=${encodeURIComponent(token)}`);
  ws = sock;
  sock.onopen = () => {
    retries = 0;
  };
  sock.onmessage = (ev) => {
    if (typeof ev.data !== 'string') return;
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (msg.type === 'session' && msg.notice) onSessionNotice(msg.notice);
  };
  sock.onclose = (ev) => {
    if (ws !== sock) return;
    ws = null;
    if (ev.code === SIGNED_OUT) {
      signedOut();
      return;
    }
    retry();
  };
}

function retry() {
  if (stopped) return;
  clearTimeout(retryTimer);
  const delay = Math.min(2000 * 2 ** retries, 60_000);
  retries += 1;
  retryTimer = setTimeout(connect, delay);
}

/** Follows the signed-in account: connected while there is one. */
export function startNotices() {
  const sync = () => {
    const id = state.me && state.me.user && isLoggedIn() ? state.me.user.id : null;
    if (id === userId) return;
    disconnect();
    userId = id;
    if (id) {
      stopped = false;
      retries = 0;
      connect();
    }
  };
  subscribe(sync);
  sync();
}
