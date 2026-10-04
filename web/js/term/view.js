// Web terminal: connects to the WebSocket of a server session and draws it
// with xterm.js. Follows docs/WEBSOCKET-PROTOCOL.md:
//
// - Server → client: `hello`, a binary snapshot of the scrollback and then
//   the live output; JSON messages for state, presence, size, title,
//   prompts (owner only), `resync` and errors.
// - Client → server: keystrokes as binary (only with write permission) and
//   JSON (`resize`, `prompt_answer`, `ping`).
//
// The terminal size is the session's (everyone shares it); whoever can write
// has a button to fit it to their window.

import './csp-shim.js';
import { Terminal } from '../../vendor/xterm/xterm.mjs';
import { FitAddon } from '../../vendor/xterm/addon-fit.mjs';
import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api, freshAccessToken } from '../api.js';
import { permissionLabel } from '../format.js';
import { badge, avatar, toast, confirmDialog, openDialog, field, capitalize } from '../ui.js';
import { t, errorText } from '../i18n.js';
import { stateBadge } from '../pages/app/shared.js';

// xterm stylesheet (loaded once).
if (!document.querySelector('link[data-xterm]')) {
  document.head.appendChild(h('link', { rel: 'stylesheet', href: '/assets/vendor/xterm/xterm.css', dataset: { xterm: '' } }));
}

const THEME = {
  background: '#0a0e0b',
  foreground: '#d7e3d1',
  cursor: '#9fd36b',
  cursorAccent: '#0a0e0b',
  selectionBackground: 'rgba(159, 211, 107, 0.32)',
  black: '#1b221c',
  red: '#f07878',
  green: '#9fd36b',
  yellow: '#e7c15a',
  blue: '#7cb7f5',
  magenta: '#d49cf0',
  cyan: '#6fd6cf',
  white: '#d7e3d1',
  brightBlack: '#65725f',
  brightRed: '#ff9a9a',
  brightGreen: '#bfe597',
  brightYellow: '#f3d98a',
  brightBlue: '#a4cdf8',
  brightMagenta: '#e4bdf6',
  brightCyan: '#9ae6e0',
  brightWhite: '#f2f7ee',
};

const MAX_RETRIES = 6;

/**
 * Mounts the terminal view. Options:
 * - `sessionId`: your own session or one shared with you (uses your token).
 * - `wsPath`: WebSocket path of a link (`/join`), without an account.
 * - `title`, `subtitle`: header texts.
 * - `back`: `{label, href}` or `{label, onClick}`.
 * - `onCleanup(fn)`: registers the cleanup when leaving the page.
 * - `onTitle(title)`: called when the session title is known.
 */
export function mountTerminal(opts) {
  const encoder = new TextEncoder();
  let ws = null;
  let term = null;
  let fit = null;
  let access = null;
  let session = null;
  let expectSnapshot = true;
  let finished = false;
  let retries = 0;
  let retryTimer = null;
  let pingTimer = null;
  let promptDlg = null;
  let promptId = null;
  let disposed = false;

  // --- Structure --------------------------------------------------------------
  const titleEl = h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, opts.title || t('terminal.title'));
  const stateSlot = h('span');
  const accessSlot = h('span');
  const viewersSlot = h('span', { class: 'row small muted' });
  const fitBtn = h('button', { class: 'btn btn-sm', type: 'button', hidden: true, title: t('terminal.fit_title'), 'aria-label': t('terminal.fit_aria') }, icon('resize', { size: 15 }), h('span', { class: 'label-long', 'aria-hidden': 'true' }, t('terminal.fit')));
  const fullBtn = h('button', { class: 'btn btn-sm btn-icon', type: 'button', 'aria-label': t('terminal.fullscreen'), title: t('terminal.fullscreen') }, icon('maximize', { size: 15 }));
  const closeBtn = h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button', hidden: true, 'aria-label': t('terminal.close_session'), title: t('terminal.close_session') }, icon('power', { size: 15 }), h('span', { class: 'label-long', 'aria-hidden': 'true' }, t('terminal.close_session_short')));
  const back = opts.back
    ? (opts.back.href
      ? h('a', { class: 'btn btn-sm btn-ghost', href: opts.back.href }, icon('arrow-left', { size: 15 }), opts.back.label)
      : h('button', { class: 'btn btn-sm btn-ghost', type: 'button', onclick: () => { cleanup(); opts.back.onClick(); } }, icon('arrow-left', { size: 15 }), opts.back.label))
    : null;
  const host = h('div', { class: 'term-host' });
  const overlay = h('div', { class: 'term-overlay', role: 'status' });
  const stage = h('div', { class: 'term-stage' }, host, overlay);
  const note = h('div', { class: 'term-note' });
  const root = h('div', { class: 'term-page' },
    h('div', { class: 'term-head' },
      back,
      h('div', { class: 'stack-sm grow' },
        titleEl,
        h('div', { class: 'term-head-meta' }, stateSlot, accessSlot, opts.subtitle ? h('span', { class: 'small muted' }, opts.subtitle) : null, viewersSlot)),
      h('div', { class: 'term-head-actions' }, fitBtn, fullBtn, closeBtn)),
    stage,
    note);

  const showOverlay = (iconName, title, text, actions = []) => {
    replace(overlay, h('div', { class: 'stack' },
      iconName === 'spinner' ? h('span', { class: 'spinner', 'aria-hidden': 'true' }) : icon(iconName, { size: 30 }),
      h('strong', null, title),
      text ? h('p', { class: 'small' }, text) : null,
      actions.length ? h('div', { class: 'row-wrap' }, actions) : null));
    overlay.hidden = false;
  };
  const hideOverlay = () => {
    overlay.hidden = true;
  };

  const canWrite = () => access === 'owner' || access === 'control';

  const updateHeader = () => {
    if (session) {
      titleEl.textContent = session.title;
      if (opts.onTitle && session.title) opts.onTitle(session.title);
      replace(stateSlot, stateBadge(session.state));
      const viewers = session.viewers || [];
      replace(viewersSlot, viewers.length
        ? [h('span', { class: 'avatar-stack', title: viewers.map((v) => v.name).join(', ') }, viewers.slice(0, 5).map((v) => avatar(v.name, v.user_id || v.id, 'sm'))), t('terminal.viewers', { count: viewers.length })]
        : null);
    }
    if (access) {
      replace(accessSlot, access === 'owner' ? badge(permissionLabel('owner'), 'accent', 'crown') : badge(permissionLabel(access), access === 'control' ? 'warn' : 'info', access === 'control' ? 'keyboard' : 'eye'));
      fitBtn.hidden = !canWrite();
      closeBtn.hidden = access !== 'owner' || !opts.sessionId;
      replace(note, canWrite()
        ? [icon('keyboard', { size: 15 }), access === 'owner'
          ? t('terminal.note.owner')
          : t('terminal.note.control')]
        : [icon('eye', { size: 15 }), t('terminal.note.view')]);
      if (term) term.options.disableStdin = !canWrite();
    }
  };

  // --- Authentication prompts (owner only) ------------------------------
  const closePrompt = () => {
    if (promptDlg) promptDlg.close('done');
    promptDlg = null;
    promptId = null;
  };

  const answer = (payload) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'prompt_answer', prompt_id: promptId, ...payload }));
    closePrompt();
  };

  const showPrompt = (p) => {
    closePrompt();
    promptId = p.prompt_id;
    if (p.kind === 'hostkey') {
      const accept = h('button', { class: 'btn btn-primary', type: 'button', onclick: () => answer({ accept: true }) }, t('terminal.hostkey.accept'));
      const reject = h('button', { class: 'btn', type: 'button', onclick: () => answer({ accept: false }) }, t('terminal.hostkey.reject'));
      promptDlg = openDialog({
        title: t('terminal.hostkey.title', { host: p.host }),
        description: t('terminal.hostkey.description'),
        iconName: 'key',
        body: [
          p.message ? h('p', null, capitalize(p.message)) : null,
          p.fingerprint ? h('div', { class: 'secret-box' }, `${p.key_type ? `${p.key_type} ` : ''}${p.fingerprint}`) : null,
          h('p', { class: 'small muted' }, t('terminal.hostkey.compare')),
        ],
        actions: [reject, accept],
      });
      return;
    }
    const inputs = (p.prompts && p.prompts.length ? p.prompts : [{ text: p.kind === 'passphrase' ? t('terminal.prompt.passphrase') : t('common.password'), echo: false }])
      .map((q) => field({ label: q.text || t('terminal.prompt.answer'), type: q.echo ? 'text' : 'password', autocomplete: 'off', reveal: false }));
    const form = h('form');
    const send = h('button', { class: 'btn btn-primary', type: 'submit' }, t('common.send'));
    const cancel = h('button', { class: 'btn', type: 'button', onclick: () => answer({ answers: null, accept: false }) }, t('common.cancel'));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      answer({ answers: inputs.map((f) => f.input.value) });
    });
    promptDlg = openDialog({
      title: p.kind === 'passphrase' ? t('terminal.prompt.passphrase_title') : t('terminal.prompt.auth_title', { host: p.host }),
      description: p.message ? capitalize(p.message) : t('terminal.prompt.description'),
      iconName: 'lock',
      body: inputs,
      actions: [cancel, send],
      form,
    });
  };

  // --- Server messages ------------------------------------------------------------
  const setState = (st) => {
    if (!session) session = {};
    session.state = st;
    updateHeader();
    const s = st && st.state;
    if (s === 'connecting') {
      showOverlay('spinner', t('terminal.overlay.connecting_host'), st.message ? capitalize(st.message) : null);
    } else if (s === 'host_offline') {
      showOverlay('wifi-off', t('terminal.overlay.host_offline'), t('terminal.overlay.host_offline_text'));
    } else if (s === 'closed') {
      finished = true;
      const reason = st.reason ? capitalize(st.reason) : null;
      showOverlay('power', t('terminal.overlay.ended'), [reason, st.exit_code != null ? t('terminal.overlay.exit_code', { code: st.exit_code }) : null].filter(Boolean).join(' ') || null,
        opts.sessionId ? [h('a', { class: 'btn btn-sm', href: '/app/sessions' }, t('terminal.back_to_sessions'))] : []);
    } else {
      hideOverlay();
    }
  };

  const onJson = (msg) => {
    switch (msg.type) {
      case 'hello':
        session = msg.session;
        access = msg.you && msg.you.access;
        if (term && session.cols && session.rows) term.resize(session.cols, session.rows);
        setState(session.state);
        retries = 0;
        break;
      case 'status':
        setState(msg.status);
        break;
      case 'presence':
        if (session) session.viewers = msg.viewers;
        updateHeader();
        break;
      case 'resize':
        if (term && msg.cols && msg.rows) term.resize(msg.cols, msg.rows);
        break;
      case 'title':
        if (session) session.title = msg.title;
        updateHeader();
        break;
      case 'prompt':
        showPrompt(msg);
        break;
      case 'prompt_done':
        if (msg.prompt_id === promptId) closePrompt();
        break;
      case 'resync':
        expectSnapshot = true;
        break;
      case 'error':
        toast(capitalize(msg.message || t('terminal.error.session')), 'error');
        if (/revok|no longer have access|revocad|ya no tienes acceso/i.test(msg.message || '')) {
          finished = true;
          showOverlay('lock', t('terminal.overlay.no_access'), capitalize(msg.message));
        }
        break;
      default:
        break;
    }
  };

  // --- Connection ---------------------------------------------------------------
  const wsUrl = async () => {
    const base = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;
    if (opts.wsPath) return base + opts.wsPath;
    const token = await freshAccessToken();
    return `${base}/api/v1/sessions/${encodeURIComponent(opts.sessionId)}/ws?access_token=${encodeURIComponent(token)}`;
  };

  // After an unexpected close: does the session still exist?
  const stillThere = async () => {
    try {
      if (opts.wsPath) {
        const token = opts.wsPath.split('share_token=')[1];
        if (token) await api.get(`/join/${token}`, { auth: false });
      } else {
        await api.get(`/sessions/${encodeURIComponent(opts.sessionId)}`);
      }
      return true;
    } catch (e) {
      return e.status === 0 ? true : e;
    }
  };

  const scheduleRetry = async () => {
    if (disposed || finished) return;
    const check = await stillThere();
    if (disposed) return;
    if (check !== true) {
      finished = true;
      showOverlay('power', t('terminal.overlay.unavailable'), capitalize(errorText(check)),
        opts.sessionId ? [h('a', { class: 'btn btn-sm', href: '/app/sessions' }, t('terminal.back_to_sessions'))] : []);
      return;
    }
    if (retries >= MAX_RETRIES) {
      showOverlay('wifi-off', t('terminal.overlay.disconnected'), t('terminal.overlay.disconnected_text'),
        [h('button', { class: 'btn btn-sm btn-primary', type: 'button', onclick: () => { retries = 0; connect(); } }, icon('refresh', { size: 15 }), t('terminal.reconnect'))]);
      return;
    }
    const delay = Math.min(1000 * 2 ** retries, 15000);
    retries += 1;
    showOverlay('spinner', t('terminal.overlay.reconnecting'), t('terminal.overlay.still_alive'));
    retryTimer = setTimeout(connect, delay);
  };

  async function connect() {
    if (disposed) return;
    clearTimeout(retryTimer);
    let url;
    try {
      url = await wsUrl();
    } catch (e) {
      showOverlay('lock', t('terminal.overlay.expired'), capitalize(errorText(e)));
      return;
    }
    if (disposed) return;
    expectSnapshot = true;
    const sock = new WebSocket(url);
    ws = sock;
    sock.binaryType = 'arraybuffer';
    sock.onopen = () => {
      clearInterval(pingTimer);
      pingTimer = setInterval(() => {
        if (sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify({ type: 'ping' }));
      }, 25_000);
    };
    sock.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        try {
          onJson(JSON.parse(ev.data));
        } catch (e) {
          console.warn('invalid terminal message', e);
        }
        return;
      }
      if (!term) return;
      if (expectSnapshot) {
        term.reset();
        expectSnapshot = false;
      }
      term.write(new Uint8Array(ev.data));
    };
    sock.onclose = () => {
      clearInterval(pingTimer);
      if (ws !== sock) return;
      ws = null;
      if (!disposed && !finished) scheduleRetry();
    };
  }

  // --- xterm -------------------------------------------------------------------------
  const start = () => {
    term = new Terminal({
      fontFamily: 'ui-monospace, "SF Mono", "Cascadia Code", "JetBrains Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: window.matchMedia('(max-width: 640px)').matches ? 12 : 14,
      lineHeight: 1.12,
      cursorBlink: true,
      scrollback: 5000,
      theme: THEME,
      disableStdin: true,
      convertEol: false,
      allowProposedApi: false,
    });
    fit = new FitAddon();
    term.loadAddon(fit);
    // xterm DOM renderer (works with any pixel density and without a GPU;
    // csp-shim.js makes it possible under the CSP).
    term.open(host);
    term.onData((data) => {
      if (canWrite() && ws && ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(data));
    });
    term.onBinary((data) => {
      if (!canWrite() || !ws || ws.readyState !== WebSocket.OPEN) return;
      const bytes = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i += 1) bytes[i] = data.charCodeAt(i) & 0xff;
      ws.send(bytes);
    });
    stage.addEventListener('click', () => term.focus());
    showOverlay('spinner', t('terminal.overlay.connecting'), null);
    connect();
    term.focus();
  };

  fitBtn.addEventListener('click', () => {
    if (!term || !ws || ws.readyState !== WebSocket.OPEN) return;
    // The available space is the stage's (the terminal may be wider and
    // overflow it): computed with the real size of a cell.
    const screen = term.element && term.element.querySelector('.xterm-screen');
    let dims = null;
    if (screen && screen.clientWidth && screen.clientHeight) {
      const cw = screen.clientWidth / term.cols;
      const ch = screen.clientHeight / term.rows;
      dims = {
        cols: Math.max(20, Math.floor((stage.clientWidth - 24 - 14) / cw)),
        rows: Math.max(6, Math.floor((stage.clientHeight - 24) / ch)),
      };
    } else if (fit) {
      dims = fit.proposeDimensions();
    }
    if (!dims) return;
    ws.send(JSON.stringify({ type: 'resize', cols: dims.cols, rows: dims.rows }));
  });
  fullBtn.addEventListener('click', () => {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (stage.requestFullscreen) stage.requestFullscreen().catch(() => {});
  });
  closeBtn.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: t('terminal.close_session'),
      message: t('terminal.close_confirm'),
      confirmLabel: t('terminal.close_session'),
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/sessions/${encodeURIComponent(opts.sessionId)}`);
      toast(t('terminal.closed_toast'), 'success');
    } catch (e) {
      toast(capitalize(errorText(e)), 'error');
    }
  });

  function cleanup() {
    if (disposed) return;
    disposed = true;
    clearTimeout(retryTimer);
    clearInterval(pingTimer);
    closePrompt();
    if (ws) {
      const s = ws;
      ws = null;
      try {
        s.close();
      } catch {
        /* already closed */
      }
    }
    if (term) term.dispose();
    term = null;
  }
  if (opts.onCleanup) opts.onCleanup(cleanup);

  // xterm needs the container in the document to measure it.
  requestAnimationFrame(() => {
    if (!disposed) start();
  });
  return root;
}
