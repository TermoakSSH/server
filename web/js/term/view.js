// Web terminal: connects to the WebSocket of a server session and draws it
// with xterm.js. Speaks protocol 2 of docs/WEBSOCKET-PROTOCOL.md:
//
// - Server → client: `waiting` (waiting room), `hello`, a binary snapshot of
//   the scrollback and then the live output; JSON messages for state,
//   participants, the keyboard (`control`), size, title, prompts and
//   requests (owner only), `resync` and errors with a stable `code`.
// - Client → server: keystrokes as binary (only while `can_write`) and JSON
//   (`resize`, `prompt_answer`, `ping`, `control_request`/`control_release`
//   and, for the owner, `join_allow`/`join_deny`, `control_grant`/
//   `control_deny`/`control_take`, `kick` and `stop_sharing`).
//
// One person drives at a time: the owner always can, everyone else watches
// until the owner hands them the keyboard, for good or for a while (timed
// grants: `control_grant` with `minutes`, `until` in `control`,
// `control_expired` when the time is up). The terminal size is the
// session's (everyone shares it); whoever can write has a button to fit it to
// their window.

import './csp-shim.js';
import { Terminal } from '../../vendor/xterm/xterm.mjs';
import { FitAddon } from '../../vendor/xterm/addon-fit.mjs';
import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api, freshAccessToken } from '../api.js';
import { permissionLabel, relTime, absTime } from '../format.js';
import { badge, avatar, toast, confirmDialog, openDialog, field, capitalize } from '../ui.js';
import { t, errorText } from '../i18n.js';
import { stateBadge } from '../pages/app/shared.js';
import { guestKey } from './guest.js';

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

// Codes that send a socket away for good (`error.code` and close code).
const END_CODES = {
  revoked: 4001,
  kicked: 4002,
  expired: 4003,
  session_ended: 4004,
  join_denied: 4005,
  forbidden: 4006,
  signed_out: 4007,
};
const END_BY_CLOSE = Object.fromEntries(Object.entries(END_CODES).map(([k, v]) => [v, k]));

// How long the owner can hand the keyboard over (minutes; `null`: until they
// take it back). The server accepts 1 to 240.
const GRANT_MINUTES = [null, 5, 15, 30, 60];

/** "4:59" or "1:02:03": time left until `until` (ms). */
function clock(until) {
  const secs = Math.max(0, Math.ceil((until - Date.now()) / 1000));
  const hours = Math.floor(secs / 3600);
  const pad = (n) => String(n).padStart(2, '0');
  const mins = Math.floor((secs % 3600) / 60);
  return hours ? `${hours}:${pad(mins)}:${pad(secs % 60)}` : `${mins}:${pad(secs % 60)}`;
}

/** Label of a participant kind (owner, user, guest). */
function kindLabel(kind) {
  return t(`terminal.kind.${kind === 'owner' || kind === 'guest' ? kind : 'user'}`);
}

/**
 * Mounts the terminal view. Options:
 * - `sessionId`: your own session or one shared with you (uses your token).
 * - `wsPath`: WebSocket path of a link (`/join`).
 * - `guestName`: link guests: display name.
 * - `withAccount`: link: join with the signed-in account (its name).
 * - `title`, `subtitle`: header texts.
 * - `owner`: name of the owner (for the waiting room).
 * - `back`: `{label, href}` or `{label, onClick}`.
 * - `onShare(session)`: owner: opens the share dialog.
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
  let me = null;
  let proto2 = false;
  let writable = false;
  let participants = [];
  let driver = null;
  let driverName = null;
  let driverUntil = null;
  let tickTimer = null;
  let revokeToast = null;
  let grantDlg = null;
  let panelOpen = false;
  let expectSnapshot = true;
  let finished = false;
  let waiting = false;
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
  const driverSlot = h('span');
  const peopleBtn = h('button', { class: 'btn btn-sm term-people-btn', type: 'button', hidden: true, 'aria-expanded': 'false', title: t('terminal.people.toggle') });
  const shareBtn = h('button', { class: 'btn btn-sm', type: 'button', hidden: true, title: t('terminal.share') }, icon('share', { size: 15 }), h('span', { class: 'label-long', 'aria-hidden': 'true' }, t('terminal.share')));
  const takeBtn = h('button', { class: 'btn btn-sm btn-primary term-take', type: 'button', hidden: true, title: t('terminal.control.take_title') }, icon('keyboard', { size: 15 }), h('span', null, t('terminal.control.take')));
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
  const banners = h('div', { class: 'term-banners', 'aria-live': 'polite' });
  const panelList = h('div', { class: 'term-people-list' });
  const panelFoot = h('div', { class: 'term-people-foot' });
  const panelTitle = h('h2', { class: 'term-people-title' }, t('terminal.people.title'));
  const panel = h('aside', { class: 'term-people', hidden: true, 'aria-label': t('terminal.people.title') },
    h('div', { class: 'term-people-head' }, panelTitle,
      h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', 'aria-label': t('common.close'), onclick: () => togglePanel(false) }, icon('x', { size: 16 }))),
    panelList,
    panelFoot);
  const note = h('div', { class: 'term-note' });
  const root = h('div', { class: 'term-page' },
    h('div', { class: 'term-head' },
      back,
      h('div', { class: 'stack-sm grow' },
        titleEl,
        h('div', { class: 'term-head-meta' }, stateSlot, accessSlot, driverSlot, opts.subtitle ? h('span', { class: 'small muted' }, opts.subtitle) : null)),
      h('div', { class: 'term-head-actions' }, takeBtn, peopleBtn, shareBtn, fitBtn, fullBtn, closeBtn)),
    banners,
    h('div', { class: 'term-main' }, stage, panel),
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

  const isOwner = () => access === 'owner';
  // Protocol 2: the server says whether our input reaches the terminal.
  // Older servers: by the access.
  const canWrite = () => (proto2 ? writable : access === 'owner' || access === 'control');

  const send = (msg) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
  };

  const endActions = () => (opts.sessionId
    ? [h('a', { class: 'btn btn-sm', href: '/app/sessions' }, t('terminal.back_to_sessions'))]
    : [h('a', { class: 'btn btn-sm', href: '/' }, t('terminal.end.home'))]);

  // --- Header, keyboard bar and banners ------------------------------------------
  const nameOf = (pid) => {
    const p = participants.find((x) => x.id === pid);
    return p ? p.name : null;
  };
  const present = () => participants.filter((p) => !p.waiting);

  // Timed grant: "4:59 left", kept up to date every second.
  const countdown = () => (driverUntil
    ? h('span', { class: 'term-countdown', dataset: { countdown: '' }, title: t('terminal.grant.until', { time: absTime(driverUntil) }) },
      icon('clock', { size: 13 }), h('span', null, t('terminal.grant.left', { time: clock(driverUntil) })))
    : null);
  const tick = () => {
    if (!driverUntil) {
      clearInterval(tickTimer);
      tickTimer = null;
      return;
    }
    const text = t('terminal.grant.left', { time: clock(driverUntil) });
    for (const el of root.querySelectorAll('[data-countdown] > span')) el.textContent = text;
  };
  const startTicking = () => {
    if (driverUntil && !tickTimer) tickTimer = setInterval(tick, 1000);
    if (!driverUntil) tick();
  };

  // Owner: hand the keyboard over, for good or for a while.
  const grant = (pid, minutes) => send(minutes ? { type: 'control_grant', participant: pid, minutes } : { type: 'control_grant', participant: pid });
  const chooseGrant = (p) => {
    if (grantDlg) grantDlg.close('cancel');
    const again = driver === p.id;
    const pick = (m) => h('button', { class: ['btn', 'term-grant-option', !m && 'btn-primary'], type: 'button', onclick: () => { dlg.close('done'); grant(p.id, m); } },
      icon(m ? 'clock' : 'keyboard', { size: 15 }),
      m ? t('terminal.grant.minutes', { count: m }) : t('terminal.grant.forever'));
    const dlg = openDialog({
      title: again ? t('terminal.grant.change_title', { name: p.name }) : t('terminal.grant.title', { name: p.name }),
      description: t('terminal.grant.description'),
      iconName: 'keyboard',
      body: h('div', { class: 'term-grant-options' }, GRANT_MINUTES.map(pick)),
      actions: [h('button', { class: 'btn', type: 'button', onclick: () => dlg.close('cancel') }, t('common.cancel'))],
      onClose: () => {
        if (grantDlg === dlg) grantDlg = null;
      },
    });
    grantDlg = dlg;
  };
  const others = () => present().filter((p) => !p.you);

  const renderPeopleButton = () => {
    const list = present();
    peopleBtn.hidden = !proto2 || !list.length;
    replace(peopleBtn,
      h('span', { class: 'avatar-stack' }, list.slice(0, 4).map((p) => avatar(p.name, p.user_id || p.id, 'sm'))),
      h('span', null, t('terminal.viewers', { count: list.length })));
    peopleBtn.setAttribute('aria-expanded', panelOpen ? 'true' : 'false');
    peopleBtn.title = list.map((p) => p.name).join(', ');
  };

  const updateHeader = () => {
    if (session) {
      titleEl.textContent = session.title;
      if (opts.onTitle && session.title) opts.onTitle(session.title);
      replace(stateSlot, stateBadge(session.state));
    }
    if (!access) return;
    replace(accessSlot, isOwner() ? badge(permissionLabel('owner'), 'accent', 'crown') : badge(permissionLabel(access), access === 'control' ? 'warn' : 'info', access === 'control' ? 'keyboard' : 'eye'));
    // Who drives: shown when someone other than the owner has the keyboard.
    replace(driverSlot, proto2 && driver
      ? h('span', { class: 'badge badge-warn term-driver', title: t('terminal.control.driver_title') }, icon('keyboard', { size: 13 }), me && driver === me.participant ? t('terminal.control.you_drive') : t('terminal.control.driving', { name: driverName || nameOf(driver) || '?' }),
        driverUntil ? h('span', { class: 'term-driver-sep', 'aria-hidden': 'true' }, '·') : null, countdown())
      : null);
    fitBtn.hidden = !canWrite();
    closeBtn.hidden = !isOwner() || !opts.sessionId;
    shareBtn.hidden = !isOwner() || !opts.sessionId || !opts.onShare;
    takeBtn.hidden = !(proto2 && isOwner() && driver);
    renderPeopleButton();
    renderNote();
    if (term) term.options.disableStdin = !canWrite();
  };

  // Bottom bar: what you can do with the keyboard.
  const renderNote = () => {
    if (!access) return;
    const btn = (label, ico, onclick, cls = 'btn btn-sm') => h('button', { class: cls, type: 'button', onclick }, icon(ico, { size: 14 }), label);
    if (!proto2) {
      replace(note, canWrite()
        ? [icon('keyboard', { size: 15 }), isOwner() ? t('terminal.note.owner') : t('terminal.note.control')]
        : [icon('eye', { size: 15 }), t('terminal.note.view')]);
      note.className = 'term-note';
      return;
    }
    let parts;
    let kind = '';
    if (isOwner()) {
      parts = driver
        ? [icon('keyboard', { size: 15 }), h('span', null, t('terminal.note.owner_guest_drives', { name: driverName || nameOf(driver) || '?' })), countdown(),
          btn(t('terminal.control.take'), 'keyboard', () => send({ type: 'control_take' }), 'btn btn-sm btn-primary')]
        : [icon('keyboard', { size: 15 }), h('span', null, t('terminal.note.owner'))];
    } else if (writable) {
      kind = 'is-driving';
      parts = [icon('keyboard', { size: 15 }), h('span', null, t('terminal.note.driving')), countdown(),
        btn(t('terminal.control.release'), 'x', () => send({ type: 'control_release' }))];
    } else if (access === 'control') {
      kind = 'is-readonly';
      const asked = me && participants.some((p) => p.you && p.requested_control);
      parts = asked
        ? [h('span', { class: 'spinner spinner-sm', 'aria-hidden': 'true' }), h('span', null, t('terminal.note.requested')),
          btn(t('terminal.control.cancel_request'), 'x', () => send({ type: 'control_release' }))]
        : [icon('eye', { size: 15 }), h('span', null, driver ? t('terminal.note.readonly_driver', { name: driverName || nameOf(driver) || '?' }) : t('terminal.note.readonly')),
          btn(t('terminal.control.request'), 'keyboard', () => send({ type: 'control_request' }), 'btn btn-sm btn-primary')];
    } else {
      kind = 'is-readonly';
      parts = [icon('eye', { size: 15 }), h('span', null, t('terminal.note.view'))];
    }
    note.className = ['term-note', kind].filter(Boolean).join(' ');
    replace(note, parts);
  };

  // Owner: who waits to enter and who asks for the keyboard.
  const renderBanners = () => {
    if (!isOwner() || !proto2) {
      replace(banners);
      return;
    }
    const items = [];
    for (const p of participants.filter((x) => x.waiting)) {
      items.push(h('div', { class: 'term-banner', role: 'alert' },
        avatar(p.name, p.user_id || p.id, 'sm'),
        h('span', { class: 'grow' }, t('terminal.banner.join', { name: p.name }), ' ', h('span', { class: 'muted' }, `· ${kindLabel(p.kind)}`)),
        h('button', { class: 'btn btn-sm btn-primary', type: 'button', onclick: () => send({ type: 'join_allow', participant: p.id }) }, icon('check', { size: 14 }), t('terminal.actions.allow')),
        h('button', { class: 'btn btn-sm', type: 'button', onclick: () => send({ type: 'join_deny', participant: p.id }) }, icon('x', { size: 14 }), t('terminal.actions.deny'))));
    }
    for (const p of participants.filter((x) => x.requested_control && !x.waiting)) {
      items.push(h('div', { class: 'term-banner', role: 'alert' },
        avatar(p.name, p.user_id || p.id, 'sm'),
        h('span', { class: 'grow' }, t('terminal.banner.control', { name: p.name })),
        h('button', { class: 'btn btn-sm btn-primary', type: 'button', onclick: () => chooseGrant(p) }, icon('keyboard', { size: 14 }), t('terminal.actions.give')),
        h('button', { class: 'btn btn-sm', type: 'button', onclick: () => send({ type: 'control_deny', participant: p.id }) }, icon('x', { size: 14 }), t('terminal.actions.deny'))));
    }
    replace(banners, items);
  };

  // Participants panel.
  const kick = async (p, block) => {
    const ok = await confirmDialog({
      title: block ? t('terminal.kick.block_title', { name: p.name }) : t('terminal.kick.title', { name: p.name }),
      message: block ? t('terminal.kick.block_message') : t('terminal.kick.message'),
      confirmLabel: block ? t('terminal.actions.kick_block') : t('terminal.actions.kick'),
      danger: true,
    });
    if (ok) send({ type: 'kick', participant: p.id, revoke_share: !!block });
  };

  const stopSharing = async () => {
    const ok = await confirmDialog({
      title: t('terminal.stop.title'),
      message: t('terminal.stop.message'),
      confirmLabel: t('terminal.stop.confirm'),
      danger: true,
    });
    if (!ok) return;
    send({ type: 'stop_sharing' });
    toast(t('terminal.stop.done'), 'success');
  };

  const participantRow = (p) => {
    const tags = [h('span', null, kindLabel(p.kind))];
    if (p.kind !== 'owner') tags.push(h('span', null, permissionLabel(p.access)));
    if (p.devices > 1) tags.push(h('span', null, t('terminal.people.devices', { count: p.devices })));
    if (p.devices === 0) tags.push(h('span', null, t('terminal.people.reconnecting')));
    if (p.since) tags.push(h('span', { title: new Date(p.since).toLocaleString() }, t('terminal.people.since', { time: relTime(p.since) })));
    if (p.is_driver && p.kind !== 'owner' && driverUntil) tags.push(countdown());
    const flags = [];
    if (p.is_driver) flags.push(h('span', { class: 'term-person-flag is-driver', title: t('terminal.people.driver') }, icon('keyboard', { size: 14 })));
    if (p.waiting) flags.push(badge(t('terminal.people.waiting'), 'info'));
    else if (p.requested_control) flags.push(badge(t('terminal.people.requested'), 'warn'));
    const actions = [];
    if (isOwner() && p.kind !== 'owner') {
      const act = (label, ico, onclick, cls = 'btn btn-sm') => h('button', { class: cls, type: 'button', onclick }, icon(ico, { size: 14 }), label);
      if (p.waiting) {
        actions.push(act(t('terminal.actions.allow'), 'check', () => send({ type: 'join_allow', participant: p.id }), 'btn btn-sm btn-primary'),
          act(t('terminal.actions.deny'), 'x', () => send({ type: 'join_deny', participant: p.id })));
      } else {
        if (p.is_driver) {
          actions.push(act(t('terminal.actions.take'), 'keyboard', () => send({ type: 'control_take' })),
            act(t('terminal.grant.change'), 'clock', () => chooseGrant(p)));
        } else if (p.access === 'control') {
          actions.push(act(t('terminal.actions.give'), 'keyboard', () => chooseGrant(p), p.requested_control ? 'btn btn-sm btn-primary' : 'btn btn-sm'));
        }
        if (p.requested_control && !p.is_driver) actions.push(act(t('terminal.actions.deny'), 'x', () => send({ type: 'control_deny', participant: p.id })));
        actions.push(act(t('terminal.actions.kick'), 'logout', () => kick(p, false), 'btn btn-sm btn-danger-ghost'),
          act(t('terminal.actions.kick_block'), 'lock', () => kick(p, true), 'btn btn-sm btn-danger-ghost'));
      }
    }
    return h('div', { class: ['term-person', p.waiting && 'is-waiting'] },
      h('div', { class: 'term-person-main' },
        avatar(p.name, p.user_id || p.id, 'sm'),
        h('div', { class: 'grow term-person-text' },
          h('div', { class: 'term-person-name' }, h('span', { class: 'break' }, p.name), p.you ? h('span', { class: 'muted' }, ` ${t('terminal.people.you')}`) : null, flags),
          h('div', { class: 'term-person-meta' }, tags))),
      actions.length ? h('div', { class: 'term-person-actions' }, actions) : null);
  };

  const renderPanel = () => {
    if (!proto2) return;
    replace(panelList, participants.length ? participants.map(participantRow) : h('p', { class: 'small muted' }, t('terminal.people.nobody')));
    replace(panelFoot, isOwner()
      ? [opts.onShare && opts.sessionId ? h('button', { class: 'btn btn-sm', type: 'button', onclick: () => opts.onShare(session) }, icon('share', { size: 14 }), t('terminal.people.manage')) : null,
        others().length || participants.some((p) => p.waiting) ? h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button', onclick: stopSharing }, icon('x', { size: 14 }), t('terminal.stop.button')) : null]
      : null);
  };

  function togglePanel(open = !panelOpen) {
    panelOpen = open;
    panel.hidden = !open;
    peopleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) renderPanel();
  }

  const renderRoom = () => {
    updateHeader();
    renderBanners();
    renderPanel();
    startTicking();
  };

  // --- Authentication prompts (owner only) ------------------------------
  const closePrompt = () => {
    if (promptDlg) promptDlg.close('done');
    promptDlg = null;
    promptId = null;
  };

  const answer = (payload) => {
    send({ type: 'prompt_answer', prompt_id: promptId, ...payload });
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
    const sendBtn = h('button', { class: 'btn btn-primary', type: 'submit' }, t('common.send'));
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
      actions: [cancel, sendBtn],
      form,
    });
  };

  // --- End of the connection -----------------------------------------------------
  const END_SCREENS = {
    revoked: ['lock', 'terminal.end.revoked_title', 'terminal.end.revoked_text'],
    kicked: ['logout', 'terminal.end.kicked_title', 'terminal.end.kicked_text'],
    expired: ['clock', 'terminal.end.expired_title', 'terminal.end.expired_text'],
    session_ended: ['power', 'terminal.overlay.ended', 'terminal.end.session_ended_text'],
    join_denied: ['lock', 'terminal.end.join_denied_title', 'terminal.end.join_denied_text'],
    forbidden: ['lock', 'terminal.overlay.no_access', 'terminal.end.forbidden_text'],
    signed_out: ['logout', 'terminal.end.signed_out_title', 'terminal.end.signed_out_text'],
  };

  const endWith = (code) => {
    const already = finished;
    finished = true;
    waiting = false;
    closePrompt();
    if (grantDlg) grantDlg.close('cancel');
    writable = false;
    driverUntil = null;
    startTicking();
    if (term) term.options.disableStdin = true;
    // The session closed: the `status` overlay (with the exit code) stays.
    if (code === 'session_ended' && already) return;
    const [ico, title, text] = END_SCREENS[code] || END_SCREENS.forbidden;
    showOverlay(ico, t(title), t(text), endActions());
    replace(banners);
    note.className = 'term-note';
    replace(note, [icon(ico, { size: 15 }), t(title)]);
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
        endActions());
    } else {
      hideOverlay();
    }
  };

  const setRoom = (list, drv) => {
    if (Array.isArray(list)) participants = list;
    // Someone else has the keyboard now: their time (if any) comes with `control`.
    if (drv !== undefined && drv !== driver) driverUntil = null;
    if (drv !== undefined) driver = drv;
    const d = driver ? participants.find((p) => p.id === driver) : null;
    if (d) driverName = d.name;
    if (!driver) driverName = null;
    renderRoom();
  };

  const showWaiting = (msg) => {
    waiting = true;
    const s = msg.session || {};
    if (s.title) titleEl.textContent = s.title;
    showOverlay('spinner', t('terminal.waiting.title', { owner: s.owner || opts.owner || t('terminal.waiting.the_owner') }),
      t('terminal.waiting.text'),
      opts.back ? [h('button', { class: 'btn btn-sm', type: 'button', onclick: () => { cleanup(); if (opts.back.onClick) opts.back.onClick(); else location.assign(opts.back.href); } }, t('terminal.waiting.leave'))] : []);
    replace(note, [icon('clock', { size: 15 }), t('terminal.waiting.note', { name: msg.name || '' })]);
  };

  const onJson = (msg) => {
    switch (msg.type) {
      case 'waiting':
        showWaiting(msg);
        break;
      case 'hello': {
        waiting = false;
        session = msg.session;
        me = msg.you || null;
        access = me && me.access;
        proto2 = msg.proto >= 2 && !!me && me.can_write !== undefined;
        writable = !!(me && me.can_write);
        participants = (session && session.participants) || [];
        driver = (session && session.driver) || null;
        driverUntil = (driver && session.driver_until) || null;
        if (term && session.cols && session.rows) term.resize(session.cols, session.rows);
        setState(session.state);
        setRoom(participants, driver);
        retries = 0;
        break;
      }
      case 'status':
        setState(msg.status);
        break;
      case 'participants':
        setRoom(msg.participants, msg.driver === undefined ? driver : msg.driver);
        break;
      case 'control': {
        const before = writable;
        const beforeUntil = driverUntil;
        writable = !!msg.can_write;
        driver = msg.driver || null;
        driverName = msg.driver_name || null;
        driverUntil = (driver && msg.until) || null;
        if (!isOwner()) {
          if (writable && !before) {
            toast(driverUntil
              ? t('terminal.grant.granted_for', { count: Math.max(1, Math.round((driverUntil - Date.now()) / 60000)) })
              : t('terminal.control.granted'), 'success');
          } else if (writable && driverUntil !== beforeUntil) {
            toast(driverUntil ? t('terminal.grant.changed', { time: clock(driverUntil) }) : t('terminal.grant.unlimited'), 'info');
          } else if (!writable && before) {
            // If the time ran out, `control_expired` comes right after: that
            // toast instead of this one.
            clearTimeout(revokeToast);
            revokeToast = setTimeout(() => {
              revokeToast = null;
              if (!disposed && !finished) toast(t('terminal.control.revoked'), 'info');
            }, 400);
          }
        }
        renderRoom();
        if (writable && term) term.focus();
        break;
      }
      case 'control_expired': {
        if (me && msg.participant === me.participant) {
          clearTimeout(revokeToast);
          revokeToast = null;
          toast(t('terminal.grant.expired_you'), 'info');
        } else if (isOwner()) {
          const name = nameOf(msg.participant);
          toast(name ? t('terminal.grant.expired_owner', { name }) : t('terminal.grant.expired_owner_unknown'), 'info');
        }
        break;
      }
      case 'join_request':
      case 'control_request':
        // The participant comes in the message too: merge it in case the
        // list has not arrived yet.
        if (msg.participant && msg.participant.id) {
          const i = participants.findIndex((p) => p.id === msg.participant.id);
          if (i >= 0) participants[i] = { ...participants[i], ...msg.participant };
          else participants = [...participants, msg.participant];
          renderRoom();
        }
        break;
      case 'control_denied':
        toast(t('terminal.control.denied'), 'info');
        participants = participants.map((p) => (p.you ? { ...p, requested_control: false } : p));
        renderRoom();
        break;
      case 'presence':
        // Older servers.
        if (session) session.viewers = msg.viewers;
        if (!proto2) {
          participants = (msg.viewers || []).map((v) => ({ ...v, devices: 1 }));
          renderPeopleButton();
          peopleBtn.hidden = !participants.length;
        }
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
        if (msg.code && msg.code !== 'forbidden' && END_CODES[msg.code]) {
          endWith(msg.code);
        } else {
          // `forbidden` is also the code of a single refused action: if the
          // socket closes right after (4006), the end screen wins.
          const text = capitalize(errorText({ code: msg.code, message: msg.message }, 'terminal.error.session'));
          setTimeout(() => {
            if (!finished && !disposed) toast(text, 'error');
          }, msg.code === 'forbidden' ? 400 : 0);
        }
        break;
      default:
        break;
    }
  };

  // --- Connection ---------------------------------------------------------------
  const linkToken = () => {
    if (!opts.wsPath) return null;
    const q = opts.wsPath.split('?')[1] || '';
    return new URLSearchParams(q).get('share_token');
  };

  const wsUrl = async () => {
    const base = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;
    if (opts.wsPath) {
      const params = new URLSearchParams({ proto: '2' });
      let token = null;
      if (opts.withAccount) {
        try {
          token = await freshAccessToken();
        } catch {
          token = null;
        }
      }
      if (token) {
        params.set('access_token', token);
      } else {
        const key = guestKey();
        if (key) params.set('guest', key);
        if (opts.guestName) params.set('name', opts.guestName);
      }
      return `${base}${opts.wsPath}${opts.wsPath.includes('?') ? '&' : '?'}${params}`;
    }
    const token = await freshAccessToken();
    return `${base}/api/v1/sessions/${encodeURIComponent(opts.sessionId)}/ws?proto=2&access_token=${encodeURIComponent(token)}`;
  };

  // After an unexpected close: does the session still exist?
  const stillThere = async () => {
    try {
      if (opts.wsPath) {
        const token = linkToken();
        if (token) await api.get(`/join/${encodeURIComponent(token)}`, { auth: false });
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
    if (disposed || finished) return;
    if (check !== true) {
      finished = true;
      showOverlay('power', t('terminal.overlay.unavailable'), capitalize(errorText(check)), endActions());
      return;
    }
    if (retries >= MAX_RETRIES) {
      showOverlay('wifi-off', t('terminal.overlay.disconnected'), t('terminal.overlay.disconnected_text'),
        [h('button', { class: 'btn btn-sm btn-primary', type: 'button', onclick: () => { retries = 0; connect(); } }, icon('refresh', { size: 15 }), t('terminal.reconnect'))]);
      return;
    }
    const delay = Math.min(1000 * 2 ** retries, 15000);
    retries += 1;
    if (!waiting) showOverlay('spinner', t('terminal.overlay.reconnecting'), t('terminal.overlay.still_alive'));
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
      if (ws !== sock) return;
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
    sock.onclose = (ev) => {
      clearInterval(pingTimer);
      if (ws !== sock) return;
      ws = null;
      if (disposed) return;
      // Sent away for good: no reconnecting.
      const code = END_BY_CLOSE[ev.code] || (END_CODES[ev.reason] ? ev.reason : null);
      if (code) {
        if (!finished || code === 'session_ended') endWith(code);
        return;
      }
      if (!finished) scheduleRetry();
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
    // Input only while the server lets it through (`can_write`).
    term.onData((data) => {
      if (canWrite() && !finished && ws && ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(data));
    });
    term.onBinary((data) => {
      if (!canWrite() || finished || !ws || ws.readyState !== WebSocket.OPEN) return;
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
    if (!term || !canWrite() || !ws || ws.readyState !== WebSocket.OPEN) return;
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
    send({ type: 'resize', cols: dims.cols, rows: dims.rows });
  });
  fullBtn.addEventListener('click', () => {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (stage.requestFullscreen) stage.requestFullscreen().catch(() => {});
  });
  takeBtn.addEventListener('click', () => send({ type: 'control_take' }));
  peopleBtn.addEventListener('click', () => togglePanel());
  shareBtn.addEventListener('click', () => {
    if (opts.onShare) opts.onShare(session);
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
    clearInterval(tickTimer);
    clearTimeout(revokeToast);
    closePrompt();
    if (grantDlg) grantDlg.close('cancel');
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
