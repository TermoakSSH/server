// Persistent server sessions: yours (with invitation management and
// closing), those shared with you and the recent history.

import { h, replace } from '../../dom.js';
import { icon } from '../../icons.js';
import { api, fetchBlob } from '../../api.js';
import { permissionLabel, duration, relTime, shortId, absTime } from '../../format.js';
import {
  pageHead, loadingState, errorState, emptyState, badge, timeEl, toast, toastError, busy, confirmDialog,
  openDialog, field, segmented, copyField, errorBox, avatar, downloadBlob, alertBox, capitalize,
} from '../../ui.js';
import { t, tx } from '../../i18n.js';
import { stateBadge } from './shared.js';

// --- Invitation names (only in this browser) ---------------------
// Older servers do not return the invitee's email in the list of a
// session's invitations: the one typed when sharing is remembered here.
const LABELS_KEY = 'termoak.shareLabels';

function shareLabels() {
  try {
    return JSON.parse(localStorage.getItem(LABELS_KEY) || '{}') || {};
  } catch {
    return {};
  }
}

function rememberShare(id, label) {
  try {
    const all = shareLabels();
    all[id] = label;
    const keys = Object.keys(all);
    // Only the 200 most recent are kept.
    for (const k of keys.slice(0, Math.max(0, keys.length - 200))) delete all[k];
    localStorage.setItem(LABELS_KEY, JSON.stringify(all));
  } catch {
    /* no storage */
  }
}

function expiryOptions() {
  return [
    { value: '', label: t('sessions.expiry.none') },
    { value: '60', label: t('sessions.expiry.hours', { count: 1 }) },
    { value: '480', label: t('sessions.expiry.hours', { count: 8 }) },
    { value: '1440', label: t('sessions.expiry.hours', { count: 24 }) },
    { value: '10080', label: t('sessions.expiry.days', { count: 7 }) },
    { value: '43200', label: t('sessions.expiry.days', { count: 30 }) },
  ];
}

function kindLabel(kind) {
  return kind === 'relay' ? t('sessions.kind.relay') : t('sessions.kind.server');
}

// --- Invitation manager of a session ----------------------------------------

/** Dialog to see, create and revoke the invitations of your own session. */
export function shareDialog(session, { onChange } = {}) {
  const list = h('div', null, loadingState(t('sessions.share.loading')));
  const result = h('div');
  const error = errorBox();
  let teams = [];

  const describe = (s) => {
    if (s.is_link) return { ico: 'link', text: t('sessions.share.anyone_with_link') };
    if (s.team_id) {
      const team = teams.find((x) => x.id === s.team_id);
      const name = s.team_name || (team && team.name);
      return { ico: 'users', text: name ? t('sessions.share.team_named', { name }) : t('sessions.share.a_team') };
    }
    // The server gives the email and name; if not (older versions), the
    // email typed when inviting, remembered in this browser.
    const label = s.user_email
      ? (s.user_name && s.user_name !== s.user_email ? `${s.user_name} (${s.user_email})` : s.user_email)
      : shareLabels()[s.id];
    return { ico: 'user', text: label || t('sessions.share.user_id', { id: shortId(s.user_id) }) };
  };

  const loadShares = async () => {
    try {
      const shares = await api.get(`/sessions/${session.id}/shares`);
      const now = Date.now();
      const active = shares.filter((s) => !s.revoked && !(s.expires_at && s.expires_at < now));
      const old = shares.length - active.length;
      if (!active.length) {
        replace(list, h('p', { class: 'small muted' }, t('sessions.share.nobody'), old ? ` ${t('sessions.share.old', { count: old })}` : ''));
        return;
      }
      replace(list, h('div', { class: 'card card-flush' }, h('div', { class: 'list' },
        active.map((s) => {
          const d = describe(s);
          const revoke = h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button' }, icon('x', { size: 15 }), t('common.revoke'));
          revoke.addEventListener('click', async () => {
            const ok = await confirmDialog({
              title: t('sessions.share.revoke_title'),
              message: t('sessions.share.revoke_message', { who: d.text, title: session.title }),
              confirmLabel: t('common.revoke'),
              danger: true,
            });
            if (!ok) return;
            busy(revoke, async () => {
              try {
                await api.del(`/sessions/${session.id}/shares/${s.id}`);
                toast(t('sessions.share.revoked'), 'success');
                await loadShares();
                if (onChange) onChange();
              } catch (e) {
                toastError(e);
              }
            });
          });
          return h('div', { class: 'list-item' },
            h('span', { class: 'icon-tile muted-tile' }, icon(d.ico, { size: 17 })),
            h('div', { class: 'list-item-main' },
              h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, d.text),
                badge(permissionLabel(s.permission), s.permission === 'control' ? 'warn' : 'info', s.permission === 'control' ? 'keyboard' : 'eye')),
              h('div', { class: 'list-item-meta' },
                h('span', null, tx('sessions.share.created', { time: timeEl(s.created_at) })),
                h('span', { title: s.expires_at ? absTime(s.expires_at) : null }, s.expires_at ? t('sessions.share.expires', { time: relTime(s.expires_at) }) : t('sessions.share.no_expiry')))),
            h('div', { class: 'list-item-actions keep-inline' }, revoke));
        }))));
    } catch (e) {
      replace(list, errorState(e, loadShares));
    }
  };

  // Share form.
  const email = field({ label: t('sessions.share.email'), name: 'email', type: 'email', placeholder: t('sessions.share.email_placeholder'), autocomplete: 'off', hint: t('sessions.share.email_hint') });
  const teamSel = field({ label: t('sessions.share.team'), name: 'team', options: [{ value: '', label: t('teams.loading') }] });
  const linkNote = alertBox({ kind: 'warn', text: t('sessions.share.link_warning') });
  const targetBox = h('div', null, email);
  const target = segmented({
    name: `target-${session.id}`,
    label: t('sessions.share.with_whom'),
    value: 'user',
    options: [
      { value: 'user', label: t('sessions.share.target.user'), icon: 'user' },
      { value: 'team', label: t('sessions.share.target.team'), icon: 'users' },
      { value: 'link', label: t('sessions.share.target.link'), icon: 'link' },
    ],
    onChange: (v) => replace(targetBox, v === 'user' ? email : v === 'team' ? teamSel : linkNote),
  });
  const perm = segmented({
    name: `perm-${session.id}`,
    label: t('sessions.share.permission'),
    value: 'view',
    options: [
      { value: 'view', label: permissionLabel('view'), icon: 'eye' },
      { value: 'control', label: permissionLabel('control'), icon: 'keyboard' },
    ],
  });
  const expiry = field({ label: t('sessions.share.expiry'), name: 'expiry', options: expiryOptions(), value: '' });
  const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, icon('share', { size: 16 }), t('sessions.share.submit'));
  const form = h('form', { class: 'form', novalidate: true },
    error,
    h('div', { class: 'field' }, h('span', { class: 'label' }, t('sessions.share.with_whom')), target),
    targetBox,
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('span', { class: 'label' }, t('sessions.share.permission')), perm),
      expiry),
    h('div', null, submit));

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    const kind = target.value;
    const body = { permission: perm.value };
    const minutes = expiry.input.value;
    if (minutes) body.expires_in_minutes = Number(minutes);
    let label = t('sessions.share.anyone_with_link');
    if (kind === 'user') {
      const v = email.input.value.trim();
      if (!v || !v.includes('@')) {
        error.show(t('sessions.share.error.email'));
        email.input.focus();
        return;
      }
      body.email = v;
      label = v;
    } else if (kind === 'team') {
      if (!teamSel.input.value) {
        error.show(t('sessions.share.error.team'));
        return;
      }
      body.team_id = teamSel.input.value;
      const team = teams.find((x) => x.id === body.team_id);
      label = team ? t('sessions.share.team_named', { name: team.name }) : t('sessions.share.team');
    } else {
      body.link = true;
    }
    busy(submit, async () => {
      try {
        const r = await api.post(`/sessions/${session.id}/shares`, body);
        if (kind === 'user') rememberShare(r.share.id, label);
        if (r.link) {
          replace(result, h('div', { class: 'share-result', role: 'status' },
            h('div', { class: 'row' }, icon('check-circle', { size: 18, class: 'accent' }), h('strong', null, t('sessions.share.link_created'))),
            h('p', { class: 'small' }, t('sessions.share.link_copy_now')),
            copyField(r.link, { label: t('sessions.share.web_link') }),
            r.app_link ? copyField(r.app_link, { label: t('sessions.share.app_link') }) : null));
        } else {
          replace(result, alertBox({ kind: 'success', text: t('sessions.share.shared_with', { who: label }) }));
        }
        email.input.value = '';
        await loadShares();
        if (onChange) onChange();
      } catch (err) {
        error.show(err);
      }
    });
  });

  openDialog({
    title: t('sessions.share.title', { title: session.title }),
    description: t('sessions.share.description'),
    iconName: 'share',
    wide: true,
    body: [
      h('div', { class: 'stack-sm' }, h('h3', { class: 'admin-section-title' }, t('sessions.share.with_access')), list),
      result,
      h('div', { class: 'stack-sm' }, h('h3', { class: 'admin-section-title' }, t('sessions.share.share_again')), form),
    ],
  });

  // Teams you can share with (those you are a member of).
  api.get('/teams').then((all) => {
    teams = all.filter((team) => team.role);
    const sel = teamSel.input;
    replace(sel, teams.length
      ? [h('option', { value: '' }, t('sessions.share.choose_team')), ...teams.map((team) => h('option', { value: team.id }, `${team.name} (${t('teams.members', { count: team.member_count })})`))]
      : h('option', { value: '' }, t('sessions.share.no_teams')));
    loadShares();
  }).catch(() => loadShares());
}

// --- Cards -------------------------------------------------------------------

function viewersStack(viewers = []) {
  if (!viewers.length) return h('span', null, icon('eye', { size: 14 }), t('sessions.nobody_connected'));
  return h('span', { title: viewers.map((v) => v.name).join(', ') },
    h('span', { class: 'avatar-stack' }, viewers.slice(0, 4).map((v) => avatar(v.name, v.user_id || v.id, 'sm'))),
    t('sessions.viewers', { count: viewers.length }));
}

function activeCard(s, reload) {
  const share = h('button', { class: 'btn btn-sm', type: 'button', onclick: () => shareDialog(s, { onChange: reload }) }, icon('share', { size: 15 }), t('sessions.share.submit'));
  const close = h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button' }, icon('power', { size: 15 }), t('common.close'));
  close.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: t('terminal.close_session'),
      message: t('sessions.close_message', { title: s.title }),
      confirmLabel: t('terminal.close_session'),
      danger: true,
    });
    if (!ok) return;
    busy(close, async () => {
      try {
        await api.del(`/sessions/${s.id}`);
        toast(t('terminal.closed_toast'), 'success');
        reload();
      } catch (e) {
        toastError(e);
      }
    });
  });
  return h('article', { class: 'card session-card' },
    h('div', { class: 'row-between' },
      h('div', { class: 'session-title grow' },
        h('span', { class: 'icon-tile' }, icon(s.kind === 'relay' ? 'laptop' : 'server', { size: 19 })),
        h('div', { class: 'grow' }, h('h3', { title: s.title }, s.title), h('span', { class: 'small muted' }, kindLabel(s.kind)))),
      stateBadge(s.state)),
    h('div', { class: 'session-meta' },
      h('span', null, icon('clock', { size: 14 }), tx('sessions.opened', { time: timeEl(s.created_at) })),
      h('span', null, icon('resize', { size: 14 }), `${s.cols}×${s.rows}`),
      viewersStack(s.viewers),
      s.recording ? h('span', null, icon('dot', { size: 12, class: 'danger-text' }), t('sessions.recording')) : null),
    s.state && s.state.state === 'connecting' && s.state.message ? h('p', { class: 'small muted' }, capitalize(s.state.message)) : null,
    h('div', { class: 'session-actions' },
      h('a', { class: 'btn btn-sm btn-primary', href: `/app/sessions/${s.id}` }, icon('terminal', { size: 15 }), t('sessions.open_in_browser')),
      share,
      close));
}

function sharedCard(s) {
  return h('article', { class: 'card session-card' },
    h('div', { class: 'row-between' },
      h('div', { class: 'session-title grow' },
        h('span', { class: 'icon-tile muted-tile' }, icon('share', { size: 19 })),
        h('div', { class: 'grow' }, h('h3', { title: s.title }, s.title), h('span', { class: 'small muted' }, s.owner_name ? t('sessions.shared_by', { name: s.owner_name }) : t('sessions.owner.shared')))),
      stateBadge(s.state)),
    h('div', { class: 'session-meta' },
      h('span', null, s.access === 'control' ? icon('keyboard', { size: 14 }) : icon('eye', { size: 14 }), permissionLabel(s.access)),
      h('span', null, icon('clock', { size: 14 }), tx('sessions.opened', { time: timeEl(s.created_at) })),
      viewersStack(s.viewers)),
    h('div', { class: 'session-actions' },
      h('a', { class: 'btn btn-sm btn-primary', href: `/app/sessions/${s.id}` }, icon('terminal', { size: 15 }), s.access === 'control' ? t('sessions.open_in_browser') : t('sessions.view_in_browser'))));
}

function recentList(items) {
  if (!items.length) return h('p', { class: 'small muted' }, t('sessions.recent.empty'));
  return h('div', { class: 'card card-flush' }, h('div', { class: 'list' },
    items.map((s) => {
      const actions = [];
      if (s.recording) {
        const dl = h('button', { class: 'btn btn-sm', type: 'button' }, icon('download', { size: 15 }), t('sessions.recent.recording'));
        dl.addEventListener('click', () => busy(dl, async () => {
          try {
            const { blob, filename } = await fetchBlob(`/sessions/${s.id}/recording`);
            downloadBlob(filename, blob);
          } catch (e) {
            toastError(e);
          }
        }));
        actions.push(dl);
      }
      return h('div', { class: 'list-item' },
        h('span', { class: 'icon-tile muted-tile' }, icon(s.kind === 'relay' ? 'laptop' : 'terminal', { size: 17 })),
        h('div', { class: 'list-item-main' },
          h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, s.title), stateBadge(s.status)),
          h('div', { class: 'list-item-meta' },
            h('span', null, timeEl(s.created_at)),
            s.ended_at ? h('span', null, t('sessions.recent.lasted', { duration: duration(s.created_at, s.ended_at) })) : null,
            h('span', null, kindLabel(s.kind)),
            s.error ? h('span', { class: 'danger-text' }, capitalize(s.error)) : null)),
        actions.length ? h('div', { class: 'list-item-actions keep-inline' }, actions) : null);
    })));
}

export function render(ctx) {
  const body = h('div', null, loadingState(t('sessions.loading')));
  const refreshBtn = h('button', { class: 'btn', type: 'button' }, icon('refresh', { size: 16 }), t('common.refresh'));
  let first = true;

  const load = async () => {
    if (first) replace(body, loadingState(t('sessions.loading')));
    try {
      const data = await api.get('/sessions');
      if (!ctx.alive()) return;
      first = false;
      replace(body, h('div', { class: 'stack-lg' },
        alertBox({
          kind: 'info',
          iconName: 'terminal',
          text: t('sessions.intro'),
        }),
        h('section', { class: 'section', 'aria-labelledby': 's-active' },
          h('div', { class: 'section-head' }, h('h2', { id: 's-active' }, t('sessions.active.title'), h('span', { class: 'count' }, String(data.active.length)))),
          data.active.length
            ? h('div', { class: 'grid grid-2' }, data.active.map((s) => activeCard(s, load)))
            : h('div', { class: 'card' }, emptyState({ iconName: 'server', title: t('sessions.active.empty.title'), text: t('sessions.active.empty.text') }))),
        h('section', { class: 'section', 'aria-labelledby': 's-shared' },
          h('div', { class: 'section-head' }, h('h2', { id: 's-shared' }, t('sessions.shared.title'), h('span', { class: 'count' }, String(data.shared.length)))),
          data.shared.length
            ? h('div', { class: 'grid grid-2' }, data.shared.map(sharedCard))
            : h('p', { class: 'small muted' }, t('sessions.shared.empty'))),
        h('section', { class: 'section', 'aria-labelledby': 's-recent' },
          h('div', { class: 'section-head' }, h('h2', { id: 's-recent' }, t('sessions.recent.title'), h('span', { class: 'count' }, String(data.recent.length)))),
          recentList(data.recent))));
    } catch (e) {
      if (ctx.alive()) replace(body, errorState(e, load));
    }
  };
  refreshBtn.addEventListener('click', () => busy(refreshBtn, load));
  load();
  // Refreshes itself every 20 seconds while the page is open.
  const timer = setInterval(() => {
    if (!document.hidden && !document.querySelector('dialog[open]')) load();
  }, 20_000);
  ctx.onCleanup(() => clearInterval(timer));

  return h('div', { class: 'stack-lg' },
    pageHead({ title: t('sessions.title'), subtitle: t('sessions.subtitle'), actions: [refreshBtn] }),
    body);
}
