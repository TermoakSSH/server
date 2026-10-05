// Persistent server sessions: yours (with invitation management and
// closing), those shared with you and the recent history.

import { h, replace } from '../../dom.js';
import { icon } from '../../icons.js';
import { api, fetchBlob } from '../../api.js';
import { permissionLabel, duration, relTime, shortId, absTime } from '../../format.js';
import {
  pageHead, loadingState, errorState, emptyState, badge, timeEl, toast, toastError, busy, confirmDialog,
  openDialog, field, segmented, copyField, errorBox, avatar, downloadBlob, alertBox, capitalize, checkbox,
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

/** Is the share still usable (not revoked nor expired)? */
function shareActive(s, now = Date.now()) {
  if (typeof s.active === 'boolean') return s.active;
  return !s.revoked && !(s.expires_at && s.expires_at < now);
}

/**
 * Dialog to see, create, change and revoke the invitations of your own
 * session, and to stop sharing it.
 */
export function shareDialog(session, { onChange } = {}) {
  const list = h('div', null, loadingState(t('sessions.share.loading')));
  const result = h('div');
  const error = errorBox();
  let teams = [];
  let editing = null;

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

  const changed = () => {
    if (onChange) onChange();
  };

  // Inline editor of an existing share (applied live with PATCH).
  const editor = (s) => {
    const err = errorBox();
    const ePerm = segmented({
      name: `eperm-${s.id}`,
      label: t('sessions.share.permission'),
      value: s.permission,
      options: [
        { value: 'view', label: permissionLabel('view'), icon: 'eye' },
        { value: 'control', label: permissionLabel('control'), icon: 'keyboard' },
      ],
      onChange: (v) => {
        eAuto.input.disabled = v !== 'control';
      },
    });
    const eExpiry = field({
      label: t('sessions.share.expiry'),
      name: 'expiry',
      small: true,
      options: [{ value: 'keep', label: s.expires_at ? t('sessions.share.edit.keep_expiry', { time: relTime(s.expires_at) }) : t('sessions.share.edit.keep_no_expiry') },
        ...expiryOptions().map((o) => (o.value === '' ? { value: 'none', label: o.label } : o))],
      value: 'keep',
    });
    const eApproval = checkbox({ label: t('sessions.share.option.approval'), checked: !!s.require_approval });
    const eAuto = checkbox({ label: t('sessions.share.option.auto_grant'), checked: !!s.auto_grant });
    eAuto.input.disabled = s.permission !== 'control';
    const save = h('button', { class: 'btn btn-sm btn-primary', type: 'button' }, icon('check', { size: 14 }), t('common.save'));
    const cancel = h('button', { class: 'btn btn-sm', type: 'button', onclick: () => { editing = null; loadShares(); } }, t('common.cancel'));
    save.addEventListener('click', () => busy(save, async () => {
      err.hide();
      const body = {
        permission: ePerm.value,
        require_approval: eApproval.input.checked,
        auto_grant: ePerm.value === 'control' && eAuto.input.checked,
      };
      const ex = eExpiry.input.value;
      if (ex === 'none') body.no_expiry = true;
      else if (ex !== 'keep') body.expires_in_minutes = Number(ex);
      try {
        await api.patch(`/sessions/${session.id}/shares/${s.id}`, body);
        toast(t('sessions.share.edit.saved'), 'success');
        editing = null;
        await loadShares();
        changed();
      } catch (e) {
        err.show(e);
      }
    }));
    return h('div', { class: 'share-edit' },
      err,
      h('div', { class: 'form-row' },
        h('div', { class: 'field' }, h('span', { class: 'label' }, t('sessions.share.permission')), ePerm),
        eExpiry),
      h('div', { class: 'share-options' }, eApproval, eAuto),
      h('div', { class: 'row-wrap' }, save, cancel));
  };

  const stopSharing = async (button) => {
    const ok = await confirmDialog({
      title: t('sessions.share.stop_title'),
      message: t('sessions.share.stop_message', { title: session.title }),
      confirmLabel: t('sessions.share.stop'),
      danger: true,
    });
    if (!ok) return;
    busy(button, async () => {
      try {
        const r = await api.del(`/sessions/${session.id}/shares`);
        toast(t('sessions.share.stopped', { count: (r && r.revoked) || 0 }), 'success');
        editing = null;
        replace(result);
        await loadShares();
        changed();
      } catch (e) {
        toastError(e);
      }
    });
  };

  async function loadShares() {
    try {
      const shares = await api.get(`/sessions/${session.id}/shares`);
      const now = Date.now();
      const active = shares.filter((s) => shareActive(s, now));
      const old = shares.length - active.length;
      if (!active.length) {
        replace(list, h('p', { class: 'small muted' }, t('sessions.share.nobody'), old ? ` ${t('sessions.share.old', { count: old })}` : ''));
        return;
      }
      const stop = h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button' }, icon('x', { size: 15 }), t('sessions.share.stop'));
      stop.addEventListener('click', () => stopSharing(stop));
      replace(list,
        h('div', { class: 'card card-flush' }, h('div', { class: 'list' },
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
                  changed();
                } catch (e) {
                  toastError(e);
                }
              });
            });
            const edit = h('button', { class: 'btn btn-sm', type: 'button', 'aria-expanded': editing === s.id ? 'true' : 'false', onclick: () => { editing = editing === s.id ? null : s.id; loadShares(); } }, icon('edit', { size: 15 }), t('sessions.share.edit.button'));
            const inside = typeof s.participants === 'number' ? s.participants : 0;
            return h('div', { class: 'list-item list-item-wrap' },
              h('span', { class: 'icon-tile muted-tile' }, icon(d.ico, { size: 17 })),
              h('div', { class: 'list-item-main' },
                h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, d.text),
                  badge(permissionLabel(s.permission), s.permission === 'control' ? 'warn' : 'info', s.permission === 'control' ? 'keyboard' : 'eye'),
                  s.require_approval ? badge(t('sessions.share.badge.approval'), '', 'lock') : null,
                  s.permission === 'control' && s.auto_grant ? badge(t('sessions.share.badge.auto_grant'), '', 'keyboard') : null),
                h('div', { class: 'list-item-meta' },
                  h('span', null, tx('sessions.share.created', { time: timeEl(s.created_at) })),
                  h('span', { title: s.expires_at ? absTime(s.expires_at) : null }, s.expires_at ? t('sessions.share.expires', { time: relTime(s.expires_at) }) : t('sessions.share.no_expiry')),
                  inside ? h('span', null, icon('users', { size: 13 }), t('sessions.share.inside', { count: inside })) : null),
                editing === s.id ? editor(s) : null),
              h('div', { class: 'list-item-actions keep-inline' }, edit, revoke));
          }))),
        h('div', { class: 'share-stop' }, stop));
    } catch (e) {
      replace(list, errorState(e, loadShares));
    }
  }

  // Share form.
  const email = field({ label: t('sessions.share.email'), name: 'email', type: 'email', placeholder: t('sessions.share.email_placeholder'), autocomplete: 'off', hint: t('sessions.share.email_hint') });
  const teamSel = field({ label: t('sessions.share.team'), name: 'team', options: [{ value: '', label: t('teams.loading') }] });
  const linkNote = alertBox({ kind: 'warn', text: t('sessions.share.link_warning') });
  const targetBox = h('div', null, email);
  // "Ask me before letting people in": on by default for links, until it is
  // changed by hand.
  const approval = checkbox({ label: t('sessions.share.option.approval'), checked: false });
  let approvalTouched = false;
  approval.input.addEventListener('change', () => {
    approvalTouched = true;
  });
  const autoGrant = checkbox({ label: t('sessions.share.option.auto_grant'), checked: false });
  autoGrant.input.disabled = true;
  const target = segmented({
    name: `target-${session.id}`,
    label: t('sessions.share.with_whom'),
    value: 'user',
    options: [
      { value: 'user', label: t('sessions.share.target.user'), icon: 'user' },
      { value: 'team', label: t('sessions.share.target.team'), icon: 'users' },
      { value: 'link', label: t('sessions.share.target.link'), icon: 'link' },
    ],
    onChange: (v) => {
      replace(targetBox, v === 'user' ? email : v === 'team' ? teamSel : linkNote);
      if (!approvalTouched) approval.input.checked = v === 'link';
    },
  });
  const perm = segmented({
    name: `perm-${session.id}`,
    label: t('sessions.share.permission'),
    value: 'view',
    options: [
      { value: 'view', label: permissionLabel('view'), icon: 'eye' },
      { value: 'control', label: permissionLabel('control'), icon: 'keyboard' },
    ],
    onChange: (v) => {
      autoGrant.input.disabled = v !== 'control';
      if (v !== 'control') autoGrant.input.checked = false;
    },
  });
  const expiry = field({ label: t('sessions.share.expiry'), name: 'expiry', options: expiryOptions(), value: '' });
  const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, icon('share', { size: 16 }), t('sessions.share.submit'));
  const form = h('form', { class: 'form', novalidate: true },
    error,
    h('div', { class: 'field' }, h('span', { class: 'label' }, t('sessions.share.with_whom')), target),
    targetBox,
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('span', { class: 'label' }, t('sessions.share.permission')), perm,
        h('div', { class: 'hint' }, t('sessions.share.permission_hint'))),
      expiry),
    h('div', { class: 'share-options' }, approval, autoGrant),
    h('div', null, submit));

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    const kind = target.value;
    const body = {
      permission: perm.value,
      require_approval: approval.input.checked,
      auto_grant: perm.value === 'control' && autoGrant.input.checked,
    };
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
        changed();
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

/** People inside a session: `participants` (protocol 2) or the older `viewers`. */
function peopleOf(s) {
  if (Array.isArray(s.participants)) return s.participants.filter((p) => !p.waiting);
  return s.viewers || [];
}

function viewersStack(s) {
  const people = peopleOf(s);
  if (!people.length) return h('span', null, icon('eye', { size: 14 }), t('sessions.nobody_connected'));
  return h('span', { title: people.map((v) => v.name).join(', ') },
    h('span', { class: 'avatar-stack' }, people.slice(0, 4).map((v) => avatar(v.name, v.user_id || v.id, 'sm'))),
    t('sessions.viewers', { count: people.length }));
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
      viewersStack(s),
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
      viewersStack(s)),
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
