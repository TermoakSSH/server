// Team page: members and their roles, inviting by email, pending
// invitations, renaming, deleting and leaving.
//
// Permissions (the server checks them too):
// - member < admin < owner. A server administrator acts as owner.
// - admin: manages members and invitations, and renames.
// - owner: also appoints owners, manages other owners and deletes.

import { h, replace } from '../../dom.js';
import { icon } from '../../icons.js';
import { api } from '../../api.js';
import { currentUser, state } from '../../session.js';
import { navigate } from '../../router.js';
import { roleLabel, ROLE_RANK, relTime, absTime } from '../../format.js';
import {
  pageHead, loadingState, errorState, badge, timeEl, toast, toastError, busy, confirmDialog, formDialog,
  field, avatar, errorBox, copyField, alertBox, emptyState,
} from '../../ui.js';
import { t, tx, getLanguage } from '../../i18n.js';

function roleOptions(acting) {
  const opts = [{ value: 'member', label: roleLabel('member') }, { value: 'admin', label: roleLabel('admin') }];
  if (acting === 'owner') opts.push({ value: 'owner', label: roleLabel('owner') });
  return opts;
}

export function render(ctx) {
  const id = ctx.params.id;
  const me = currentUser();
  const root = h('div', { class: 'stack-lg' }, loadingState(t('team.loading')));

  let team = null;
  let members = [];
  let acting = null; // effective role: your own, or owner if you are a server admin

  const load = async () => {
    try {
      const data = await api.get(`/teams/${id}`);
      if (!ctx.alive()) return;
      team = data.team;
      members = data.members;
      acting = me.is_admin ? 'owner' : team.role;
      ctx.setTitle(team.name);
      draw();
    } catch (e) {
      if (!ctx.alive()) return;
      replace(root,
        h('a', { class: 'back-link', href: '/app/teams' }, icon('arrow-left', { size: 16 }), t('teams.title')),
        h('div', { class: 'card' }, e.status === 404
          ? emptyState({ iconName: 'users', title: t('team.not_found.title'), text: t('team.not_found.text'), action: h('a', { class: 'btn', href: '/app/teams' }, t('team.not_found.action')) })
          : errorState(e, load)));
    }
  };

  const canManage = () => ROLE_RANK[acting] >= ROLE_RANK.admin;
  const isOwner = () => acting === 'owner';

  // --- Team actions ----------------------------------------------------

  const rename = () => {
    const name = field({ label: t('common.name'), name: 'name', required: true, value: team.name, maxlength: 80 });
    formDialog({
      title: t('team.rename.title'),
      fields: [name],
      submitLabel: t('common.save'),
      onSubmit: async () => {
        team = { ...team, ...(await api.patch(`/teams/${id}`, { name: name.input.value.trim() })) };
        toast(t('team.rename.done'), 'success');
        ctx.setTitle(team.name);
        draw();
      },
    });
  };

  const remove = async () => {
    const ok = await confirmDialog({
      title: t('team.delete.title', { name: team.name }),
      message: t('team.delete.message'),
      confirmLabel: t('team.delete.confirm'),
      danger: true,
      typed: team.name,
    });
    if (!ok) return;
    try {
      await api.del(`/teams/${id}`);
      toast(t('team.delete.done', { name: team.name }), 'success');
      navigate('/app/teams');
    } catch (e) {
      toastError(e);
    }
  };

  const leave = async () => {
    const ok = await confirmDialog({
      title: t('team.leave.title', { name: team.name }),
      message: t('team.leave.message'),
      confirmLabel: t('team.leave.confirm'),
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(`/teams/${id}/members/${me.id}`);
      toast(t('team.leave.done', { name: team.name }), 'success');
      navigate('/app/teams');
    } catch (e) {
      toastError(e);
    }
  };

  // --- Members ------------------------------------------------------------------

  const memberRow = (m) => {
    const self = m.user_id === me.id;
    // You can edit a member if you manage the team and, for owners, only as an owner.
    const editable = !self && canManage() && (m.role !== 'owner' || isOwner());
    let roleEl;
    if (editable) {
      const sel = h('select', { class: 'select select-sm', 'aria-label': t('team.member.role_of', { name: m.name || m.email }) },
        roleOptions(acting).map((o) => h('option', { value: o.value }, o.label)));
      sel.value = m.role;
      sel.addEventListener('change', async () => {
        const prev = m.role;
        sel.disabled = true;
        try {
          members = await api.patch(`/teams/${id}/members/${m.user_id}`, { role: sel.value });
          toast(t('team.member.role_changed', { name: m.name || m.email, role: roleLabel(sel.value) }), 'success');
          draw();
        } catch (e) {
          sel.value = prev;
          toastError(e);
        } finally {
          sel.disabled = false;
        }
      });
      roleEl = sel;
    } else {
      roleEl = badge(roleLabel(m.role), m.role === 'owner' ? 'accent' : m.role === 'admin' ? 'info' : '', m.role === 'owner' ? 'crown' : null);
    }
    let removeBtn = null;
    if (editable) {
      removeBtn = h('button', { class: 'btn btn-sm btn-ghost btn-icon', type: 'button', 'aria-label': t('team.member.remove_aria', { name: m.name || m.email }), title: t('team.member.remove_title') }, icon('trash', { size: 16 }));
      removeBtn.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: t('team.member.remove_title'),
          message: t('team.member.remove_message', { name: m.name || m.email, team: team.name }),
          confirmLabel: t('common.remove'),
          danger: true,
        });
        if (!ok) return;
        try {
          await api.del(`/teams/${id}/members/${m.user_id}`);
          toast(t('team.member.removed', { name: m.name || m.email }), 'success');
          load();
        } catch (e) {
          toastError(e);
        }
      });
    }
    return h('div', { class: 'list-item' },
      avatar(m.name, m.email),
      h('div', { class: 'list-item-main' },
        h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, m.name || m.email), self ? badge(t('common.you')) : null),
        h('div', { class: 'list-item-meta' }, h('span', { class: 'break' }, m.email), h('span', null, tx('team.member.since', { time: timeEl(m.added_at) })))),
      h('div', { class: 'list-item-actions keep-inline' }, roleEl, removeBtn));
  };

  // --- Invite -----------------------------------------------------------------

  const inviteCard = (pending) => {
    const error = errorBox();
    const result = h('div');
    const email = field({ label: t('common.email'), name: 'email', type: 'email', required: true, placeholder: t('team.invite.email_placeholder'), autocomplete: 'off' });
    const role = field({ label: t('team.invite.role'), name: 'role', options: roleOptions(acting), value: 'member' });
    const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, icon('send', { size: 16 }), t('team.invite.submit'));
    const form = h('form', { class: 'form', novalidate: true },
      error,
      h('div', { class: 'form-row' }, email, role),
      h('div', null, submit));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      error.hide();
      if (!form.reportValidity()) return;
      const address = email.input.value.trim();
      busy(submit, async () => {
        try {
          const r = await api.post(`/teams/${id}/invites`, { email: address, role: role.input.value });
          email.input.value = '';
          if (r.added) {
            members = r.members;
            toast(t('team.invite.added', { email: address }), 'success');
            draw();
            return;
          }
          const link = r.web_url || r.url;
          replace(result, h('div', { class: 'share-result', role: 'status' },
            h('div', { class: 'row' }, icon(r.emailed ? 'mail' : 'link', { size: 18, class: 'accent' }),
              h('strong', null, r.emailed ? t('team.invite.sent', { email: address }) : t('team.invite.created', { email: address }))),
            h('p', { class: 'small' }, r.emailed
              ? t('team.invite.emailed_note')
              : state.info && state.info.features && state.info.features.email
                ? t('team.invite.email_failed_note')
                : t('team.invite.no_email_note')),
            copyField(link, { label: t('team.invite.link') }),
            r.web_url ? copyField(r.url, { label: t('team.invite.app_link') }) : null));
          loadPending(pending);
        } catch (err) {
          error.show(err);
        }
      });
    });
    return h('section', { class: 'card', id: 'invite', 'aria-labelledby': 'invite-title' },
      h('div', { class: 'card-head' },
        h('div', null, h('h2', { class: 'card-title', id: 'invite-title' }, t('team.invite.title')),
          h('p', { class: 'card-sub' }, t('team.invite.subtitle')))),
      h('div', { class: 'stack' }, form, result));
  };

  const loadPending = async (box) => {
    try {
      const invites = await api.get(`/teams/${id}/invites`);
      if (!ctx.alive()) return;
      if (!invites.length) {
        replace(box, h('p', { class: 'small muted' }, t('team.pending.empty')));
        return;
      }
      replace(box, h('div', { class: 'card card-flush' }, h('div', { class: 'list' }, invites.map((inv) => {
        const revoke = h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button' }, t('common.revoke'));
        revoke.addEventListener('click', async () => {
          const ok = await confirmDialog({ title: t('team.pending.revoke_title'), message: inv.email ? t('team.pending.revoke_message', { email: inv.email }) : t('team.pending.revoke_message_anonymous'), confirmLabel: t('common.revoke'), danger: true });
          if (!ok) return;
          busy(revoke, async () => {
            try {
              await api.del(`/teams/${id}/invites/${inv.id}`);
              toast(t('team.pending.revoked'), 'success');
              loadPending(box);
            } catch (e) {
              toastError(e);
            }
          });
        });
        return h('div', { class: 'list-item' },
          h('span', { class: 'icon-tile muted-tile' }, icon('mail', { size: 17 })),
          h('div', { class: 'list-item-main' },
            h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, inv.email || t('team.pending.no_email')), badge(roleLabel(inv.team_role || 'member'))),
            h('div', { class: 'list-item-meta' },
              h('span', null, tx('team.pending.sent', { time: timeEl(inv.created_at) })),
              h('span', { title: inv.expires_at ? absTime(inv.expires_at) : null }, inv.expires_at ? t('team.pending.expires', { time: relTime(inv.expires_at) }) : t('team.pending.no_expiry')))),
          h('div', { class: 'list-item-actions keep-inline' }, revoke));
      }))));
    } catch (e) {
      if (ctx.alive()) replace(box, errorState(e, () => loadPending(box)));
    }
  };

  // --- Drawing -------------------------------------------------------------------

  function draw() {
    const actions = [];
    if (canManage()) actions.push(h('button', { class: 'btn', type: 'button', onclick: rename }, icon('edit', { size: 15 }), t('common.rename')));
    if (team.role) actions.push(h('button', { class: 'btn', type: 'button', onclick: leave }, icon('logout', { size: 15 }), t('team.leave.action')));
    if (isOwner()) actions.push(h('button', { class: 'btn btn-danger-ghost', type: 'button', onclick: remove }, icon('trash', { size: 15 }), t('common.delete')));

    const sorted = [...members].sort((a, b) => (ROLE_RANK[b.role] - ROLE_RANK[a.role]) || (a.name || a.email).localeCompare(b.name || b.email, getLanguage()));
    const pending = h('div', null, loadingState());

    replace(root,
      pageHead({
        back: { href: '/app/teams', label: t('teams.title') },
        title: team.name,
        subtitle: h('span', { class: 'row-wrap' },
          team.role ? badge(t('team.your_role', { role: roleLabel(team.role) }), team.role === 'owner' ? 'accent' : 'info') : badge(t('teams.server_admin'), 'info', 'shield-check'),
          h('span', { class: 'small muted' }, t('teams.members', { count: members.length }))),
        actions,
      }),
      h('section', { class: 'section', 'aria-labelledby': 'members-title' },
        h('div', { class: 'section-head' }, h('h2', { id: 'members-title' }, t('team.members.title'), h('span', { class: 'count' }, String(members.length)))),
        h('div', { class: 'card card-flush' }, h('div', { class: 'list' }, sorted.map(memberRow))),
        !canManage() ? h('p', { class: 'small muted' }, t('team.members.manage_note')) : null),
      canManage() ? inviteCard(pending) : null,
      canManage()
        ? h('section', { class: 'section', 'aria-labelledby': 'pending-title' },
          h('div', { class: 'section-head' }, h('h2', { id: 'pending-title' }, t('team.pending.title'))),
          pending)
        : null,
      alertBox({ kind: 'info', iconName: 'share', text: t('team.share_hint') }));
    if (canManage()) loadPending(pending);
    if (location.hash === '#invite') {
      const el = document.getElementById('invite');
      if (el) {
        el.scrollIntoView();
        const input = el.querySelector('input');
        if (input) input.focus();
      }
    }
  }

  load();
  return root;
}
