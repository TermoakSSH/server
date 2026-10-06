// Vault page: its items (read-only: they are edited from the apps), its
// members and their roles, sharing with a person or a team, the Strict
// switch, the role of a team's members, and renaming, leaving and deleting.
// (The activity of a vault is in the full web and the apps.)
//
// Permissions (the server checks them too):
// - use_only < editor < manager. Managers are computed: the owner of a shared
//   vault, the owners and admins of the team of a team vault.
// - Members see the vault, its items (never their secrets on the web) and
//   its members. Managers also share, change roles, switch Strict, edit and
//   delete.
// - The personal vault cannot be shared, left or deleted.

import { h, replace } from '../../dom.js';
import { icon } from '../../icons.js';
import { api } from '../../api.js';
import { currentUser } from '../../session.js';
import { navigate } from '../../router.js';
import {
  pageHead, loadingState, errorState, badge, timeEl, toast, toastError, busy, confirmDialog, formDialog,
  field, avatar, errorBox, alertBox, emptyState, switchInput,
} from '../../ui.js';
import { t, tx, getLanguage } from '../../i18n.js';
import {
  vaultName, vaultRoleLabel, vaultRoleBadge, vaultKindLabel, vaultTile, itemCountsText, itemTotal, ownerText,
  colorOptions, iconOptions, teamRoleOptions, rankOf, ITEM_KINDS,
} from './vaults.js';

/** Options of a grant's role. */
function grantOptions() {
  return [{ value: 'editor', label: vaultRoleLabel('editor') }, { value: 'use_only', label: vaultRoleLabel('use_only') }];
}

/** Name of a member (user or team). */
function principalName(p) {
  if (!p) return '—';
  if (p.type === 'team') return p.name || t('vault.member.team_unknown');
  return p.name || p.email || '—';
}

/** "user@address:port" of a host. */
function hostAddress(host) {
  const s = host.settings || {};
  return `${s.username ? `${s.username}@` : ''}${host.address || ''}${s.port && s.port !== 22 ? `:${s.port}` : ''}`;
}

export function render(ctx) {
  const id = ctx.params.id;
  const me = currentUser();
  const root = h('div', { class: 'stack-lg' }, loadingState(t('vault.loading')));

  let vault = null;
  let members = [];
  let teams = [];

  const isManager = () => vault && vault.role === 'manager';
  const isPersonal = () => vault && vault.kind === 'personal';
  const directGrant = () => members.find((m) => !m.implicit && m.principal && m.principal.type === 'user' && m.principal.id === me.id);

  const notFound = (e) => {
    replace(root,
      h('a', { class: 'back-link', href: '/app/vaults' }, icon('arrow-left', { size: 16 }), t('vaults.title')),
      h('div', { class: 'card' }, e.status === 404
        ? emptyState({ iconName: 'vault', title: t('vault.not_found.title'), text: t('vault.not_found.text'), action: h('a', { class: 'btn', href: '/app/vaults' }, t('vault.not_found.action')) })
        : errorState(e, load)));
  };

  async function load() {
    try {
      const v = await api.get(`/vaults/${id}`);
      const [list, myTeams] = await Promise.all([
        v.kind === 'personal' ? [] : api.get(`/vaults/${id}/members`),
        api.get('/teams').catch(() => []),
      ]);
      if (!ctx.alive()) return;
      vault = { ...v, item_counts: v.item_counts || {} };
      members = list;
      teams = myTeams.filter((team) => team.role);
      ctx.setTitle(vaultName(vault));
      draw();
    } catch (e) {
      if (ctx.alive()) notFound(e);
    }
  }

  // Reloads after a change (members, settings); keeps the page if it fails.
  const reload = () => load().catch(() => {});

  // --- Vault actions ------------------------------------------------------

  const edit = () => {
    const personal = isPersonal();
    const name = field({ label: t('common.name'), name: 'name', required: true, maxlength: 80, value: vaultName(vault), autocomplete: 'off' });
    const description = personal ? null : field({ label: t('vaults.create.description'), name: 'description', maxlength: 500, value: vault.description || '', autocomplete: 'off' });
    const color = field({ label: t('vaults.create.color'), name: 'color', options: colorOptions(), value: vault.color || '' });
    const ico = field({ label: t('vaults.create.icon'), name: 'icon', options: iconOptions(), value: vault.icon || '' });
    formDialog({
      title: t('vault.edit.title'),
      iconName: 'edit',
      fields: [name, description, h('div', { class: 'form-row' }, color, ico)].filter(Boolean),
      submitLabel: t('common.save'),
      onSubmit: async () => {
        const body = { color: color.input.value || null, icon: ico.input.value || null };
        const typed = name.input.value.trim();
        // The personal vault keeps its stored name unless it really changes.
        if (!personal || typed !== vaultName(vault)) body.name = typed;
        if (description) body.description = description.input.value.trim();
        const v = await api.patch(`/vaults/${id}`, body);
        vault = { ...v, item_counts: v.item_counts || {} };
        toast(t('vault.edit.done'), 'success');
        ctx.setTitle(vaultName(vault));
        draw();
      },
    });
  };

  const remove = async () => {
    const total = itemTotal(vault.item_counts);
    const ok = await confirmDialog({
      title: t('vault.delete.title', { name: vault.name }),
      message: h('div', { class: 'stack-sm' },
        h('p', null, t('vault.delete.message')),
        h('ul', { class: 'danger-list' },
          h('li', null, total ? t('vault.delete.items', { items: itemCountsText(vault.item_counts) }) : t('vault.delete.no_items')),
          vault.member_count ? h('li', null, t('vault.delete.members', { count: vault.member_count })) : null,
          vault.kind === 'team' ? h('li', null, t('vault.delete.team_members')) : null)),
      confirmLabel: t('vault.delete.confirm'),
      danger: true,
      typed: vault.name,
    });
    if (!ok) return;
    try {
      await api.del(`/vaults/${id}`, undefined, { query: { confirm: vault.name } });
      toast(t('vault.delete.done', { name: vault.name }), 'success');
      navigate('/app/vaults');
    } catch (e) {
      toastError(e);
    }
  };

  const leave = async () => {
    const ok = await confirmDialog({
      title: t('vault.leave.title', { name: vaultName(vault) }),
      message: t('vault.leave.message'),
      confirmLabel: t('vault.leave.confirm'),
      danger: true,
    });
    if (!ok) return;
    try {
      await api.post(`/vaults/${id}/leave`);
      toast(t('vault.leave.done', { name: vaultName(vault) }), 'success');
      navigate('/app/vaults');
    } catch (e) {
      toastError(e);
    }
  };

  // --- Items ------------------------------------------------------------------

  const itemsSection = () => {
    const counts = vault.item_counts || {};
    const list = h('div', null, loadingState());
    const loadHosts = async () => {
      try {
        const hosts = await api.get('/hosts', { query: { vault_id: id } });
        if (!ctx.alive()) return;
        if (!hosts.length) {
          replace(list, h('p', { class: 'small muted' }, t('vault.items.no_hosts')));
          return;
        }
        const sorted = [...hosts].sort((a, b) => (a.label || '').localeCompare(b.label || '', getLanguage()));
        replace(list, h('div', { class: 'card card-flush' }, h('div', { class: 'list', dataset: { vaultHosts: '' } }, sorted.map((host) => h('div', { class: 'list-item', dataset: { hostId: host.id } },
          h('span', { class: 'icon-tile muted-tile' }, icon('server', { size: 17 })),
          h('div', { class: 'list-item-main' },
            h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, host.label || host.address),
              host.secret_hidden ? badge(t('vault.items.use_only_badge'), 'warn', 'lock') : null),
            h('div', { class: 'list-item-meta' }, h('span', { class: 'break mono' }, hostAddress(host)),
              host.updated_at ? h('span', null, tx('vault.items.updated', { time: timeEl(host.updated_at) })) : null)))))));
      } catch (e) {
        if (ctx.alive()) replace(list, errorState(e, loadHosts));
      }
    };
    loadHosts();
    const kinds = ITEM_KINDS.filter((k) => counts[k] > 0);
    return h('section', { class: 'section', 'aria-labelledby': 'items-title' },
      h('div', { class: 'section-head' }, h('h2', { id: 'items-title' }, t('vault.items.title'), h('span', { class: 'count' }, String(itemTotal(counts))))),
      kinds.length
        ? h('div', { class: 'stat-row vault-stats' }, kinds.map((k) => h('div', { class: 'stat', dataset: { kind: k } },
          h('strong', null, String(counts[k])), h('span', null, t(`vaults.kind_name.${k}`, { count: counts[k] })))))
        : null,
      h('h3', { class: 'admin-section-title' }, t('vault.items.hosts_title')),
      list,
      vault.role === 'use_only'
        ? alertBox({ kind: 'warn', iconName: 'lock', title: t('vault.items.use_only_title'), text: vault.settings && vault.settings.use_only_local === false ? t('vault.items.use_only_strict') : t('vault.items.use_only_text') })
        : h('p', { class: 'small muted' }, t('vault.items.apps_note')));
  };

  // --- Members ------------------------------------------------------------------

  const implicitNote = (m) => {
    if (m.principal.type === 'team') return t('vault.member.team_members', { team: m.principal.name || '—' });
    return vault.kind === 'team' ? t('vault.member.team_admin') : t('vault.member.owner');
  };

  const memberRow = (m) => {
    const p = m.principal || {};
    const isTeam = p.type === 'team';
    const self = !isTeam && p.id === me.id;
    const name = principalName(p);
    const editable = isManager() && !m.implicit;
    let roleEl;
    if (editable) {
      const sel = h('select', { class: 'select select-sm', 'aria-label': t('vault.member.role_of', { name }) },
        grantOptions().map((o) => h('option', { value: o.value }, o.label)));
      sel.value = m.role;
      sel.addEventListener('change', async () => {
        const prev = m.role;
        sel.disabled = true;
        try {
          const updated = await api.patch(`/vaults/${id}/members/${m.id}`, { role: sel.value });
          m.role = updated.role;
          toast(t('vault.member.role_changed', { name, role: vaultRoleLabel(updated.role) }), 'success');
          reload();
        } catch (e) {
          sel.value = prev;
          toastError(e);
        } finally {
          sel.disabled = false;
        }
      });
      roleEl = sel;
    } else {
      roleEl = vaultRoleBadge(m.role);
    }
    let removeBtn = null;
    if (editable) {
      removeBtn = h('button', { class: 'btn btn-sm btn-ghost btn-icon', type: 'button', 'aria-label': t('vault.member.remove_aria', { name }), title: t('vault.member.remove_title') }, icon('trash', { size: 16 }));
      removeBtn.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: t('vault.member.remove_title'),
          message: t(isTeam ? 'vault.member.remove_message_team' : 'vault.member.remove_message', { name, vault: vault.name }),
          confirmLabel: t('common.remove'),
          danger: true,
        });
        if (!ok) return;
        try {
          await api.del(`/vaults/${id}/members/${m.id}`);
          toast(t('vault.member.removed', { name }), 'success');
          reload();
        } catch (e) {
          toastError(e);
        }
      });
    }
    const meta = [];
    if (!isTeam && p.email && p.name) meta.push(h('span', { class: 'break' }, p.email));
    if (isTeam && !m.implicit) meta.push(h('span', null, t('vault.member.team')));
    if (m.implicit) meta.push(h('span', null, implicitNote(m)));
    else if (m.added_at) meta.push(h('span', null, tx('vault.member.since', { time: timeEl(m.added_at) })));
    return h('div', { class: 'list-item', dataset: { memberId: m.id, principal: p.id || '' } },
      isTeam ? h('span', { class: 'icon-tile muted-tile' }, icon('users', { size: 17 })) : avatar(p.name, p.email),
      h('div', { class: 'list-item-main' },
        h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, name), self ? badge(t('common.you')) : null),
        h('div', { class: 'list-item-meta' }, meta)),
      h('div', { class: 'list-item-actions keep-inline nowrap-actions' }, roleEl, removeBtn));
  };

  const addCard = () => {
    const error = errorBox();
    const options = [{ value: 'user', label: t('vault.add.person') }];
    if (teams.length) options.push({ value: 'team', label: t('vault.add.team') });
    const kind = field({ label: t('vault.add.with'), name: 'kind', options, value: 'user' });
    const email = field({ label: t('common.email'), name: 'email', type: 'email', required: true, placeholder: t('team.invite.email_placeholder'), autocomplete: 'off' });
    const team = field({ label: t('vault.add.team_label'), name: 'team_id', options: teams.map((x) => ({ value: x.id, label: x.name })) });
    const role = field({ label: t('vault.add.role'), name: 'role', options: grantOptions(), value: 'editor' });
    const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, icon('user-plus', { size: 16 }), t('vault.add.submit'));
    const sync = () => {
      const byTeam = kind.input.value === 'team';
      email.hidden = byTeam;
      email.input.required = !byTeam;
      team.hidden = !byTeam;
    };
    kind.input.addEventListener('change', sync);
    if (options.length < 2) kind.hidden = true;
    sync();
    const form = h('form', { class: 'form', novalidate: true },
      error,
      h('div', { class: 'form-row' }, kind, email, team, role),
      h('ul', { class: 'small muted role-help' },
        h('li', null, h('strong', null, vaultRoleLabel('editor')), ': ', t('vault.roles.editor')),
        h('li', null, h('strong', null, vaultRoleLabel('use_only')), ': ', t('vault.roles.use_only'))),
      h('div', null, submit));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      error.hide();
      if (!form.reportValidity()) return;
      const byTeam = kind.input.value === 'team';
      const body = byTeam ? { team_id: team.input.value, role: role.input.value } : { email: email.input.value.trim(), role: role.input.value };
      busy(submit, async () => {
        try {
          const m = await api.post(`/vaults/${id}/members`, body);
          email.input.value = '';
          toast(t('vault.add.added', { name: principalName(m.principal), role: vaultRoleLabel(m.role) }), 'success');
          reload();
        } catch (err) {
          error.show(err);
        }
      });
    });
    return h('section', { class: 'card', id: 'share', 'aria-labelledby': 'share-title' },
      h('div', { class: 'card-head' },
        h('div', null, h('h2', { class: 'card-title', id: 'share-title' }, t('vault.add.title')),
          h('p', { class: 'card-sub' }, t('vault.add.subtitle')))),
      form);
  };

  // --- Settings: Strict and the team's role ------------------------------------------

  const settingsCard = () => {
    const strict = !!(vault.settings && vault.settings.use_only_local === false);
    const sw = switchInput({
      label: t('vault.strict.label'),
      checked: strict,
      disabled: !isManager(),
      onChange: async (on, input) => {
        input.disabled = true;
        try {
          const v = await api.patch(`/vaults/${id}`, { settings: { ...(vault.settings || {}), use_only_local: !on } });
          vault = { ...v, item_counts: v.item_counts || {} };
          toast(on ? t('vault.strict.on') : t('vault.strict.off'), 'success');
          reload();
        } catch (e) {
          input.checked = !on;
          toastError(e);
        } finally {
          input.disabled = !isManager();
        }
      },
    });
    sw.input.setAttribute('aria-describedby', 'strict-help');
    let teamRole = null;
    if (vault.kind === 'team') {
      const sel = field({
        label: t('vault.team_role.title'),
        name: 'team_member_role',
        options: teamRoleOptions({ none: true }),
        value: vault.team_member_role || '',
        disabled: !isManager(),
        hint: t('vault.team_role.hint', { team: vault.owner_name || '—' }),
      });
      sel.input.addEventListener('change', async () => {
        const prev = vault.team_member_role || '';
        sel.input.disabled = true;
        try {
          const v = await api.patch(`/vaults/${id}`, { team_member_role: sel.input.value || null });
          vault = { ...v, item_counts: v.item_counts || {} };
          toast(t('vault.team_role.saved'), 'success');
          reload();
        } catch (e) {
          sel.input.value = prev;
          toastError(e);
        } finally {
          sel.input.disabled = !isManager();
        }
      });
      teamRole = sel;
    }
    return h('section', { class: 'card', 'aria-labelledby': 'settings-title' },
      h('div', { class: 'card-head' }, h('div', null, h('h2', { class: 'card-title', id: 'settings-title' }, t('vault.settings.title')))),
      h('div', { class: 'stack' },
        h('div', { class: 'toggle-list' },
          sw,
          h('p', { class: 'small muted', id: 'strict-help' }, t('vault.strict.help'))),
        teamRole,
        isManager() ? null : h('p', { class: 'small muted' }, t('vault.settings.managers_only'))));
  };

  // --- Drawing -------------------------------------------------------------------

  function draw() {
    const actions = [];
    if (isManager()) actions.push(h('button', { class: 'btn', type: 'button', onclick: edit }, icon('edit', { size: 15 }), t('common.edit')));
    if (!isPersonal() && directGrant()) actions.push(h('button', { class: 'btn', type: 'button', onclick: leave }, icon('logout', { size: 15 }), t('vault.leave.action')));
    if (isManager() && !isPersonal()) actions.push(h('button', { class: 'btn btn-danger-ghost', type: 'button', onclick: remove }, icon('trash', { size: 15 }), t('common.delete')));

    const sorted = [...members].sort((a, b) => (Number(b.implicit) - Number(a.implicit))
      || (rankOf(b.role) - rankOf(a.role))
      || principalName(a.principal).localeCompare(principalName(b.principal), getLanguage()));

    replace(root,
      pageHead({
        back: { href: '/app/vaults', label: t('vaults.title') },
        title: h('span', { class: 'row vault-title' }, vaultTile(vault), h('span', { class: 'break' }, vaultName(vault))),
        subtitle: h('span', { class: 'row-wrap' },
          badge(vaultKindLabel(vault.kind), vault.kind === 'team' ? 'info' : '', vault.kind === 'team' ? 'users' : vault.kind === 'shared' ? 'share' : 'user'),
          vaultRoleBadge(vault.role, { prefix: true }),
          h('span', { class: 'small muted' }, ownerText(vault))),
        actions,
      }),
      vault.description ? h('p', { class: 'muted break' }, vault.description) : null,
      isPersonal() ? alertBox({ kind: 'info', iconName: 'lock', text: t('vault.personal_note') }) : null,
      itemsSection(),
      isPersonal()
        ? null
        : h('section', { class: 'section', 'aria-labelledby': 'members-title' },
          h('div', { class: 'section-head' }, h('h2', { id: 'members-title' }, t('vault.members.title'), h('span', { class: 'count' }, String(members.length)))),
          h('div', { class: 'card card-flush' }, h('div', { class: 'list', dataset: { vaultMembers: '' } }, sorted.map(memberRow))),
          !isManager() ? h('p', { class: 'small muted' }, t('vault.members.manage_note')) : null),
      !isPersonal() && isManager() ? addCard() : null,
      !isPersonal() ? settingsCard() : null);
  }

  load();
  return root;
}
