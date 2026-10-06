// Vaults: the ones you can use (personal, shared and team vaults) with your
// role, owner, members and item counts; and creating a new one. Also the
// pieces the vault and team pages share (labels, tiles, the create dialog).
//
// Items (hosts, keys, snippets...) are added and edited from the apps; the
// web manages who has access to each vault.
//
// `color` and `icon` of a vault are free text on the server; the apps use a
// `#rrggbb` color and an icon name from VAULT_ICONS (anything else shows the
// default vault icon).

import { h, replace } from '../../dom.js';
import { icon } from '../../icons.js';
import { api } from '../../api.js';
import { navigate } from '../../router.js';
import { pageHead, loadingState, errorState, emptyState, badge, field, formDialog, toast, alertBox } from '../../ui.js';
import { t, has } from '../../i18n.js';

/** Colors offered for a vault (the value stored is the hex code). */
export const VAULT_COLORS = [
  ['green', '#7d9a2c'],
  ['teal', '#14b8a6'],
  ['blue', '#3b82f6'],
  ['purple', '#8b5cf6'],
  ['pink', '#ec4899'],
  ['red', '#ef4444'],
  ['orange', '#f97316'],
  ['yellow', '#eab308'],
  ['gray', '#64748b'],
];

/** Icons offered for a vault (names of icons.js). */
export const VAULT_ICONS = ['vault', 'server', 'key', 'users', 'shield', 'terminal', 'globe', 'lock'];

/** Item kinds, in the order they are listed. */
export const ITEM_KINDS = ['host', 'group', 'identity', 'key', 'snippet', 'forward', 'known_host', 'memory'];

/** Rank of a vault role (never compare them as text). */
export const VAULT_RANK = { unknown: 0, use_only: 1, editor: 2, manager: 3 };

export const rankOf = (role) => VAULT_RANK[role] || 0;

/** Name of a vault: the personal one is translated, not stored per language. */
export function vaultName(v) {
  if (!v) return '—';
  if (v.kind === 'personal' && (!v.name || v.name === 'Personal')) return t('vaults.personal_name');
  return v.name || '—';
}

/** Readable role (`manager`, `editor`, `use_only`; unknown values: no access). */
export function vaultRoleLabel(role) {
  return has(`vaults.role.${role}`) ? t(`vaults.role.${role}`) : t('vaults.role.unknown');
}

/** Badge of a role: managers accent, Use only with a lock. */
export function vaultRoleBadge(role, { prefix = false } = {}) {
  const label = prefix ? t('vault.your_role', { role: vaultRoleLabel(role) }) : vaultRoleLabel(role);
  if (role === 'manager') return badge(label, 'accent', 'crown');
  if (role === 'use_only') return badge(label, 'warn', 'lock');
  if (role === 'editor') return badge(label, 'info', 'edit');
  return badge(label);
}

/** Readable kind: personal, shared or team. */
export function vaultKindLabel(kind) {
  return has(`vaults.kind.${kind}`) ? t(`vaults.kind.${kind}`) : kind || '—';
}

const HEX = /^#[0-9a-f]{6}$/i;

/** Square tile with the vault's icon in its color. */
export function vaultTile(v, { size = 19, large = false } = {}) {
  const name = v && VAULT_ICONS.includes(v.icon) ? v.icon : v && v.kind === 'personal' ? 'user' : v && v.kind === 'team' ? 'users' : 'vault';
  const tile = h('span', { class: ['icon-tile', 'vault-tile', large && 'icon-tile-lg'], 'aria-hidden': 'true' }, icon(name, { size: large ? 24 : size }));
  if (v && HEX.test(v.color || '')) tile.style.setProperty('--vault-color', v.color);
  return tile;
}

/** "3 hosts · 1 key" from `item_counts`, or "Empty". */
export function itemCountsText(counts) {
  const parts = ITEM_KINDS.filter((k) => counts && counts[k] > 0).map((k) => t(`vaults.items.${k}`, { count: counts[k] }));
  return parts.length ? parts.join(' · ') : t('vaults.items.empty');
}

/** Total of items of a vault. */
export function itemTotal(counts) {
  return Object.values(counts || {}).reduce((a, b) => a + (Number(b) || 0), 0);
}

/** Owner line: "Owner: Ana" / "Team: Infra". */
export function ownerText(v) {
  if (v.kind === 'personal') return t('vaults.owner_you');
  if (v.kind === 'team') return t('vaults.owner_team', { name: v.owner_name || '—' });
  return t('vaults.owner', { name: v.owner_name || '—' });
}

/** `<select>` options of the colors (with "No color"). */
export function colorOptions() {
  return [{ value: '', label: t('vaults.color.none') }, ...VAULT_COLORS.map(([k, hex]) => ({ value: hex, label: t(`vaults.color.${k}`) }))];
}

/** `<select>` options of the icons (the first one is the default). */
export function iconOptions() {
  return [{ value: '', label: t('vaults.icon.default') }, ...VAULT_ICONS.map((k) => ({ value: k, label: t(`vaults.icon.${k}`) }))];
}

/** Options of the role of a team's plain members. */
export function teamRoleOptions({ none = false } = {}) {
  const opts = [{ value: 'editor', label: t('vaults.role.editor') }, { value: 'use_only', label: t('vaults.role.use_only') }];
  if (none) opts.push({ value: '', label: t('vault.team_role.none') });
  return opts;
}

/**
 * Dialog to create a vault: shared (yours) or owned by a team where you are
 * owner or admin (`teams`: the result of GET /teams). `teamId` preselects a
 * team. Resolves with the created vault (or nothing).
 */
export function createVaultDialog({ teams = [], teamId = null, go = true } = {}) {
  return new Promise((resolve) => {
    const manageable = teams.filter((team) => team.role === 'owner' || team.role === 'admin');
    const name = field({ label: t('common.name'), name: 'name', required: true, maxlength: 80, placeholder: t('vaults.create.name_placeholder'), autocomplete: 'off' });
    const description = field({ label: t('vaults.create.description'), name: 'description', maxlength: 500, autocomplete: 'off' });
    const owner = field({
      label: t('vaults.create.owner'),
      name: 'owner',
      options: [{ value: '', label: t('vaults.create.owner_me') }, ...manageable.map((team) => ({ value: team.id, label: t('vaults.create.owner_team', { name: team.name }) }))],
      value: teamId || '',
      hint: t('vaults.create.owner_hint'),
    });
    const teamRole = field({ label: t('vaults.create.team_member_role'), name: 'team_member_role', options: teamRoleOptions(), value: 'editor', hint: t('vaults.create.team_member_role_hint') });
    const color = field({ label: t('vaults.create.color'), name: 'color', options: colorOptions(), value: '' });
    const ico = field({ label: t('vaults.create.icon'), name: 'icon', options: iconOptions(), value: '' });
    const syncOwner = () => {
      teamRole.hidden = !owner.input.value;
    };
    owner.input.addEventListener('change', syncOwner);
    syncOwner();
    if (!manageable.length) owner.hidden = true;
    let created = null;
    const dlg = formDialog({
      title: t('vaults.create.title'),
      description: t('vaults.create.text'),
      iconName: 'vault',
      fields: [name, description, owner, teamRole, h('div', { class: 'form-row' }, color, ico)],
      submitLabel: t('vaults.create.submit'),
      onSubmit: async () => {
        const body = { name: name.input.value.trim() };
        if (description.input.value.trim()) body.description = description.input.value.trim();
        if (color.input.value) body.color = color.input.value;
        if (ico.input.value) body.icon = ico.input.value;
        if (owner.input.value) {
          body.team_id = owner.input.value;
          body.team_member_role = teamRole.input.value;
        }
        created = await api.post('/vaults', body);
        toast(t('vaults.create.done', { name: created.name }), 'success');
      },
    });
    dlg.el.addEventListener('close', () => {
      resolve(created);
      if (created && go) navigate(`/app/vaults/${created.id}`);
    });
  });
}

/** Card of a vault in a list. */
export function vaultCard(v) {
  return h('a', { class: 'card card-link vault-card', href: `/app/vaults/${v.id}` },
    h('div', { class: 'row-between' },
      h('div', { class: 'row grow' },
        vaultTile(v),
        h('div', { class: 'grow' },
          h('h3', { class: 'break' }, vaultName(v)),
          h('span', { class: 'small muted' }, ownerText(v)))),
      icon('chevron-right', { size: 18, class: 'faint' })),
    h('div', { class: 'row-wrap mt-16' },
      badge(vaultKindLabel(v.kind), v.kind === 'team' ? 'info' : '', v.kind === 'team' ? 'users' : v.kind === 'shared' ? 'share' : 'user'),
      vaultRoleBadge(v.role),
      v.kind !== 'personal' ? h('span', { class: 'small muted' }, t('vaults.members', { count: v.member_count || 0 })) : null),
    h('p', { class: 'small muted mt-8 vault-counts' }, itemCountsText(v.item_counts)));
}

export function render(ctx) {
  const body = h('div', null, loadingState(t('vaults.loading')));
  let teams = [];
  const create = () => createVaultDialog({ teams });
  const createBtn = h('button', { class: 'btn btn-primary', type: 'button', onclick: create }, icon('plus', { size: 16 }), t('vaults.new'));

  const load = async () => {
    try {
      const [vaults, myTeams] = await Promise.all([api.get('/vaults'), api.get('/teams').catch(() => [])]);
      if (!ctx.alive()) return;
      teams = myTeams.filter((team) => team.role);
      const others = vaults.filter((v) => v.kind !== 'personal');
      replace(body, h('div', { class: 'stack-lg' },
        h('div', { class: 'grid grid-2' }, vaults.map(vaultCard)),
        others.length ? null : h('div', { class: 'card' }, emptyState({
          iconName: 'vault',
          title: t('vaults.empty.title'),
          text: t('vaults.empty.text'),
          action: h('button', { class: 'btn btn-primary', type: 'button', onclick: create }, icon('plus', { size: 16 }), t('vaults.new')),
        })),
        alertBox({ kind: 'info', iconName: 'info', text: t('vaults.apps_note') })));
    } catch (e) {
      if (ctx.alive()) replace(body, errorState(e, load));
    }
  };
  load();
  return h('div', { class: 'stack-lg' },
    pageHead({ title: t('vaults.title'), subtitle: t('vaults.subtitle'), actions: [createBtn] }),
    body);
}
