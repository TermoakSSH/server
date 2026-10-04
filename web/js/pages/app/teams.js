// Teams: yours, with your role and members; and creating a new one.

import { h, replace } from '../../dom.js';
import { icon } from '../../icons.js';
import { api } from '../../api.js';
import { currentUser } from '../../session.js';
import { stripQuery } from '../../router.js';
import { roleLabel } from '../../format.js';
import { pageHead, loadingState, errorState, emptyState, badge, timeEl } from '../../ui.js';
import { t } from '../../i18n.js';
import { createTeamDialog } from './shared.js';

function teamCard(team) {
  return h('a', { class: 'card card-link', href: `/app/teams/${team.id}` },
    h('div', { class: 'row-between' },
      h('div', { class: 'row grow' },
        h('span', { class: 'icon-tile' }, icon('users', { size: 19 })),
        h('div', { class: 'grow' }, h('h3', { class: 'break' }, team.name), h('span', { class: 'small muted' }, t('teams.members', { count: team.member_count })))),
      icon('chevron-right', { size: 18, class: 'faint' })),
    h('div', { class: 'row-wrap mt-16' },
      team.role ? badge(roleLabel(team.role), team.role === 'owner' ? 'accent' : team.role === 'admin' ? 'info' : '', team.role === 'owner' ? 'crown' : null) : badge(t('teams.server_admin'), 'info', 'shield-check'),
      h('span', { class: 'small faint' }, tx('teams.created', { time: timeEl(team.created_at) }))));
}

export function render(ctx) {
  const u = currentUser();
  const body = h('div', null, loadingState(t('teams.loading')));
  const createBtn = h('button', { class: 'btn btn-primary', type: 'button', onclick: () => createTeamDialog() }, icon('plus', { size: 16 }), t('teams.new'));

  const load = async () => {
    try {
      const teams = await api.get('/teams');
      if (!ctx.alive()) return;
      // A server administrator may receive every team: only those they are a
      // member of are shown here.
      const mine = teams.filter((team) => team.role);
      const others = teams.length - mine.length;
      replace(body, h('div', { class: 'stack-lg' },
        mine.length
          ? h('div', { class: 'grid grid-2' }, mine.map(teamCard))
          : h('div', { class: 'card' }, emptyState({
            iconName: 'users',
            title: t('teams.empty.title'),
            text: t('teams.empty.text'),
            action: h('button', { class: 'btn btn-primary', type: 'button', onclick: () => createTeamDialog() }, icon('plus', { size: 16 }), t('teams.empty.action')),
          })),
        u.is_admin && others > 0
          ? h('p', { class: 'small muted' }, icon('shield-check', { size: 14, class: 'inline-ico' }), ' ', t('teams.admin_note.others', { count: others }))
          : null));
    } catch (e) {
      if (ctx.alive()) replace(body, errorState(e, load));
    }
  };
  load();
  if (ctx.query.get('create') === '1') {
    stripQuery('create');
    setTimeout(() => createTeamDialog(), 0);
  }
  return h('div', { class: 'stack-lg' },
    pageHead({ title: t('teams.title'), subtitle: t('teams.subtitle'), actions: [createBtn] }),
    body);
}
