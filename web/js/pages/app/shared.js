// Pieces shared by the app pages: creating teams and session state badges.

import { h } from '../../dom.js';
import { api } from '../../api.js';
import { navigate } from '../../router.js';
import { sessionStateInfo } from '../../format.js';
import { badge, field, formDialog, toast } from '../../ui.js';
import { t } from '../../i18n.js';

/** Dialog to create a team. Resolves with the created team (or nothing). */
export function createTeamDialog({ go = true } = {}) {
  return new Promise((resolve) => {
    const name = field({ label: t('teams.create.name'), name: 'name', required: true, maxlength: 80, placeholder: t('teams.create.name_placeholder'), autocomplete: 'off' });
    let created = null;
    const dlg = formDialog({
      title: t('teams.create.title'),
      description: t('teams.create.description'),
      iconName: 'users',
      fields: [name],
      submitLabel: t('teams.create.submit'),
      onSubmit: async () => {
        created = await api.post('/teams', { name: name.input.value.trim() });
        toast(t('teams.create.done', { name: created.name }), 'success');
      },
    });
    dlg.el.addEventListener('close', () => {
      resolve(created);
      if (created && go) navigate(`/app/teams/${created.id}`);
    });
  });
}

/** Badge with the state of a session. */
export function stateBadge(stateValue) {
  const st = sessionStateInfo(stateValue);
  const el = badge(st.label, st.kind);
  if (st.live) el.prepend(h('span', { class: 'dot dot-live' }));
  return el;
}
