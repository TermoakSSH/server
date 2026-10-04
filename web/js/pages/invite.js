// Invitation to create an account (/invite/{token}): shows which team it
// invites to, locks the email when the invitation is bound to one and reuses
// the sign-up form.

import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { isLoggedIn, currentUser, signOut, loadMe } from '../session.js';
import { refresh } from '../router.js';
import { relTime, absTime } from '../format.js';
import { loadingState, alertBox, busy, capitalize } from '../ui.js';
import { signupForm } from './signup.js';
import { t, tx, errorText } from '../i18n.js';

export function render(ctx) {
  const token = ctx.params.token;
  const card = h('div', { class: 'auth-card auth-card-wide' }, loadingState(t('invite.checking')));

  const load = async () => {
    let inv;
    try {
      inv = await api.get(`/invites/${encodeURIComponent(token)}`, { auth: false });
    } catch (e) {
      if (!ctx.alive()) return;
      replace(card,
        h('div', { class: 'auth-head' },
          h('span', { class: 'icon-tile icon-tile-lg danger-tile' }, icon('ticket', { size: 24 })),
          h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, t('invite.invalid_title')),
          h('p', null, e.status === 404 ? t('invite.invalid_text') : capitalize(errorText(e)))),
        h('div', { class: 'stack-sm' },
          h('a', { class: 'btn btn-primary btn-block', href: '/login' }, t('common.sign_in')),
          h('a', { class: 'btn btn-block', href: '/' }, t('invite.go_home'))));
      return;
    }
    if (!ctx.alive()) return;
    const title = inv.team
      ? tx('invite.title_team', { team: h('span', { class: 'accent' }, t('invite.team_quoted', { team: inv.team })) })
      : t('invite.title');
    const appLink = `termoak://invite?server=${encodeURIComponent(location.origin)}&token=${encodeURIComponent(token)}`;

    let body;
    if (isLoggedIn()) {
      if (!currentUser()) await loadMe().catch(() => {});
      const u = currentUser();
      const out = h('button', { class: 'btn btn-block', type: 'button' }, icon('logout', { size: 15 }), t('invite.sign_out_and_create'));
      out.addEventListener('click', () => busy(out, async () => {
        await signOut();
        refresh();
      }));
      body = h('div', { class: 'stack' },
        alertBox({
          kind: 'info',
          title: u ? t('invite.signed_in_as', { email: u.email }) : t('invite.signed_in_unknown'),
          text: inv.team
            ? t('invite.signed_in_team_text')
            : t('invite.signed_in_text'),
        }),
        h('a', { class: 'btn btn-primary btn-block', href: '/app' }, t('common.go_to_app')),
        out);
    } else {
      body = signupForm({ invite: token, inviteLocked: true, lockedEmail: inv.email || null, next: '/app', submitLabel: t('invite.submit') });
    }

    replace(card,
      h('div', { class: 'auth-head' },
        h('span', { class: 'icon-tile icon-tile-lg' }, icon(inv.team ? 'users' : 'ticket', { size: 24 })),
        h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, title),
        h('p', null, isLoggedIn() ? t('invite.subtitle_signed_in') : t('invite.subtitle')),
        inv.expires_at ? h('p', { class: 'small faint', title: absTime(inv.expires_at) }, icon('clock', { size: 13, class: 'inline-ico' }), ` ${t('invite.expires', { when: relTime(inv.expires_at) })}`) : null),
      body,
      h('div', { class: 'divider-text mt-24' }, t('invite.or')),
      h('div', { class: 'stack-sm mt-16' },
        h('a', { class: 'btn btn-block', href: appLink, 'data-external': '' }, icon('external', { size: 15 }), t('invite.open_in_app')),
        h('p', { class: 'small faint center' }, tx('invite.no_app', { link: h('a', { href: 'https://termoak.com/download', target: '_blank', rel: 'noopener' }, t('invite.no_app_link')) }))));
  };
  load();
  return card;
}
