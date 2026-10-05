// Shared session link (/join/{token}): session details, a button to open it
// in the app and, as an alternative, to join it in the browser. Guests
// without an account choose the name the others see (remembered in this
// browser); with a waiting room, the terminal shows it until the owner lets
// them in.

import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { isLoggedIn, state, loadMe } from '../session.js';
import { permissionLabel, relTime, absTime } from '../format.js';
import { loadingState, badge, capitalize, toastError, field } from '../ui.js';
import { stateBadge } from './app/shared.js';
import { savedGuestName, saveGuestName } from '../term/guest.js';
import { t, tx, errorText } from '../i18n.js';

function topBar() {
  return h('div', { class: 'auth-top' },
    h('a', { class: 'brand', href: '/', 'aria-label': t('join.brand_label') },
      h('img', { src: '/assets/icon.svg', alt: '', width: 30, height: 30 }),
      h('span', { class: 'brand-name' }, 'Term', h('span', null, 'oak'))),
    isLoggedIn()
      ? h('a', { class: 'btn btn-sm', href: '/app' }, t('common.go_to_app'))
      : h('a', { class: 'btn btn-ghost btn-sm', href: '/login' }, t('common.sign_in')));
}

/** Link that opens the session in the app (same format the server generates). */
export function joinAppLink(token) {
  return `termoak://join?server=${encodeURIComponent(location.origin)}&token=${encodeURIComponent(token)}`;
}

export function render(ctx) {
  const token = ctx.params.token;
  const page = h('div', { class: 'join-page' });
  const main = h('main', { class: 'auth-main', id: 'contenido' });
  const card = h('div', { class: 'auth-card auth-card-wide' }, loadingState(t('join.loading')));
  main.appendChild(card);
  page.append(topBar(), main);

  const load = async () => {
    let data;
    try {
      data = await api.get(`/join/${encodeURIComponent(token)}`, { auth: false });
    } catch (e) {
      if (!ctx.alive()) return;
      replace(card,
        h('div', { class: 'auth-head' },
          h('span', { class: 'icon-tile icon-tile-lg danger-tile' }, icon('link', { size: 24 })),
          h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, t('join.invalid_title')),
          h('p', null, e.status === 404 || e.code === 'invalid_link' ? t('join.invalid_text') : capitalize(errorText(e)))),
        h('a', { class: 'btn btn-block', href: '/' }, t('join.go_home')));
      return;
    }
    // Signed in: you join with your account (and its name).
    let account = null;
    if (isLoggedIn()) {
      try {
        account = state.me || await loadMe();
      } catch {
        account = null;
      }
    }
    if (!ctx.alive()) return;
    ctx.setTitle(t('join.page_title', { title: data.session.title }));
    const control = data.permission === 'control';
    // `participants` is a count (older servers sent a `viewers` list).
    const inside = typeof data.session.participants === 'number'
      ? data.session.participants
      : (data.session.viewers || []).length;
    const user = account && account.user;

    const name = user ? null : field({
      label: t('join.name.label'),
      name: 'name',
      maxlength: 40,
      autocomplete: 'nickname',
      placeholder: t('join.name.placeholder'),
      value: savedGuestName(),
      hint: t('join.name.hint'),
    });

    const openWeb = h('button', { class: 'btn btn-outline btn-block', type: 'submit' }, icon('globe', { size: 16 }), t('join.join_in_browser'));
    const form = h('form', { class: 'stack', novalidate: true }, name, openWeb);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const guestName = name ? name.input.value.replace(/\s+/g, ' ').trim().slice(0, 40) : '';
      if (name) saveGuestName(guestName);
      try {
        const { mountTerminal } = await import('../term/view.js');
        page.classList.add('is-terminal');
        replace(page, mountTerminal({
          wsPath: data.ws_path,
          withAccount: !!user,
          guestName: guestName || null,
          owner: data.owner,
          title: data.session.title,
          subtitle: t('join.shared_by_owner', { owner: data.owner }),
          back: { label: t('common.back'), onClick: () => { page.classList.remove('is-terminal'); replace(page, topBar(), main); } },
          onCleanup: ctx.onCleanup,
        }));
      } catch (err) {
        toastError(err, t('join.terminal_failed'));
      }
    });

    replace(card,
      h('div', { class: 'auth-head' },
        h('span', { class: 'icon-tile icon-tile-lg' }, icon('terminal', { size: 24 })),
        h('span', { class: 'small muted' }, t('join.invited_by', { owner: data.owner })),
        h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, data.session.title)),
      h('div', { class: 'stack' },
        h('div', { class: 'join-meta' },
          h('div', { class: 'join-meta-row' }, h('span', null, t('join.meta.shared_by')), h('strong', null, data.owner)),
          h('div', { class: 'join-meta-row' }, h('span', null, t('join.meta.permission')), badge(permissionLabel(data.permission), control ? 'warn' : 'info', control ? 'keyboard' : 'eye')),
          h('div', { class: 'join-meta-row' }, h('span', null, t('join.meta.entry')), h('span', null, data.require_approval ? t('join.meta.entry_approval') : t('join.meta.entry_direct'))),
          h('div', { class: 'join-meta-row' }, h('span', null, t('join.meta.state')), stateBadge(data.session.state)),
          h('div', { class: 'join-meta-row' }, h('span', null, t('join.meta.connected')), h('span', null, inside ? t('join.meta.people', { count: inside }) : t('join.meta.nobody'))),
          data.expires_at ? h('div', { class: 'join-meta-row' }, h('span', null, t('join.meta.expires')), h('span', { title: absTime(data.expires_at) }, relTime(data.expires_at))) : null),
        h('a', { class: 'btn btn-primary btn-lg btn-block', href: joinAppLink(token), 'data-external': '' }, icon('external', { size: 17 }), t('join.open_in_app')),
        user ? h('p', { class: 'small muted' }, t('join.as_account', { name: user.name || user.email })) : null,
        form,
        h('p', { class: 'small muted center' }, tx('join.no_app', { link: h('a', { href: 'https://termoak.com/download', target: '_blank', rel: 'noopener' }, t('join.no_app_link')) })),
        h('p', { class: 'small faint center' }, [
          control ? t('join.control_note') : t('join.view_note'),
          data.require_approval ? ` ${t('join.approval_note')}` : '',
        ].join(''))));
  };
  load();
  return page;
}
