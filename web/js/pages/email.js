// Email links: verify the email (/verify-email?token=...) and confirm an
// email change (/confirm-email?token=...).

import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { isLoggedIn, loadMe, currentUser } from '../session.js';
import { stripQuery } from '../router.js';
import { busy, toast, toastError, loadingState, capitalize } from '../ui.js';
import { t, tx, errorText } from '../i18n.js';

// Result of each kind of link in this page load (the token is removed from
// the URL, so re-renders reuse it).
const results = {};

function head(title, text, iconName, kind = '') {
  return h('div', { class: 'auth-head' },
    h('span', { class: ['icon-tile icon-tile-lg', kind && `${kind}-tile`] }, icon(iconName, { size: 24 })),
    h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, title),
    text ? h('p', null, text) : null);
}

function continueButton() {
  return isLoggedIn()
    ? h('a', { class: 'btn btn-primary btn-lg btn-block', href: '/app' }, t('common.go_to_app'), icon('arrow-right', { size: 16 }))
    : h('a', { class: 'btn btn-primary btn-lg btn-block', href: '/login' }, t('common.sign_in'));
}

function resendButton() {
  if (!isLoggedIn()) return null;
  const btn = h('button', { class: 'btn btn-block', type: 'button' }, icon('send', { size: 15 }), t('verify_email.resend'));
  btn.addEventListener('click', () => busy(btn, async () => {
    try {
      const r = await api.post('/me/verify-email');
      toast(t('verify_email.resent', { email: r.email }), 'success');
    } catch (e) {
      toastError(e);
    }
  }));
  return btn;
}

function tokenFlow(ctx, kind, { endpoint, success, failure }) {
  const token = ctx.query.get('token');
  if (token) {
    stripQuery('token');
    results[kind] = api.post(endpoint, { token }, { auth: false });
  }
  const card = h('div', { class: 'auth-card' }, loadingState(t('verify_email.checking')));
  const pending = results[kind];
  if (!pending) {
    replace(card, head(t('verify_email.no_token_title'), t('verify_email.no_token_text'), 'mail'), continueButton());
    return card;
  }
  pending.then(async (r) => {
    // When signed in, reload the account (verified or new email).
    if (isLoggedIn()) await loadMe().catch(() => {});
    replace(card, success(r));
  }).catch((e) => {
    replace(card, failure(e));
  });
  return card;
}

/** /verify-email */
export function verify(ctx) {
  return tokenFlow(ctx, 'verify', {
    endpoint: '/auth/verify-email',
    success: (r) => [
      head(t('verify_email.done_title'), null, 'check-circle'),
      h('div', { class: 'stack' },
        h('p', { class: 'muted' }, tx('verify_email.done_text', { email: h('strong', null, r.email) })),
        continueButton()),
    ],
    failure: (e) => {
      const u = currentUser();
      const already = u && u.email_verified;
      return [
        head(already ? t('verify_email.already_title') : t('verify_email.failed_title'), already ? null : capitalize(errorText(e)), already ? 'check-circle' : 'alert', already ? '' : 'danger'),
        h('div', { class: 'stack' },
          already ? null : h('p', { class: 'muted small' }, t('verify_email.failed_hint')),
          already ? null : resendButton(),
          continueButton()),
      ];
    },
  });
}

/** /confirm-email */
export function confirm(ctx) {
  return tokenFlow(ctx, 'confirm', {
    endpoint: '/auth/confirm-email',
    success: (r) => [
      head(t('confirm_email.done_title'), null, 'check-circle'),
      h('div', { class: 'stack' },
        h('p', { class: 'muted' }, tx('confirm_email.done_text', { email: h('strong', null, r.email) })),
        continueButton()),
    ],
    failure: (e) => [
      head(t('confirm_email.failed_title'), capitalize(errorText(e)), 'alert', 'danger'),
      h('div', { class: 'stack' },
        h('p', { class: 'muted small' }, t('confirm_email.failed_hint')),
        isLoggedIn() ? h('a', { class: 'btn btn-primary btn-block', href: '/app/account' }, t('confirm_email.go_to_account')) : continueButton()),
    ],
  });
}
