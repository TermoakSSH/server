// Create an account. The form is also used on the invitation page.
//
// - With registration closed and no invitation, it explains how to get one
//   and lets you paste the code.
// - If the server has terms of use, they must be accepted.

import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { signIn, registrationOpen, state } from '../session.js';
import { navigate, safeNext } from '../router.js';
import { deviceName } from '../format.js';
import { field, errorBox, busy, toast, checkbox, passwordMeter, alertBox } from '../ui.js';
import { t, tx, getLanguage } from '../i18n.js';

/**
 * Sign-up form.
 * - `invite`: invitation code (sent with the registration).
 * - `lockedEmail`: fixed email (invitations bound to an email).
 * - `requireInvite`: the code is mandatory (registration closed).
 * - `inviteLocked`: the code is already applied and not shown.
 * - `next`: where to go afterwards.
 */
export function signupForm({ invite = '', lockedEmail = null, requireInvite = false, inviteLocked = false, next = '/app', submitLabel = null } = {}) {
  const info = state.info || {};
  const error = errorBox();
  const name = field({ label: t('common.name'), name: 'name', autocomplete: 'name', required: true, placeholder: t('signup.name_placeholder') });
  const email = field({
    label: t('common.email'),
    name: 'email',
    type: 'email',
    autocomplete: 'email',
    required: true,
    value: lockedEmail || '',
    readonly: !!lockedEmail,
    spellcheck: 'false',
    autocapitalize: 'none',
    hint: lockedEmail ? t('signup.email_locked_hint') : null,
  });
  const password = field({ label: t('common.password'), name: 'password', type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
  const meter = passwordMeter(password.input);

  // Invitation code: visible when prefilled or mandatory; otherwise behind
  // a link.
  const inviteField = field({
    label: t('signup.invite_label'),
    name: 'invite',
    value: invite,
    required: requireInvite,
    autocomplete: 'off',
    spellcheck: 'false',
    hint: requireInvite ? t('signup.invite_required_hint') : t('signup.invite_optional_hint'),
  });
  // On the invitation page the code is already applied and not shown.
  const inviteVisible = !inviteLocked && (!!invite || requireInvite);
  const inviteToggle = h('button', { type: 'button', class: 'link-btn small', 'aria-expanded': 'false' }, t('signup.have_invite'));
  inviteField.hidden = !inviteVisible;
  inviteToggle.hidden = inviteVisible || inviteLocked;
  inviteToggle.addEventListener('click', () => {
    inviteField.hidden = false;
    inviteToggle.hidden = true;
    inviteToggle.setAttribute('aria-expanded', 'true');
    inviteField.input.focus();
  });

  let terms = null;
  if (info.terms_url) {
    terms = checkbox({
      name: 'terms',
      required: true,
      label: info.privacy_url
        ? tx('signup.accept_terms_privacy', {
          terms: h('a', { href: info.terms_url, target: '_blank', rel: 'noopener noreferrer' }, t('signup.terms_link')),
          privacy: h('a', { href: info.privacy_url, target: '_blank', rel: 'noopener noreferrer' }, t('signup.privacy_link')),
        })
        : tx('signup.accept_terms', {
          terms: h('a', { href: info.terms_url, target: '_blank', rel: 'noopener noreferrer' }, t('signup.terms_link')),
        }),
    });
  }

  const submit = h('button', { class: 'btn btn-primary btn-lg btn-block', type: 'submit' }, submitLabel || t('common.sign_up'));
  const form = h('form', { class: 'form', novalidate: true },
    error, name, email, h('div', { class: 'stack-sm' }, password, meter), inviteField, inviteToggle, terms,
    info.privacy_url && !info.terms_url
      ? h('p', { class: 'small muted' }, tx('signup.accept_privacy_notice', { privacy: h('a', { href: info.privacy_url, target: '_blank', rel: 'noopener noreferrer' }, t('signup.privacy_link')) }))
      : null,
    submit);

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    if (password.input.value.length > 0 && password.input.value.length < 10) {
      error.show(t('signup.error.password_short', { min: 10 }));
      password.input.focus();
      return;
    }
    if (terms && !terms.input.checked) {
      error.show(t('signup.error.terms_required'));
      terms.input.focus();
      return;
    }
    if (!form.reportValidity()) return;
    busy(submit, async () => {
      try {
        const code = inviteField.input.value.trim();
        const resp = await api.post('/auth/register', {
          email: email.input.value.trim(),
          name: name.input.value.trim(),
          password: password.input.value,
          device_name: deviceName(),
          platform: 'web',
          invite: code || undefined,
          locale: getLanguage(),
        }, { auth: false });
        await signIn(resp);
        const f = (state.info && state.info.features) || {};
        if (!resp.user.email_verified && f.email_verification) {
          toast(t('signup.created_verify', { email: resp.user.email }), 'success', { timeout: 8000 });
        } else {
          toast(t('signup.welcome', { name: resp.user.name || resp.user.email }), 'success');
        }
        navigate(next, { replace: true });
      } catch (err) {
        error.show(err);
      }
    });
  });
  return form;
}

export function render(ctx) {
  const info = state.info || {};
  const next = safeNext(ctx.query.get('next'));
  const invite = (ctx.query.get('invite') || '').trim();
  const card = h('div', { class: 'auth-card' });
  const loginLink = h('p', { class: 'auth-foot' }, tx('signup.have_account', { link: h('a', { href: next !== '/app' ? `/login?next=${encodeURIComponent(next)}` : '/login' }, t('signup.have_account_link')) }));

  const showForm = (code) => {
    replace(card,
      h('div', { class: 'auth-head' },
        h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, info.needs_setup ? t('signup.setup_title') : t('signup.title')),
        h('p', null, info.needs_setup
          ? t('signup.setup_subtitle')
          : t('signup.subtitle'))),
      info.needs_setup ? h('div', { class: 'mb-16' }, alertBox({ kind: 'info', iconName: 'shield-check', text: t('signup.setup_note') })) : null,
      signupForm({ invite: code, requireInvite: !registrationOpen() && !info.needs_setup, next }),
      loginLink);
  };

  if (registrationOpen() || info.needs_setup || invite) {
    showForm(invite);
    return card;
  }

  // Registration closed and no invitation: explanation and a field for the code.
  const code = field({ label: t('signup.invite_label'), name: 'invite', required: true, autocomplete: 'off', spellcheck: 'false' });
  const form = h('form', { class: 'form', novalidate: true }, code, h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, t('common.continue'), icon('arrow-right', { size: 16 })));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!form.reportValidity()) return;
    showForm(code.input.value.trim());
  });
  replace(card,
    h('div', { class: 'auth-head' },
      h('span', { class: 'icon-tile icon-tile-lg warn-tile' }, icon('lock', { size: 24 })),
      h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, t('signup.closed_title')),
      h('p', null, t('signup.closed_text'))),
    form,
    loginLink);
  return card;
}
