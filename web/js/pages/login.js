// Sign in, with the two-step verification step on the same page when the
// server answers `totp_required`.

import { h } from '../dom.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { signIn, registrationOpen, state } from '../session.js';
import { navigate, safeNext } from '../router.js';
import { deviceName } from '../format.js';
import { field, errorBox, busy, toast } from '../ui.js';
import { t, tx } from '../i18n.js';
import { toCheckEmail, checkEmailPath } from './verify.js';

export function render(ctx) {
  const next = safeNext(ctx.query.get('next'));
  const error = errorBox();

  const email = field({ label: t('common.email'), name: 'email', type: 'email', autocomplete: 'username', required: true, value: ctx.query.get('email') || '', spellcheck: 'false', autocapitalize: 'none' });
  const password = field({
    label: t('common.password'),
    name: 'password',
    type: 'password',
    autocomplete: 'current-password',
    required: true,
    labelExtra: h('a', { href: '/forgot-password' }, t('login.forgot_link')),
  });

  // 2FA step: hidden until the server asks for it.
  let recovery = false;
  const code = field({
    label: t('login.totp.code_label'),
    name: 'totp_code',
    type: 'text',
    autocomplete: 'one-time-code',
    inputmode: 'numeric',
    maxlength: 6,
    code: true,
    hint: t('login.totp.code_hint'),
  });
  const toggleRecovery = h('button', { type: 'button', class: 'link-btn small' }, t('login.totp.use_recovery'));
  toggleRecovery.addEventListener('click', () => {
    recovery = !recovery;
    const input = code.input;
    input.value = '';
    input.inputMode = recovery ? 'text' : 'numeric';
    input.maxLength = recovery ? 32 : 6;
    input.placeholder = recovery ? 'xxxx-xxxx' : '';
    code.querySelector('label').textContent = recovery ? t('login.totp.recovery_label') : t('login.totp.code_label');
    code.querySelector('.hint').textContent = recovery
      ? t('login.totp.recovery_hint')
      : t('login.totp.code_hint');
    toggleRecovery.textContent = recovery ? t('login.totp.use_app') : t('login.totp.use_recovery');
    input.focus();
  });
  const who = h('strong');
  const back = h('button', { type: 'button', class: 'link-btn small' }, t('login.totp.switch_account'));
  const totpStep = h('div', { class: 'stack', hidden: true },
    h('div', { class: 'alert' }, icon('shield-check', { size: 19 }),
      h('div', { class: 'alert-body' },
        h('div', { class: 'alert-title' }, t('login.totp.title')),
        h('div', null, tx('login.totp.text', { email: who })))),
    code,
    h('div', { class: 'row-between' }, toggleRecovery, back));

  const credentials = h('div', { class: 'stack' }, email, password);
  const submit = h('button', { class: 'btn btn-primary btn-lg btn-block', type: 'submit' }, t('common.sign_in'));
  const form = h('form', { class: 'form', novalidate: true }, error, credentials, totpStep, submit);

  const showTotp = (show) => {
    totpStep.hidden = !show;
    credentials.hidden = show;
    submit.textContent = show ? t('login.totp.submit') : t('common.sign_in');
    code.input.required = show;
    if (show) {
      who.textContent = email.input.value.trim();
      code.input.focus();
    } else {
      code.input.value = '';
      password.input.focus();
    }
  };
  back.addEventListener('click', () => {
    error.hide();
    showTotp(false);
  });
  // Submits by itself once the 6 digits are typed.
  code.input.addEventListener('input', () => {
    if (!recovery) code.input.value = code.input.value.replace(/\D/g, '').slice(0, 6);
    if (!recovery && code.input.value.length === 6) form.requestSubmit();
  });

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    if (!form.reportValidity()) return;
    busy(submit, async () => {
      const body = {
        email: email.input.value.trim(),
        password: password.input.value,
        device_name: deviceName(),
        platform: 'web',
      };
      if (!totpStep.hidden) body.totp_code = code.input.value.trim();
      try {
        const resp = await api.post('/auth/login', body, { auth: false });
        // The email is not confirmed yet: the code screen (it signs in).
        if (resp.verification_required) {
          await toCheckEmail(resp, { next, from: 'login' });
          return;
        }
        await signIn(resp);
        toast(t('login.welcome_back', { name: resp.user.name || resp.user.email }), 'success');
        navigate(next, { replace: true });
      } catch (err) {
        if (err.code === 'email_not_verified') {
          navigate(checkEmailPath(body.email, { next, from: 'login' }));
        } else if (err.code === 'totp_required') {
          showTotp(true);
        } else if (err.code === 'totp_invalid') {
          error.show(err);
          code.input.value = '';
          code.input.focus();
        } else if (err.status === 401 && err.code === 'unauthorized' && totpStep.hidden) {
          error.show(t('login.error.invalid_credentials'));
          password.input.select();
        } else {
          error.show(err);
          if (err.status === 401 && totpStep.hidden) password.input.select();
        }
      }
    });
  });

  const info = state.info || {};
  return h('div', { class: 'auth-card' },
    h('div', { class: 'auth-head' },
      h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, t('login.title')),
      h('p', null, t('login.subtitle'))),
    form,
    h('p', { class: 'auth-foot' },
      registrationOpen()
        ? tx('login.no_account', { link: h('a', { href: next !== '/app' ? `/signup?next=${encodeURIComponent(next)}` : '/signup' }, t('login.no_account_link')) })
        : info.needs_setup ? null : t('login.no_account_closed')));
}
