// Password recovery: ask for the link by email (/forgot-password) and choose
// a new password with the received link (/reset-password?token=...).

import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api, tokens } from '../api.js';
import { state, emit } from '../session.js';
import { stripQuery } from '../router.js';
import { field, errorBox, busy, passwordMeter, alertBox } from '../ui.js';
import { t, tx } from '../i18n.js';

const RESET_KEY = 'termoak.reset_token';

function head(title, text, iconName) {
  return h('div', { class: 'auth-head' },
    iconName ? h('span', { class: 'icon-tile icon-tile-lg' }, icon(iconName, { size: 24 })) : null,
    h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, title),
    text ? h('p', null, text) : null);
}

/** /forgot-password */
export function forgot(ctx) {
  const card = h('div', { class: 'auth-card' });
  const features = (state.info && state.info.features) || {};
  const back = h('p', { class: 'auth-foot' }, h('a', { href: '/login' }, icon('arrow-left', { size: 14 }), ` ${t('password.back_to_login')}`));

  if (!features.email) {
    replace(card,
      head(t('password.forgot.title'), null, 'key'),
      alertBox({ kind: 'warn', title: t('password.forgot.no_email_title'), text: t('password.forgot.no_email_text') }),
      back);
    return card;
  }

  const error = errorBox();
  const email = field({ label: t('password.forgot.email_label'), name: 'email', type: 'email', autocomplete: 'email', required: true, value: ctx.query.get('email') || '', spellcheck: 'false', autocapitalize: 'none' });
  const submit = h('button', { class: 'btn btn-primary btn-lg btn-block', type: 'submit' }, t('password.forgot.submit'));
  const form = h('form', { class: 'form', novalidate: true }, error, email, submit);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    if (!form.reportValidity()) return;
    busy(submit, async () => {
      const address = email.input.value.trim();
      try {
        await api.post('/auth/forgot-password', { email: address }, { auth: false });
        replace(card,
          head(t('password.forgot.sent_title'), null, 'mail'),
          h('div', { class: 'stack' },
            h('p', { class: 'muted' }, tx('password.forgot.sent_text', { email: h('strong', null, address) })),
            h('p', { class: 'small faint' }, t('password.forgot.sent_hint'))),
          back);
      } catch (err) {
        error.show(err);
      }
    });
  });
  replace(card, head(t('password.forgot.title'), t('password.forgot.subtitle')), form, back);
  return card;
}

/** /reset-password?token=... */
export function reset(ctx) {
  // The token is removed from the URL as soon as it is read and kept in this tab.
  const fromUrl = ctx.query.get('token');
  if (fromUrl) {
    try {
      sessionStorage.setItem(RESET_KEY, fromUrl);
    } catch {
      /* no storage: it stays in memory */
    }
    stripQuery('token');
  }
  let token = fromUrl;
  if (!token) {
    try {
      token = sessionStorage.getItem(RESET_KEY);
    } catch {
      token = null;
    }
  }
  const card = h('div', { class: 'auth-card' });
  if (!token) {
    replace(card,
      head(t('password.reset.invalid_title'), t('password.reset.invalid_text'), 'alert'),
      h('a', { class: 'btn btn-primary btn-block', href: '/forgot-password' }, t('password.reset.request_new')));
    return card;
  }

  const error = errorBox();
  const password = field({ label: t('password.reset.new_label'), name: 'password', type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
  const repeat = field({ label: t('password.reset.repeat_label'), name: 'password2', type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
  const submit = h('button', { class: 'btn btn-primary btn-lg btn-block', type: 'submit' }, t('password.reset.submit'));
  const form = h('form', { class: 'form', novalidate: true }, error, h('div', { class: 'stack-sm' }, password, passwordMeter(password.input)), repeat, submit);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    if (password.input.value.length < 10) {
      error.show(t('password.error.too_short', { min: 10 }));
      return;
    }
    if (password.input.value !== repeat.input.value) {
      error.show(t('password.error.mismatch'));
      repeat.input.focus();
      return;
    }
    busy(submit, async () => {
      try {
        const r = await api.post('/auth/reset-password', { token, password: password.input.value }, { auth: false });
        try {
          sessionStorage.removeItem(RESET_KEY);
        } catch {
          /* nothing to do */
        }
        // The server signs out every device.
        tokens.clear();
        state.me = null;
        emit();
        replace(card,
          head(t('password.reset.done_title'), null, 'check-circle'),
          h('div', { class: 'stack' },
            h('p', { class: 'muted' }, t('password.reset.done_text')),
            h('a', { class: 'btn btn-primary btn-lg btn-block', href: `/login?email=${encodeURIComponent(r.email || '')}` }, t('common.sign_in'))));
      } catch (err) {
        error.show(err);
        // An invalid or expired link cannot be reused.
        if (/\b(link|enlace)\b/i.test(err.message || '')) {
          try {
            sessionStorage.removeItem(RESET_KEY);
          } catch {
            /* nothing to do */
          }
        }
      }
    });
  });
  replace(card, head(t('password.reset.title'), t('password.reset.subtitle', { min: 10 })), form);
  return card;
}
