// "Check your email": the 6-digit code the server emails when an account
// needs its address confirmed (/check-email?email=...&next=...&from=login).
// The right code confirms the email and signs in. The link in the same email
// keeps working (/verify-email).

import { h, replace } from '../dom.js';
import { icon } from '../icons.js';
import { api } from '../api.js';
import { signIn } from '../session.js';
import { navigate, safeNext } from '../router.js';
import { deviceName } from '../format.js';
import { field, errorBox, busy, toast } from '../ui.js';
import { t, tx } from '../i18n.js';

/** Seconds between two codes (the server allows one per minute). */
const COOLDOWN_S = 60;
/** When a code can be asked for again, per email (survives re-renders). */
const resendAt = new Map();

/** Path of this screen. `from`: `signup` (default) or `login`. */
export function checkEmailPath(email, { next = '/app', from = 'signup' } = {}) {
  const q = new URLSearchParams({ email });
  if (next && next !== '/app') q.set('next', next);
  if (from === 'login') q.set('from', 'login');
  return `/check-email?${q}`;
}

/**
 * After a registration or sign-in that answered `verification_required`:
 * its tokens only reach the account itself, so the device is signed out
 * right away (the code signs in properly) and the code screen opens.
 */
export async function toCheckEmail(resp, { next = '/app', from = 'signup' } = {}) {
  const access = resp.tokens && resp.tokens.access_token;
  if (access) {
    try {
      await fetch('/api/v1/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${access}`, 'Content-Type': 'application/json' },
        body: '{}',
        credentials: 'omit',
      });
    } catch {
      // Unused tokens expire by themselves.
    }
  }
  const email = (resp.user && resp.user.email) || '';
  resendAt.set(email.toLowerCase(), Date.now() + COOLDOWN_S * 1000);
  navigate(checkEmailPath(email, { next, from }), { replace: true });
}

function head(title, text, iconName) {
  return h('div', { class: 'auth-head' },
    h('span', { class: 'icon-tile icon-tile-lg' }, icon(iconName, { size: 24 })),
    h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, title),
    text ? h('p', null, text) : null);
}

/** Only digits, at most `max` (pasted codes may have spaces or dashes). */
function digits(value, max = 6) {
  return String(value || '').replace(/\D/g, '').slice(0, max);
}

/** Numeric code input: strips everything but digits, also when pasting. */
function codeField(opts, onComplete) {
  const f = field({
    type: 'text',
    autocomplete: 'one-time-code',
    inputmode: 'numeric',
    pattern: '[0-9]*',
    maxlength: 6,
    code: true,
    spellcheck: 'false',
    autocapitalize: 'none',
    ...opts,
  });
  const input = f.input;
  input.addEventListener('paste', (e) => {
    const text = e.clipboardData && e.clipboardData.getData('text');
    if (!text) return;
    e.preventDefault();
    input.value = digits(text);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  input.addEventListener('input', () => {
    const clean = digits(input.value);
    if (clean !== input.value) input.value = clean;
    if (clean.length === 6) onComplete();
  });
  return f;
}

function clock(seconds) {
  const m = Math.floor(seconds / 60);
  const s = String(seconds % 60).padStart(2, '0');
  return `${m}:${s}`;
}

/** /check-email */
export function render(ctx) {
  const email = (ctx.query.get('email') || '').trim();
  const next = safeNext(ctx.query.get('next'));
  const fromLogin = ctx.query.get('from') === 'login';
  const withNext = (path) => (next !== '/app' ? `${path}?next=${encodeURIComponent(next)}` : path);
  const card = h('div', { class: 'auth-card' });

  if (!email) {
    replace(card,
      head(t('check_email.title'), t('check_email.no_email_text'), 'mail'),
      h('a', { class: 'btn btn-primary btn-lg btn-block', href: withNext('/login') }, t('common.sign_in')));
    return card;
  }

  const key = email.toLowerCase();
  const error = errorBox();
  const submit = h('button', { class: 'btn btn-primary btn-lg btn-block', type: 'submit' }, t('check_email.submit'));
  const form = h('form', { class: 'form', novalidate: true });
  const send = () => {
    if (!submit.classList.contains('is-busy')) form.requestSubmit();
  };

  const code = codeField({ label: t('check_email.code_label'), name: 'code', required: true, hint: t('check_email.link_hint') }, () => {
    if (totp.hidden || digits(totp.input.value).length === 6) send();
  });
  // Two-step verification: only when the account already has it turned on.
  const totp = codeField({ label: t('login.totp.code_label'), name: 'totp_code', hint: t('login.totp.code_hint') }, send);
  totp.hidden = true;

  form.append(error, code, totp, submit);

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    const value = digits(code.input.value);
    if (value.length !== 6) {
      error.show(t('check_email.error.six_digits'));
      code.input.focus();
      return;
    }
    busy(submit, async () => {
      const body = { email, code: value, device_name: deviceName(), platform: 'web' };
      if (!totp.hidden) body.totp_code = totp.input.value.trim();
      try {
        const resp = await api.post('/auth/verify-code', body, { auth: false });
        resendAt.delete(key);
        await signIn(resp);
        toast(t('check_email.verified', { name: resp.user.name || resp.user.email }), 'success');
        navigate(next, { replace: true });
      } catch (err) {
        if (err.code === 'totp_required') {
          totp.hidden = false;
          totp.input.required = true;
          totp.input.focus();
        } else if (err.code === 'totp_invalid') {
          error.show(err);
          totp.input.value = '';
          totp.input.focus();
        } else {
          error.show(err);
          if (err.code === 'invalid_code') {
            code.input.value = '';
            code.input.focus();
          }
        }
      }
    });
  });

  // "Resend code", with a countdown while the server would refuse it.
  const resend = h('button', { type: 'button', class: 'btn btn-block' });
  let timer = null;
  let shown = false;
  const stop = () => {
    clearInterval(timer);
    timer = null;
  };
  const paint = () => {
    // The page was left: stop counting.
    if (card.isConnected) shown = true;
    else if (shown) return stop();
    const left = Math.max(0, Math.ceil(((resendAt.get(key) || 0) - Date.now()) / 1000));
    resend.disabled = left > 0 || resend.classList.contains('is-busy');
    replace(resend, icon('send', { size: 15 }), left > 0 ? t('check_email.resend_in', { time: clock(left) }) : t('check_email.resend'));
    if (left <= 0 && timer) stop();
    return undefined;
  };
  const cooldown = (seconds) => {
    resendAt.set(key, Date.now() + Math.max(1, Number(seconds) || COOLDOWN_S) * 1000);
    if (!timer) timer = setInterval(paint, 1000);
    paint();
  };
  resend.addEventListener('click', async () => {
    if (resend.disabled) return;
    error.hide();
    resend.classList.add('is-busy');
    resend.setAttribute('aria-busy', 'true');
    resend.disabled = true;
    try {
      const r = await api.post('/auth/resend-code', { email }, { auth: false });
      resend.classList.remove('is-busy');
      cooldown((r && r.resend_after) || COOLDOWN_S);
      toast(t('check_email.resent', { email }), 'success');
      code.input.value = '';
      code.input.focus();
    } catch (err) {
      resend.classList.remove('is-busy');
      const after = err.data && err.data.error && err.data.error.retry_after;
      if (err.status === 429) cooldown(after || COOLDOWN_S);
      else paint();
      error.show(err);
    } finally {
      resend.removeAttribute('aria-busy');
    }
  });
  // A code was just sent (sign-up, or sign-in with an expired one).
  if (!resendAt.has(key)) resendAt.set(key, Date.now() + COOLDOWN_S * 1000);
  if (resendAt.get(key) > Date.now()) timer = setInterval(paint, 1000);
  paint();

  replace(card,
    head(t('check_email.title'), tx(fromLogin ? 'check_email.text_login' : 'check_email.text', { email: h('strong', null, email) }), 'mail'),
    form,
    h('div', { class: 'stack mt-16' }, resend),
    h('p', { class: 'auth-foot' },
      h('a', { href: withNext(fromLogin ? '/login' : '/signup') }, t('check_email.different_email'))));
  queueMicrotask(() => code.input.focus());
  return card;
}
