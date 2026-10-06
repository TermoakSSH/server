// Reusable UI components: toasts, dialogs, confirmations, copy buttons, form
// fields, badges, loading/empty/error states, dropdown menus and the
// language picker.

import { h, clear, uid } from './dom.js';
import { icon } from './icons.js';
import { relTime, absTime, initials, hue } from './format.js';
import { t, tx, errorText, languages, getLanguage, setLanguage } from './i18n.js';

// --- Toasts ---------------------------------------------------------------

/**
 * Shows a short notice. `type`: `info`, `success` or `error`.
 * The region is `aria-live` so screen readers announce it.
 */
export function toast(message, type = 'info', { timeout } = {}) {
  const region = document.getElementById('toasts');
  if (!region) return;
  const ico = { success: 'check-circle', error: 'alert', info: 'info' }[type] || 'info';
  const close = () => {
    el.classList.add('is-leaving');
    setTimeout(() => el.remove(), 200);
  };
  const el = h('div', { class: ['toast', `toast-${type}`], role: type === 'error' ? 'alert' : 'status' },
    icon(ico, { size: 18 }),
    h('div', { class: 'toast-body' }, message),
    h('button', { class: 'toast-close', type: 'button', 'aria-label': t('ui.toast.close'), onclick: close }, icon('x', { size: 16 })),
  );
  region.appendChild(el);
  // At most 4 notices at a time.
  while (region.children.length > 4) region.firstElementChild.remove();
  setTimeout(close, timeout || (type === 'error' ? 7000 : 4500));
}

/**
 * Error notice: the translation of `error.<code>` or the API message
 * (`fallback` is a text shown when the error has no message).
 */
export function toastError(err, fallback = null) {
  const msg = err && (err.code || err.message) ? errorText(err) : fallback || t('error.generic_retry');
  toast(capitalize(msg), 'error');
}

/** Capitalizes the first letter (API messages may start in lowercase). */
export function capitalize(text) {
  const s = String(text || '');
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

// --- Dialogs -------------------------------------------------------------

/**
 * Opens a native modal dialog (`<dialog>`), with trapped focus and Escape.
 * Returns `{el, close}`. `body` can be a node or a list of nodes.
 */
export function openDialog({ title, description, body, actions = [], wide = false, iconName, iconKind, onClose, form = null }) {
  const titleId = uid('dlg-title');
  const descId = description ? uid('dlg-desc') : null;
  const closeBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-icon btn-sm dialog-close', 'aria-label': t('common.close') }, icon('x'));
  const head = h('div', { class: 'dialog-head' },
    iconName ? h('span', { class: ['icon-tile', iconKind ? `${iconKind}-tile` : ''] }, icon(iconName, { size: 20 })) : null,
    h('div', { class: 'stack-sm grow' },
      h('h2', { id: titleId }, title),
      description ? h('p', { id: descId, class: 'muted small' }, description) : null),
    closeBtn,
  );
  const content = [head, h('div', { class: 'dialog-body' }, body), actions.length ? h('div', { class: 'dialog-actions' }, actions) : null];
  const inner = form || h('div');
  for (const c of content) if (c) inner.appendChild(c);
  const dlg = h('dialog', { class: ['dialog', wide && 'dialog-wide'], 'aria-labelledby': titleId, 'aria-describedby': descId }, inner);
  const close = (value = '') => {
    if (dlg.open) dlg.close(value);
  };
  closeBtn.addEventListener('click', () => close('cancel'));
  // Click on the backdrop: close.
  dlg.addEventListener('mousedown', (e) => {
    if (e.target === dlg) {
      const r = dlg.getBoundingClientRect();
      const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
      if (!inside) close('cancel');
    }
  });
  dlg.addEventListener('close', () => {
    dlg.remove();
    if (onClose) onClose(dlg.returnValue);
  });
  document.body.appendChild(dlg);
  dlg.showModal();
  // Focus the first field, if any.
  const first = dlg.querySelector('input:not([type=hidden]):not([disabled]), select, textarea');
  if (first) first.focus();
  return { el: dlg, close };
}

/**
 * Confirmation (destructive actions). Returns a promise resolving to `true`
 * when confirmed. With `typed`, that text must be typed to confirm.
 */
export function confirmDialog({ title, message, confirmLabel = t('common.confirm'), cancelLabel = t('common.cancel'), danger = false, typed = null, iconName }) {
  return new Promise((resolve) => {
    let done = false;
    const confirmBtn = h('button', { type: 'submit', class: ['btn', danger ? 'btn-danger' : 'btn-primary'] }, confirmLabel);
    const cancelBtn = h('button', { type: 'button', class: 'btn' }, cancelLabel);
    const body = [];
    if (message) body.push(typeof message === 'string' ? h('p', null, message) : message);
    if (typed) {
      const input = h('input', { class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false', 'aria-label': t('ui.confirm.typed_aria', { text: typed }) });
      confirmBtn.disabled = true;
      input.addEventListener('input', () => {
        confirmBtn.disabled = input.value.trim() !== typed;
      });
      body.push(h('div', { class: 'field' }, h('label', null, tx('ui.confirm.typed_label', { text: h('code', null, typed) })), input));
    }
    const form = h('form', { method: 'dialog' });
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (confirmBtn.disabled) return;
      done = true;
      dlg.close('ok');
      resolve(true);
    });
    const dlg = openDialog({
      title,
      body,
      actions: [cancelBtn, confirmBtn],
      iconName: iconName || (danger ? 'alert' : null),
      iconKind: danger ? 'danger' : null,
      form,
      onClose: () => {
        if (!done) resolve(false);
      },
    });
    cancelBtn.addEventListener('click', () => dlg.close('cancel'));
    if (!typed) confirmBtn.focus();
  });
}

/**
 * Dialog with a form. `onSubmit(form)` may be async; if it throws, the error
 * is shown inside the dialog and it stays open.
 */
export function formDialog({ title, description, fields, submitLabel = t('common.save'), danger = false, wide = false, iconName, onSubmit }) {
  const error = errorBox();
  const submit = h('button', { type: 'submit', class: ['btn', danger ? 'btn-danger' : 'btn-primary'] }, submitLabel);
  const cancel = h('button', { type: 'button', class: 'btn' }, t('common.cancel'));
  const form = h('form', { novalidate: true });
  const dlg = openDialog({ title, description, body: [error, ...[].concat(fields)], actions: [cancel, submit], wide, form, iconName, iconKind: danger ? 'danger' : null });
  cancel.addEventListener('click', () => dlg.close('cancel'));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    error.hide();
    if (!form.reportValidity()) return;
    await busy(submit, async () => {
      try {
        const keep = await onSubmit(form, dlg);
        if (keep !== false) dlg.close('ok');
      } catch (err) {
        error.show(err);
      }
    });
  });
  return dlg;
}

// --- Buttons and copy -----------------------------------------------------

/** Runs `fn` with the button disabled and a loading indicator. */
export async function busy(button, fn) {
  if (!button) return fn();
  if (button.classList.contains('is-busy')) return undefined;
  const wasDisabled = button.disabled;
  button.classList.add('is-busy');
  button.setAttribute('aria-busy', 'true');
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.classList.remove('is-busy');
    button.removeAttribute('aria-busy');
    button.disabled = wasDisabled;
  }
}

/** Copies text to the clipboard (with a fallback for contexts without permission). */
export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* try the fallback */
  }
  const ta = h('textarea', { class: 'visually-hidden', readonly: true, 'aria-hidden': 'true' });
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

/** Button that copies `text` and confirms with "Copied". */
export function copyButton(text, { label = t('common.copy'), small = true, iconOnly = false, className = '' } = {}) {
  const content = () => (iconOnly ? [icon('copy', { size: 16 })] : [icon('copy', { size: 16 }), h('span', null, label)]);
  const btn = h('button', {
    type: 'button',
    class: ['btn', small && 'btn-sm', iconOnly && 'btn-icon', className],
    'aria-label': iconOnly ? label : null,
    title: iconOnly ? label : null,
  }, content());
  btn.addEventListener('click', async () => {
    const value = typeof text === 'function' ? text() : text;
    const ok = await copyText(value);
    if (!ok) {
      toast(t('ui.copy.failed'), 'error');
      return;
    }
    clear(btn);
    btn.append(icon('check', { size: 16 }), iconOnly ? '' : h('span', null, t('common.copied')));
    setTimeout(() => {
      clear(btn);
      btn.append(...content());
    }, 1600);
  });
  return btn;
}

/** Read-only field with a copy button. */
export function copyField(value, { label, wrap = false } = {}) {
  const box = h('div', { class: ['copy-field', wrap && 'wrap'] }, h('code', { title: value }, value), copyButton(value, { iconOnly: true, label: label ? t('ui.copy.label', { what: label }) : t('common.copy') }));
  if (!label) return box;
  return h('div', { class: 'field' }, h('span', { class: 'label' }, label), box);
}

/** Downloads a text as a file. */
export function downloadText(filename, text, type = 'text/plain;charset=utf-8') {
  downloadBlob(filename, new Blob([text], { type }));
}

export function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename, class: 'visually-hidden' });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// --- Forms ----------------------------------------------------------

/**
 * Labelled field. Returns the container; the control is in `.input`.
 * Options: label, name, type, value, placeholder, autocomplete, required,
 * hint, minlength, maxlength, readonly, inputmode, pattern, options (select),
 * labelExtra (node to the right of the label).
 */
export function field(opts) {
  const id = opts.id || uid('f');
  let control;
  if (opts.options) {
    control = h('select', { id, name: opts.name, class: ['select', opts.small && 'select-sm'], required: opts.required, disabled: opts.disabled },
      opts.options.map((o) => {
        const opt = h('option', { value: o.value, disabled: o.disabled }, o.label);
        // defaultSelected: the chosen option survives form.reset().
        if (opts.value !== undefined && opts.value !== null && String(o.value) === String(opts.value)) opt.defaultSelected = true;
        return opt;
      }));
    if (opts.value !== undefined && opts.value !== null) control.value = String(opts.value);
  } else if (opts.type === 'textarea') {
    control = h('textarea', { id, name: opts.name, class: 'textarea', rows: opts.rows || 3, placeholder: opts.placeholder, required: opts.required });
    if (opts.value) control.value = opts.value;
  } else {
    control = h('input', {
      id,
      name: opts.name,
      type: opts.type || 'text',
      class: ['input', opts.code && 'input-code', opts.small && 'input-sm'],
      placeholder: opts.placeholder,
      autocomplete: opts.autocomplete,
      required: opts.required,
      minlength: opts.minlength,
      maxlength: opts.maxlength,
      readonly: opts.readonly,
      disabled: opts.disabled,
      inputmode: opts.inputmode,
      pattern: opts.pattern,
      spellcheck: opts.spellcheck,
      autocapitalize: opts.autocapitalize,
      min: opts.min,
      max: opts.max,
      value: opts.value ?? undefined,
    });
  }
  const hintId = opts.hint ? uid('hint') : null;
  if (hintId) control.setAttribute('aria-describedby', hintId);
  const labelEl = h('label', { for: id }, opts.label);
  const wrap = h('div', { class: 'field' },
    opts.labelExtra ? h('div', { class: 'label-row' }, labelEl, opts.labelExtra) : labelEl,
    opts.type === 'password' && opts.reveal !== false ? passwordWrap(control) : control,
    opts.hint ? h('div', { id: hintId, class: 'hint' }, opts.hint) : null,
  );
  wrap.input = control;
  return wrap;
}

// Password with a button to show it.
function passwordWrap(input) {
  const btn = h('button', { type: 'button', class: 'btn btn-ghost btn-icon btn-sm', 'aria-label': t('ui.password.show'), 'aria-pressed': 'false', title: t('ui.password.toggle') }, icon('eye', { size: 17 }));
  btn.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.setAttribute('aria-pressed', String(show));
    btn.setAttribute('aria-label', show ? t('ui.password.hide') : t('ui.password.show'));
  });
  return h('div', { class: 'pw-wrap' }, input, btn);
}

/** Simple password strength meter (at least 10 characters). */
export function passwordMeter(input) {
  const bar = h('span');
  const meter = h('div', { class: 'password-meter', 'aria-hidden': 'true' }, bar);
  const text = h('div', { class: 'hint' }, t('ui.password.min', { min: 10 }));
  const update = () => {
    const v = input.value;
    let level = 0;
    if (v.length >= 10) level = 2;
    if (v.length >= 14) level = 3;
    const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
    if (level >= 2 && kinds >= 3) level += 1;
    if (v.length > 0 && v.length < 10) level = 1;
    level = Math.min(level, 4);
    meter.dataset.level = String(level);
    bar.style.width = `${[0, 22, 50, 78, 100][level]}%`;
    text.textContent = v.length === 0
      ? t('ui.password.min', { min: 10 })
      : v.length < 10
        ? t('ui.password.missing', { count: 10 - v.length })
        : ['', '', t('ui.password.fair'), t('ui.password.good'), t('ui.password.strong')][level];
  };
  input.addEventListener('input', update);
  update();
  return h('div', { class: 'stack-sm' }, meter, text);
}

/** Form error box: `.show(err|text)` and `.hide()`. */
export function errorBox() {
  const text = h('div', { class: 'grow' });
  const box = h('div', { class: 'form-error', role: 'alert', hidden: true }, icon('alert', { size: 18 }), text);
  box.show = (err) => {
    text.textContent = capitalize(typeof err === 'string' ? err : errorText(err, 'error.generic'));
    box.hidden = false;
  };
  box.hide = () => {
    box.hidden = true;
  };
  return box;
}

/** Checkbox with text. */
export function checkbox({ label, name, checked = false, required = false, id }) {
  const input = h('input', { type: 'checkbox', name, checked, required, id: id || uid('chk') });
  const wrap = h('label', { class: 'check' }, input, h('span', null, label));
  wrap.input = input;
  return wrap;
}

/** Switch with text. */
export function switchInput({ label, checked = false, disabled = false, onChange }) {
  const input = h('input', { type: 'checkbox', role: 'switch', checked, disabled });
  if (onChange) input.addEventListener('change', () => onChange(input.checked, input));
  const wrap = h('label', { class: 'switch' }, input, h('span', null, label));
  wrap.input = input;
  return wrap;
}

/** Segmented control (radio group). Returns the container with `.value`. */
export function segmented({ name, options, value, label, onChange }) {
  const group = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': label });
  for (const o of options) {
    const input = h('input', { type: 'radio', name, value: o.value, checked: o.value === value });
    input.addEventListener('change', () => {
      if (input.checked && onChange) onChange(o.value);
    });
    group.appendChild(h('label', null, input, o.icon ? icon(o.icon, { size: 15 }) : null, o.label));
  }
  Object.defineProperty(group, 'value', {
    get() {
      const c = group.querySelector('input:checked');
      return c ? c.value : null;
    },
  });
  return group;
}

// --- Visual pieces ----------------------------------------------------------

export function badge(text, kind = '', iconName = null) {
  return h('span', { class: ['badge', kind && `badge-${kind}`] }, iconName ? icon(iconName, { size: 13 }) : null, text);
}

export function avatar(name, email, size = '') {
  return h('span', { class: ['avatar', size && `avatar-${size}`], dataset: { hue: hue(email || name) }, 'aria-hidden': 'true' }, initials(name, email));
}

/** `<time>` with a relative date that updates itself. */
export function timeEl(ms, { prefix = '' } = {}) {
  if (!ms) return h('span', { class: 'faint' }, '—');
  const d = new Date(Number(ms));
  return h('time', { datetime: d.toISOString(), title: absTime(ms), dataset: { rel: ms, prefix } }, prefix + relTime(ms));
}

// Updates relative dates every 30 seconds.
setInterval(() => {
  for (const t of document.querySelectorAll('time[data-rel]')) {
    t.textContent = (t.dataset.prefix || '') + relTime(Number(t.dataset.rel));
  }
}, 30_000);

export function loadingState(text = t('common.loading')) {
  return h('div', { class: 'loading', role: 'status' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), h('span', null, text));
}

export function emptyState({ iconName = 'info', title, text, action }) {
  return h('div', { class: 'empty' },
    h('span', { class: 'icon-tile icon-tile-lg muted-tile' }, icon(iconName, { size: 24 })),
    h('div', { class: 'empty-title' }, title),
    text ? h('p', { class: 'empty-text' }, text) : null,
    action || null);
}

/** Error state with a retry button. */
export function errorState(err, onRetry) {
  const notVerified = err && err.code === 'email_not_verified';
  return h('div', { class: 'empty' },
    h('span', { class: ['icon-tile icon-tile-lg', notVerified ? 'warn-tile' : 'danger-tile'] }, icon(notVerified ? 'mail' : 'alert', { size: 24 })),
    h('div', { class: 'empty-title' }, notVerified ? t('ui.error_state.verify_title') : t('ui.error_state.title')),
    h('p', { class: 'empty-text' }, notVerified
      ? t('ui.error_state.verify_text')
      : capitalize(errorText(err))),
    onRetry && !notVerified ? h('button', { class: 'btn btn-sm', type: 'button', onclick: onRetry }, icon('refresh', { size: 15 }), t('common.retry')) : null);
}

/** Inline notice. `kind`: info, warn, danger or success. */
export function alertBox({ kind = 'info', title, text, actions, iconName }) {
  const ico = iconName || { info: 'info', warn: 'alert', danger: 'alert', success: 'check-circle' }[kind];
  return h('div', { class: ['alert', kind !== 'info' && `alert-${kind}`], role: kind === 'danger' ? 'alert' : null },
    icon(ico, { size: 19 }),
    h('div', { class: 'alert-body' },
      title ? h('div', { class: 'alert-title' }, title) : null,
      text ? (typeof text === 'string' ? h('div', null, text) : text) : null,
      actions && actions.length ? h('div', { class: 'alert-actions' }, actions) : null));
}

/** Page header of the app. */
export function pageHead({ title, subtitle, actions, back }) {
  return h('div', { class: 'stack-sm' },
    back ? h('a', { class: 'back-link', href: back.href }, icon('arrow-left', { size: 16 }), back.label) : null,
    h('header', { class: 'page-head' },
      h('div', null, h('h1', { tabindex: '-1', dataset: { pageTitle: '' } }, title), subtitle ? h('p', null, subtitle) : null),
      actions ? h('div', { class: 'page-actions' }, actions) : null));
}

/**
 * Accessible dropdown menu (button + list of actions).
 * items: [{label, icon, onClick, href, danger, separator}]
 */
export function dropdown({ button, items, placement = 'down', className = '' }) {
  const menuId = uid('menu');
  const menu = h('div', { class: ['menu', `menu-${placement}`], id: menuId, role: 'menu', hidden: true });
  const wrap = h('div', { class: ['menu-wrap', className] }, button, menu);
  button.setAttribute('aria-haspopup', 'menu');
  button.setAttribute('aria-expanded', 'false');
  button.setAttribute('aria-controls', menuId);

  const build = () => {
    clear(menu);
    const list = typeof items === 'function' ? items() : items;
    for (const it of list) {
      if (!it) continue;
      if (it.separator) {
        menu.appendChild(h('div', { class: 'menu-sep', role: 'separator' }));
        continue;
      }
      if (it.header) {
        menu.appendChild(h('div', { class: 'menu-label' }, it.header));
        continue;
      }
      const attrs = { class: ['menu-item', it.danger && 'danger'], role: 'menuitem', tabindex: '-1' };
      const el = it.href
        ? h('a', { ...attrs, href: it.href }, it.icon ? icon(it.icon, { size: 16 }) : null, it.label)
        : h('button', { ...attrs, type: 'button' }, it.icon ? icon(it.icon, { size: 16 }) : null, it.label);
      el.addEventListener('click', (e) => {
        close();
        if (it.onClick) {
          e.preventDefault();
          it.onClick();
        }
      });
      menu.appendChild(el);
    }
  };
  const itemsEls = () => [...menu.querySelectorAll('.menu-item')];
  const onDoc = (e) => {
    if (!wrap.contains(e.target)) close();
  };
  const onKey = (e) => {
    const els = itemsEls();
    const i = els.indexOf(document.activeElement);
    if (e.key === 'Escape') {
      close();
      button.focus();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      (els[i + 1] || els[0])?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      (els[i - 1] || els[els.length - 1])?.focus();
    } else if (e.key === 'Tab') {
      close();
    }
  };
  function open() {
    build();
    menu.hidden = false;
    button.setAttribute('aria-expanded', 'true');
    document.addEventListener('mousedown', onDoc);
    wrap.addEventListener('keydown', onKey);
    itemsEls()[0]?.focus();
  }
  function close() {
    menu.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    document.removeEventListener('mousedown', onDoc);
    wrap.removeEventListener('keydown', onKey);
  }
  button.addEventListener('click', () => (menu.hidden ? open() : close()));
  return wrap;
}

/**
 * Language picker: a `<select>` with every available language (by its
 * `language.name`). Changing it switches the language (see app.js).
 */
export function languagePicker({ id, small = false, label = true } = {}) {
  const select = h('select', {
    id: id || uid('lang'),
    class: ['select', small && 'select-sm'],
    'aria-label': label ? t('language.label') : null,
  }, languages().map((l) => h('option', { value: l.code, lang: l.code, selected: l.code === getLanguage() }, l.name)));
  select.value = getLanguage();
  select.addEventListener('change', () => {
    setLanguage(select.value).catch((e) => toastError(e));
  });
  return select;
}
