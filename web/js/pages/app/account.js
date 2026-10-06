// Account: profile and email, preferences (language), security (password and
// two-step verification), sessions and devices, and deleting the account.

import { h, replace, uid } from '../../dom.js';
import { icon } from '../../icons.js';
import { api } from '../../api.js';
import { state, currentUser, loadMe, signOut } from '../../session.js';
import { t, tx } from '../../i18n.js';
import { navigate } from '../../router.js';
import { platformLabel, platformIcon, absTime } from '../../format.js';
import {
  pageHead, loadingState, errorState, badge, timeEl, toast, toastError, busy, confirmDialog, formDialog,
  field, avatar, errorBox, alertBox, copyButton, downloadText, passwordMeter, checkbox, languagePicker,
} from '../../ui.js';

// Tabs: [path segment, label key, icon].
const TABS = [
  ['', 'account.tab.profile', 'user'],
  ['security', 'account.tab.security', 'shield'],
  ['devices', 'account.tab.devices', 'laptop'],
];

function card(title, sub, ...content) {
  return h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('div', null, h('h2', { class: 'card-title' }, title), sub ? h('p', { class: 'card-sub' }, sub) : null)),
    ...content);
}

// --- Profile -----------------------------------------------------------------

function profileCard() {
  const u = currentUser();
  const error = errorBox();
  const name = field({ label: t('common.name'), name: 'name', required: true, value: u.name, autocomplete: 'name', maxlength: 80 });
  const save = h('button', { class: 'btn btn-primary', type: 'submit' }, t('common.save'));
  const form = h('form', { class: 'form', novalidate: true },
    h('div', { class: 'row' }, avatar(u.name, u.email, 'lg'),
      h('div', { class: 'grow' }, h('div', { class: 'strong break' }, u.name || u.email), h('div', { class: 'small muted' }, tx('account.profile.created', { time: timeEl(u.created_at) })))),
    error, name, h('div', null, save));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    if (!form.reportValidity()) return;
    busy(save, async () => {
      try {
        await api.patch('/me', { name: name.input.value.trim() });
        await loadMe();
        toast(t('account.profile.saved'), 'success');
      } catch (err) {
        error.show(err);
      }
    });
  });
  return card(t('account.profile.title'), t('account.profile.subtitle'), form);
}

function preferencesCard() {
  const id = uid('lang');
  return card(t('account.preferences.title'), null,
    h('div', { class: 'field' },
      h('label', { for: id }, t('language.label')),
      languagePicker({ id }),
      h('div', { class: 'hint' }, t('account.language.hint'))));
}

function emailCard() {
  const u = currentUser();
  const features = (state.info && state.info.features) || {};
  const error = errorBox();
  const result = h('div');
  const email = field({ label: t('account.email.new'), name: 'email', type: 'email', required: true, autocomplete: 'email', spellcheck: 'false' });
  const password = field({ label: t('account.current_password'), name: 'password', type: 'password', required: true, autocomplete: 'current-password' });
  const save = h('button', { class: 'btn', type: 'submit' }, t('account.email.change'));
  const form = h('form', { class: 'form', novalidate: true }, error, h('div', { class: 'form-row' }, email, password), h('div', null, save));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    if (!form.reportValidity()) return;
    busy(save, async () => {
      try {
        const r = await api.post('/me/email', { email: email.input.value.trim(), password: password.input.value }, { credential: true });
        password.input.value = '';
        if (r.pending) {
          replace(result, alertBox({
            kind: 'info',
            iconName: 'mail',
            title: t('account.email.pending_title'),
            text: h('span', null, tx('account.email.pending_text', { new_email: h('strong', null, r.email), email: h('strong', null, u.email) })),
          }));
          email.input.value = '';
        } else {
          await loadMe();
          toast(t('account.email.changed', { email: r.user.email }), 'success');
          replace(result);
          draw();
        }
      } catch (err) {
        error.show(err);
      }
    });
  });
  return card(t('common.email'), null,
    h('div', { class: 'stack' },
      h('div', { class: 'row-wrap' }, h('strong', { class: 'break' }, u.email),
        u.email_verified ? badge(t('account.email.verified'), 'accent', 'check') : badge(t('account.email.unverified'), 'warn', 'mail')),
      features.email ? h('p', { class: 'small muted' }, t('account.email.change_hint')) : null,
      result,
      form));
}

/** The vaults of a `shared_vaults` error: `[{id, name, member_count}]`. */
function sharedVaultsOf(err) {
  const src = (err.data && err.data.error) || {};
  return Array.isArray(src.vaults) ? src.vaults : [];
}

/** Second confirmation when deleting the account deletes shared vaults. */
function confirmSharedVaults(vaults) {
  return confirmDialog({
    title: t('account.delete.vaults_title', { count: vaults.length }),
    message: h('div', { class: 'stack-sm' },
      h('p', null, t('account.delete.vaults_text', { count: vaults.length })),
      h('ul', { class: 'danger-list', dataset: { sharedVaults: '' } }, vaults.map((v) => h('li', null,
        h('strong', null, v.name), ' · ', t('account.delete.vaults_members', { count: v.member_count || 0 }))))),
    confirmLabel: t('account.delete.vaults_confirm'),
    danger: true,
  });
}

function deleteCard() {
  const u = currentUser();
  const open = () => {
    const word = t('account.delete.confirm_word');
    const password = field({ label: t('common.password'), name: 'password', type: 'password', required: true, autocomplete: 'current-password' });
    const code = u.totp_enabled
      ? field({ label: t('account.totp.code'), name: 'totp', required: true, inputmode: 'numeric', autocomplete: 'one-time-code', hint: t('account.delete.code_hint') })
      : null;
    const confirmField = field({ label: t('account.delete.confirm_label', { word }), name: 'confirm', required: true, autocomplete: 'off', spellcheck: 'false' });
    let deleteShared = false;
    formDialog({
      title: t('account.delete.dialog_title'),
      description: t('account.delete.dialog_text'),
      iconName: 'trash',
      danger: true,
      fields: [password, code, confirmField].filter(Boolean),
      submitLabel: t('account.delete.submit'),
      onSubmit: async () => {
        if (confirmField.input.value.trim() !== word) throw new Error(t('account.delete.confirm_error', { word }));
        const body = { password: password.input.value, totp_code: code ? code.input.value.trim() : undefined };
        if (deleteShared) body.delete_shared_vaults = true;
        try {
          await api.del('/me', body, { credential: true });
        } catch (e) {
          // Your shared vaults that have members go with the account: list
          // them and ask again.
          if (e.code !== 'shared_vaults') throw e;
          if (!(await confirmSharedVaults(sharedVaultsOf(e)))) return false;
          deleteShared = true;
          // A two-step code is only accepted once: ask for a new one.
          if (code) {
            code.input.value = '';
            code.input.focus();
            throw new Error(t('account.delete.vaults_new_code'));
          }
          await api.del('/me', { ...body, delete_shared_vaults: true }, { credential: true });
        }
        await signOut({ remote: false });
        toast(t('account.delete.done'), 'success', { timeout: 8000 });
        navigate('/');
      },
    });
  };
  return h('section', { class: 'card card-danger' },
    h('div', { class: 'card-head' }, h('div', null, h('h2', { class: 'card-title' }, t('account.delete.title')), h('p', { class: 'card-sub' }, t('account.delete.subtitle')))),
    h('ul', { class: 'danger-list' },
      h('li', null, t('account.delete.item_data')),
      h('li', null, t('account.delete.item_vaults')),
      h('li', null, t('account.delete.item_sessions')),
      h('li', null, t('account.delete.item_teams'))),
    h('div', { class: 'card-foot' }, h('button', { class: 'btn btn-danger', type: 'button', onclick: open }, icon('trash', { size: 16 }), t('account.delete.button'))));
}

// --- Security ------------------------------------------------------------------

function passwordCard() {
  const error = errorBox();
  const current = field({ label: t('account.current_password'), name: 'current', type: 'password', required: true, autocomplete: 'current-password' });
  const next = field({ label: t('account.password.new'), name: 'new', type: 'password', required: true, minlength: 10, autocomplete: 'new-password' });
  const repeat = field({ label: t('account.password.repeat'), name: 'repeat', type: 'password', required: true, minlength: 10, autocomplete: 'new-password' });
  const save = h('button', { class: 'btn btn-primary', type: 'submit' }, t('account.password.change'));
  const form = h('form', { class: 'form', novalidate: true },
    error, current,
    h('div', { class: 'form-row' }, h('div', { class: 'stack-sm' }, next, passwordMeter(next.input)), repeat),
    h('div', null, save));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    error.hide();
    if (next.input.value.length < 10) {
      error.show(t('account.password.too_short'));
      return;
    }
    if (next.input.value !== repeat.input.value) {
      error.show(t('account.password.mismatch'));
      return;
    }
    if (!form.reportValidity()) return;
    busy(save, async () => {
      try {
        await api.post('/me/password', { current_password: current.input.value, new_password: next.input.value }, { credential: true });
        form.reset();
        next.input.dispatchEvent(new Event('input'));
        toast(t('account.password.changed'), 'success');
      } catch (err) {
        error.show(err);
      }
    });
  });
  return card(t('common.password'), t('account.password.subtitle'), form);
}

/** Encodes a UTF-8 text in base64 (for the QR data: URL). */
function toBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function totpCard(ctx) {
  const body = h('div', null, loadingState());
  const section = card(t('account.totp.title'), t('account.totp.subtitle'), body);

  const showStatus = async () => {
    replace(body, loadingState());
    let st;
    try {
      st = await api.get('/me/2fa');
    } catch (e) {
      replace(body, errorState(e, showStatus));
      return;
    }
    if (!ctx.alive()) return;
    if (st.enabled) {
      const disable = h('button', { class: 'btn btn-danger-ghost', type: 'button' }, t('account.totp.disable'));
      disable.addEventListener('click', () => {
        const password = field({ label: t('common.password'), name: 'password', type: 'password', required: true, autocomplete: 'current-password' });
        const code = field({ label: t('account.totp.code'), name: 'code', required: true, autocomplete: 'one-time-code', hint: t('account.totp.disable_code_hint') });
        formDialog({
          title: t('account.totp.disable_title'),
          description: t('account.totp.disable_text'),
          iconName: 'shield',
          danger: true,
          fields: [password, code],
          submitLabel: t('account.totp.disable'),
          onSubmit: async () => {
            await api.post('/me/2fa/disable', { password: password.input.value, code: code.input.value.trim() }, { credential: true });
            await loadMe();
            toast(t('account.totp.disabled_toast'), 'success');
            showStatus();
          },
        });
      });
      const left = st.recovery_codes_left;
      replace(body, h('div', { class: 'stack' },
        h('div', { class: 'row-wrap' }, badge(t('account.totp.on'), 'accent', 'shield-check'),
          h('span', { class: 'small muted' }, t('account.totp.codes_left', { count: left }))),
        left <= 3 ? alertBox({ kind: 'warn', text: t('account.totp.codes_low') }) : null,
        h('div', { class: 'row-wrap' }, disable)));
    } else {
      const start = h('button', { class: 'btn btn-primary', type: 'button' }, icon('shield-check', { size: 16 }), t('account.totp.enable_button'));
      start.addEventListener('click', () => busy(start, setup));
      replace(body, h('div', { class: 'stack' },
        h('div', { class: 'row-wrap' }, badge(t('account.totp.off'), 'warn', 'shield'),
          h('span', { class: 'small muted' }, t('account.totp.needs_app'))),
        h('div', null, start)));
    }
  };

  const steps = (current) => h('div', { class: 'steps', 'aria-label': t('account.totp.steps') },
    [t('account.totp.step_scan'), t('account.totp.step_confirm'), t('account.totp.step_save')].map((label, i) => h('span', { class: [i + 1 === current && 'is-current', i + 1 < current && 'is-done'], 'aria-current': i + 1 === current ? 'step' : null },
      h('span', { class: 'step-num' }, i + 1 < current ? '✓' : String(i + 1)), label)));

  // Steps 1 and 2: QR, secret and code.
  const setup = async () => {
    let data;
    try {
      data = await api.post('/me/2fa/setup');
    } catch (e) {
      toastError(e);
      return;
    }
    const error = errorBox();
    const code = field({ label: t('account.totp.code_6'), name: 'code', required: true, inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, code: true });
    const confirmBtn = h('button', { class: 'btn btn-primary', type: 'submit' }, t('account.totp.enable'));
    const cancel = h('button', { class: 'btn btn-ghost', type: 'button', onclick: showStatus }, t('common.cancel'));
    const form = h('form', { class: 'form', novalidate: true }, error, code, h('div', { class: 'row-wrap' }, confirmBtn, cancel));
    code.input.addEventListener('input', () => {
      code.input.value = code.input.value.replace(/\D/g, '').slice(0, 6);
    });
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      error.hide();
      if (code.input.value.length !== 6) {
        error.show(t('account.totp.code_6_error'));
        return;
      }
      busy(confirmBtn, async () => {
        try {
          const r = await api.post('/me/2fa/enable', { code: code.input.value });
          await loadMe();
          showCodes(r.recovery_codes);
        } catch (err) {
          error.show(err);
          code.input.select();
        }
      });
    });
    const secretGrouped = data.secret.replace(/(.{4})/g, '$1 ').trim();
    const qr = data.qr_svg
      ? h('div', { class: 'qr-box' }, h('img', { src: `data:image/svg+xml;base64,${toBase64(data.qr_svg)}`, alt: t('account.totp.qr_alt'), width: 184, height: 184 }))
      : null;
    replace(body, h('div', { class: 'stack' },
      steps(1),
      h('div', { class: 'totp-setup' },
        qr,
        h('div', { class: 'stack' },
          h('p', null, t('account.totp.instructions_scan')),
          h('div', { class: 'stack-sm' },
            h('span', { class: 'small muted' }, t('account.totp.manual_key')),
            h('div', { class: 'row' }, h('div', { class: 'secret-box grow', dataset: { secret: data.secret } }, secretGrouped), copyButton(data.secret, { iconOnly: true, label: t('account.totp.copy_key') }))),
          h('p', null, t('account.totp.instructions_code')),
          form))));
    code.input.focus();
  };

  // Step 3: recovery codes (only shown now).
  const showCodes = (codes) => {
    const text = [
      t('account.totp.file_title'),
      t('account.totp.file_account', { email: currentUser().email }),
      t('account.totp.file_server', { server: location.origin }),
      t('account.totp.file_generated', { date: absTime(Date.now()) }),
      '',
      t('account.totp.file_note'),
      '',
      ...codes,
      '',
    ].join('\n');
    const saved = checkbox({ label: t('account.totp.saved_check') });
    const done = h('button', { class: 'btn btn-primary', type: 'button', disabled: true }, t('account.totp.finish'));
    saved.input.addEventListener('change', () => {
      done.disabled = !saved.input.checked;
    });
    done.addEventListener('click', () => {
      toast(t('account.totp.enabled_toast'), 'success');
      showStatus();
    });
    replace(body, h('div', { class: 'stack' },
      steps(3),
      alertBox({ kind: 'success', title: t('account.totp.enabled_title'), text: t('account.totp.enabled_text') }),
      h('ol', { class: 'codes-grid', 'aria-label': t('account.totp.codes_label') }, codes.map((c) => h('li', null, c))),
      h('div', { class: 'row-wrap' },
        copyButton(codes.join('\n'), { label: t('account.totp.copy_all'), small: false }),
        h('button', { class: 'btn', type: 'button', onclick: () => downloadText(t('account.totp.file_name'), text) }, icon('download', { size: 16 }), t('account.totp.download_txt'))),
      saved,
      h('div', null, done)));
  };

  showStatus();
  return section;
}

// --- Sessions and devices --------------------------------------------------------

/** This device was signed out on the server: forget it here and go to sign in. */
async function signedOutHere(message) {
  await signOut({ remote: false });
  if (message) toast(message, 'success');
  navigate('/login');
}

function deviceRow(d, current, reload) {
  const revoke = h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button', dataset: { action: 'sign-out-device' } },
    icon('logout', { size: 15 }), t('common.sign_out'));
  revoke.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: current ? t('account.devices.sign_out_here_title') : t('account.devices.sign_out_device_title', { name: d.name }),
      message: current ? t('account.devices.sign_out_here_text') : t('account.devices.sign_out_device_text'),
      confirmLabel: t('common.sign_out'),
      danger: !current,
    });
    if (!ok) return;
    busy(revoke, async () => {
      try {
        await api.del(`/devices/${d.id}`);
        if (current) {
          await signedOutHere();
          return;
        }
        toast(t('account.devices.signed_out_device', { name: d.name }), 'success');
        reload();
      } catch (e) {
        toastError(e);
      }
    });
  });
  const meta = [
    h('span', null, platformLabel(d.platform)),
    d.user_agent ? h('span', { dataset: { field: 'client' } }, d.user_agent) : null,
    d.last_ip ? h('span', { dataset: { field: 'ip' } }, t('account.devices.ip', { ip: d.last_ip })) : null,
  ];
  const times = [
    h('span', null, current ? t('account.devices.active_now') : tx('account.devices.last_used', { time: timeEl(d.last_seen_at) })),
    h('span', null, tx('account.devices.since', { time: timeEl(d.created_at) })),
  ];
  return h('div', { class: 'list-item', dataset: { deviceId: d.id, current: current ? 'true' : 'false' } },
    h('span', { class: ['icon-tile', !current && 'muted-tile'] }, icon(platformIcon(d.platform), { size: 18 })),
    h('div', { class: 'list-item-main' },
      h('div', { class: 'list-item-title' }, h('span', { class: 'break' }, d.name),
        current ? badge(t('account.devices.this_device'), 'accent') : null,
        d.push ? badge(t('account.devices.notifications'), 'info', 'send') : null),
      h('div', { class: 'list-item-meta' }, meta),
      h('div', { class: 'list-item-meta' }, times)),
    h('div', { class: 'list-item-actions keep-inline' }, revoke));
}

function devicesCard(ctx) {
  const body = h('div', null, loadingState(t('account.devices.loading')));
  const load = async () => {
    try {
      const data = await api.get('/devices');
      if (!ctx.alive()) return;
      const others = data.devices.filter((d) => d.id !== data.current);
      // This device first, then the most recently used.
      const rows = data.devices.filter((d) => d.id === data.current).concat(others);
      const signOutOthers = h('button', { class: 'btn btn-sm', type: 'button', disabled: !others.length, dataset: { action: 'sign-out-others' } },
        t('account.devices.sign_out_others'));
      signOutOthers.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: t('account.devices.sign_out_others_title'),
          message: t('account.devices.sign_out_others_text', { count: others.length }),
          confirmLabel: t('account.devices.sign_out_others_confirm'),
          danger: true,
        });
        if (!ok) return;
        busy(signOutOthers, async () => {
          try {
            const r = await api.post('/devices/sign-out-all', { include_current: false });
            toast(t('account.devices.signed_out_others', { count: r.revoked || 0 }), 'success');
            load();
          } catch (e) {
            toastError(e);
          }
        });
      });
      const signOutEverywhere = h('button', { class: 'btn btn-sm btn-danger-ghost', type: 'button', dataset: { action: 'sign-out-everywhere' } },
        icon('logout', { size: 15 }), t('account.devices.sign_out_everywhere'));
      signOutEverywhere.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: t('account.devices.sign_out_everywhere_title'),
          message: t('account.devices.sign_out_everywhere_text', { count: data.devices.length }),
          confirmLabel: t('account.devices.sign_out_everywhere_confirm'),
          danger: true,
        });
        if (!ok) return;
        busy(signOutEverywhere, async () => {
          try {
            await api.post('/devices/sign-out-all', { include_current: true });
            await signedOutHere(t('account.devices.signed_out_everywhere'));
          } catch (e) {
            toastError(e);
          }
        });
      });
      replace(body, h('div', { class: 'stack' },
        h('div', { class: 'card card-flush' }, h('div', { class: 'list', dataset: { devices: '' } }, rows.map((d) => deviceRow(d, d.id === data.current, load)))),
        h('div', { class: 'row-between' },
          h('span', { class: 'small muted' }, t('account.devices.count', { count: data.devices.length })),
          h('div', { class: 'row-wrap' }, signOutOthers, signOutEverywhere))));
    } catch (e) {
      if (ctx.alive()) replace(body, errorState(e, load));
    }
  };
  load();
  return h('section', { class: 'section' },
    h('div', { class: 'section-head' }, h('div', null, h('h2', null, t('account.tab.devices')), h('p', { class: 'small muted' }, t('account.devices.subtitle')))),
    body);
}

// --- Page --------------------------------------------------------------------------

let draw = () => {};

export function render(ctx) {
  const tab = ctx.params.tab || '';
  const known = TABS.some(([k]) => k === tab);
  const content = h('div', { class: 'stack-lg' });
  draw = () => {
    if (!ctx.alive()) return;
    if (tab === 'security') replace(content, passwordCard(), totpCard(ctx));
    else if (tab === 'devices') replace(content, devicesCard(ctx));
    else replace(content, profileCard(), preferencesCard(), emailCard(), deleteCard());
  };
  if (!known) {
    navigate('/app/account', { replace: true });
    return null;
  }
  draw();
  const title = t(TABS.find(([k]) => k === tab)[1]);
  ctx.setTitle(t('account.page_title', { tab: title }));
  return h('div', { class: 'stack-lg' },
    pageHead({ title: t('account.title'), subtitle: currentUser().email }),
    h('nav', { class: 'tabs', 'aria-label': t('account.tabs_label') },
      TABS.map(([k, label, ico]) => h('a', { class: 'tab', href: k ? `/app/account/${k}` : '/app/account', 'aria-current': k === tab ? 'page' : null }, icon(ico, { size: 16 }), t(label)))),
    content);
}

