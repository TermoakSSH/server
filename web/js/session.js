// Shared state of the web: server information and the signed-in account. Pages subscribe to hear about changes.

import { api, tokens } from './api.js';

export const state = {
  /** `GET /info`: version, registration, features, legal links. */
  info: null,
  /** `GET /me`: `{user, device, plan}` or `null` when signed out. */
  me: null,
};

const listeners = new Set();

/** Subscribes to state changes. Returns the unsubscribe function. */
export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function emit() {
  for (const fn of [...listeners]) {
    try {
      fn(state);
    } catch (e) {
      console.warn('state subscriber', e);
    }
  }
}

/** Public server information (requested once). */
export async function loadInfo(force = false) {
  if (!state.info || force) {
    state.info = await api.get('/info', { auth: false });
  }
  return state.info;
}

export function isLoggedIn() {
  return !!tokens.get();
}

/** Loads (or reloads) the current account. */
export async function loadMe() {
  state.me = await api.get('/me');
  emit();
  return state.me;
}

/** Saves the tokens of a login or registration and loads the account. */
export async function signIn(authResponse) {
  tokens.set(authResponse.tokens);
  state.me = null;
  return loadMe();
}

/** Signs out (on the server, if possible, and in this browser). */
export async function signOut({ remote = true } = {}) {
  if (remote && tokens.get()) {
    try {
      await api.post('/auth/logout');
    } catch {
      // Doesn't matter: the tokens are deleted anyway.
    }
  }
  tokens.clear();
  state.me = null;
  emit();
}

/** Current user (or `null`). */
export function currentUser() {
  return state.me ? state.me.user : null;
}

/** Does the email need to be confirmed to use the account? */
export function needsVerification() {
  const u = currentUser();
  const f = state.info && state.info.features;
  return !!(u && !u.email_verified && f && f.email_verification);
}

/** Is registration open? */
export function registrationOpen() {
  return !!(state.info && state.info.registration === 'open');
}

let externalSignOut = null;

/** Registers what to do when another tab signs out. */
export function onExternalSignOut(fn) {
  externalSignOut = fn;
}

// Another tab signed out: sync the state.
window.addEventListener('storage', (e) => {
  if (e.key !== tokens.key || e.newValue) return;
  state.me = null;
  if (externalSignOut) externalSignOut();
  emit();
});
