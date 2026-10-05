// Link guests: the display name and the key that keeps them the same
// participant across reconnects (both kept in this browser). Separate from
// view.js so the /join page can use them without loading xterm.

const GUEST_KEY = 'termoak.guestKey';
const GUEST_NAME = 'termoak.guestName';

// Without storage, the key lasts while the page is open.
let memoryKey = null;

function newKey() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Random key that identifies this browser as the same link guest. */
export function guestKey() {
  try {
    let key = localStorage.getItem(GUEST_KEY);
    if (!key || !/^[A-Za-z0-9_-]{8,64}$/.test(key)) {
      key = newKey();
      localStorage.setItem(GUEST_KEY, key);
    }
    return key;
  } catch {
    memoryKey = memoryKey || newKey();
    return memoryKey;
  }
}

/** The display name this browser used last time as a link guest. */
export function savedGuestName() {
  try {
    return localStorage.getItem(GUEST_NAME) || '';
  } catch {
    return '';
  }
}

export function saveGuestName(name) {
  try {
    if (name) localStorage.setItem(GUEST_NAME, name);
    else localStorage.removeItem(GUEST_NAME);
  } catch {
    /* no storage */
  }
}
