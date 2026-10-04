// Helpers to build the DOM without innerHTML.
//
// All text coming from the API is inserted as text nodes, so there is no way
// to inject HTML. `style` attributes are not used either (the CSP blocks
// them): dynamic styles are set with `el.style.property = ...`.

const SVG_NS = 'http://www.w3.org/2000/svg';

// Keys assigned as element properties rather than attributes.
const PROPS = new Set(['value', 'checked', 'selected', 'indeterminate', 'defaultValue']);

function isAttrs(x) {
  return x !== null && typeof x === 'object' && !(x instanceof Node) && !Array.isArray(x);
}

function appendChildren(el, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false || c === true) continue;
    if (Array.isArray(c)) {
      appendChildren(el, c);
    } else if (c instanceof Node) {
      el.appendChild(c);
    } else {
      el.appendChild(document.createTextNode(String(c)));
    }
  }
}

function applyAttrs(el, attrs, svg) {
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') {
      const cls = Array.isArray(value) ? value.filter(Boolean).join(' ') : value;
      if (cls) el.setAttribute('class', cls);
    } else if (key === 'dataset') {
      for (const [k, v] of Object.entries(value)) {
        if (v !== undefined && v !== null) el.dataset[k] = String(v);
      }
    } else if (key === 'ref') {
      value(el);
    } else if (key.startsWith('on') && typeof value === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === 'style') {
      // Objects only: applied through CSSOM, which the CSP allows.
      if (typeof value === 'object') {
        for (const [prop, v] of Object.entries(value)) el.style.setProperty(prop, v);
      }
    } else if (!svg && PROPS.has(key)) {
      el[key] = value;
    } else if (value === true) {
      el.setAttribute(key, '');
    } else {
      el.setAttribute(key, String(value));
    }
  }
}

/**
 * Creates an HTML element.
 *
 *   h('button', {class: 'btn', onclick: fn}, t('common.save'))
 *   h('ul', null, items.map((i) => h('li', null, i.name)))
 *
 * - `on*` attributes with a function become event listeners.
 * - `class` accepts a string or a list (falsy values are ignored).
 * - `true` sets an empty attribute; `false`, `null` or `undefined` omit it.
 * - Children can be nodes, strings, numbers or lists (they are flattened).
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (isAttrs(attrs)) {
    applyAttrs(el, attrs, false);
  } else if (attrs !== undefined) {
    children.unshift(attrs);
  }
  appendChildren(el, children);
  return el;
}

/** Same as `h`, but for SVG elements. */
export function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  if (isAttrs(attrs)) applyAttrs(el, attrs, true);
  else if (attrs !== undefined) children.unshift(attrs);
  appendChildren(el, children);
  return el;
}

/** Empties an element. */
export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

/** Replaces the content of an element. */
export function replace(el, ...children) {
  clear(el);
  appendChildren(el, children);
  return el;
}

/** Appends children to an element. */
export function append(el, ...children) {
  appendChildren(el, children);
  return el;
}

/** Unique id to link labels and fields. */
let seq = 0;
export function uid(prefix = 'id') {
  seq += 1;
  return `${prefix}-${seq}`;
}
