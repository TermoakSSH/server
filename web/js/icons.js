// SVG icons, built with the DOM (no files and no inline HTML).
//
// 24×24 grid with a 1.8 px stroke. Many paths follow the style of Feather
// Icons (MIT, © Cole Bemis); the operating system ones are simplified
// silhouettes.

import { s } from './dom.js';

// Each icon is a list of [tag, attributes].
const P = (d) => ['path', { d }];
const C = (cx, cy, r) => ['circle', { cx, cy, r }];
const L = (x1, y1, x2, y2) => ['line', { x1, y1, x2, y2 }];
const PL = (points) => ['polyline', { points }];
const R = (x, y, width, height, rx = 2) => ['rect', { x, y, width, height, rx }];

const ICONS = {
  terminal: [PL('4 17 10 11 4 5'), L(12, 19, 20, 19)],
  server: [R(2, 3, 20, 8), R(2, 13, 20, 8), L(6, 7, 6.01, 7), L(6, 17, 6.01, 17)],
  share: [C(18, 5, 3), C(6, 12, 3), C(18, 19, 3), L(8.6, 13.5, 15.4, 17.5), L(15.4, 6.5, 8.6, 10.5)],
  'user-plus': [P('M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'), C(9, 7, 4), L(19, 8, 19, 14), L(22, 11, 16, 11)],
  vault: [R(3, 3, 18, 18, 3), C(12, 12, 4), L(12, 12, 14.5, 9.5), L(6, 21, 6, 22.5), L(18, 21, 18, 22.5)],
  users: [P('M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2'), C(9, 7, 4), P('M23 21v-2a4 4 0 0 0-3-3.87'), P('M16 3.13a4 4 0 0 1 0 7.75')],
  user: [P('M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2'), C(12, 7, 4)],
  shield: [P('M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z')],
  'shield-check': [P('M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'), PL('9 12 11 14 15 10')],
  key: [C(7.5, 15.5, 4.5), L(10.7, 12.3, 20, 3), L(17, 6, 20, 9), L(14.5, 8.5, 16.5, 10.5)],
  lock: [R(3, 11, 18, 11), P('M7 11V7a5 5 0 0 1 10 0v4')],
  download: [P('M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'), PL('7 10 12 15 17 10'), L(12, 15, 12, 3)],
  phone: [R(6, 2, 12, 20, 2.5), L(11, 18, 13, 18)],
  laptop: [R(4, 4, 16, 11, 1.5), P('M2 19h20'), P('M3.5 15.5 2 19'), P('M20.5 15.5 22 19')],
  monitor: [R(2, 3, 20, 14), L(8, 21, 16, 21), L(12, 17, 12, 21)],
  check: [PL('20 6 9 17 4 12')],
  x: [L(18, 6, 6, 18), L(6, 6, 18, 18)],
  copy: [R(9, 9, 13, 13), P('M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1')],
  link: [P('M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'), P('M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71')],
  trash: [PL('3 6 5 6 21 6'), P('M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6'), P('M10 11v6'), P('M14 11v6'), P('M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2')],
  logout: [P('M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4'), PL('16 17 21 12 16 7'), L(21, 12, 9, 12)],
  menu: [L(3, 6, 21, 6), L(3, 12, 21, 12), L(3, 18, 21, 18)],
  clock: [C(12, 12, 10), PL('12 6 12 12 16 14')],
  mail: [R(2, 4, 20, 16), P('m22 6-10 7L2 6')],
  plus: [L(12, 5, 12, 19), L(5, 12, 19, 12)],
  'chevron-right': [PL('9 18 15 12 9 6')],
  'chevron-up-down': [PL('7 15 12 20 17 15'), PL('7 9 12 4 17 9')],
  'arrow-right': [L(5, 12, 19, 12), PL('12 5 19 12 12 19')],
  'arrow-left': [L(19, 12, 5, 12), PL('12 19 5 12 12 5')],
  external: [P('M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'), PL('15 3 21 3 21 9'), L(10, 14, 21, 3)],
  eye: [P('M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'), C(12, 12, 3)],
  keyboard: [R(2, 6, 20, 12), P('M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10')],
  refresh: [P('M21 12a9 9 0 1 1-2.64-6.36L21 8'), PL('21 3 21 8 16 8')],
  alert: [P('M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z'), L(12, 9, 12, 13), L(12, 17, 12.01, 17)],
  info: [C(12, 12, 10), L(12, 16, 12, 12), L(12, 8, 12.01, 8)],
  'check-circle': [C(12, 12, 10), PL('8 12.5 11 15.5 16 9.5')],
  globe: [C(12, 12, 10), L(2, 12, 22, 12), P('M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z')],
  search: [C(11, 11, 7.5), L(21, 21, 16.4, 16.4)],
  sun: [C(12, 12, 4), P('M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41')],
  moon: [P('M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z')],
  maximize: [P('M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3')],
  power: [P('M18.36 6.64a9 9 0 1 1-12.73 0'), L(12, 2, 12, 12)],
  ticket: [P('M3 7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a2 2 0 0 0 0 4v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 0 0-4z'), P('M14 5v2M14 11v2M14 17v2')],
  card: [R(2, 5, 20, 14), L(2, 10, 22, 10), L(6, 15, 10, 15)],
  edit: [P('M12 20h9'), P('M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4z')],
  crown: [P('M3 8l4.5 4L12 5l4.5 7L21 8l-2 11H5z')],
  send: [L(22, 2, 11, 13), ['polygon', { points: '22 2 15 22 11 13 2 9 22 2' }]],
  'wifi-off': [L(2, 2, 22, 22), P('M8.5 16.43a5 5 0 0 1 7 0'), P('M2 8.82a15 15 0 0 1 4.17-2.65'), P('M10.66 5c4.01-.36 8.14.9 11.34 3.76'), P('M16.85 11.25a10 10 0 0 1 2.22 1.68'), P('M5 13a10 10 0 0 1 5.24-2.76'), L(12, 20, 12.01, 20)],
  resize: [PL('15 3 21 3 21 9'), PL('9 21 3 21 3 15'), L(21, 3, 14, 10), L(3, 21, 10, 14)],
};

// Filled icons (solid fill, no stroke).
const FILLED = {
  dot: [C(12, 12, 5)],
};

/**
 * Creates a decorative SVG icon (aria-hidden), or a labelled one with `label`.
 * @param {string} name icon name
 * @param {{size?: number, class?: string, label?: string}} opts
 */
export function icon(name, opts = {}) {
  const size = opts.size || 18;
  const filled = Object.prototype.hasOwnProperty.call(FILLED, name);
  const shapes = filled ? FILLED[name] : ICONS[name] || ICONS.info;
  const attrs = {
    viewBox: '0 0 24 24',
    width: size,
    height: size,
    class: ['ico', opts.class].filter(Boolean).join(' '),
    focusable: 'false',
  };
  if (filled) {
    attrs.fill = 'currentColor';
  } else {
    Object.assign(attrs, {
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': opts.stroke || 1.8,
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round',
    });
  }
  if (opts.label) {
    attrs.role = 'img';
    attrs['aria-label'] = opts.label;
  } else {
    attrs['aria-hidden'] = 'true';
  }
  return s('svg', attrs, shapes.map(([tag, a]) => s(tag, a)));
}
