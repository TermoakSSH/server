// Adapts xterm.js to the web's strict CSP (`style-src 'self'`, no inline
// styles).
//
// xterm.js 6 creates `<style>` elements with generated rules (theme colors,
// cell size, scrollbar) and, in the DOM renderer, sets `style` attributes on
// some cells. The CSP blocks both. Here:
//
// - `document.createElement('style')` returns an inert element whose
//   `textContent` is poured into a constructed stylesheet
//   (`CSSStyleSheet` + `adoptedStyleSheets`), which the CSP does not block.
// - `setAttribute('style', …)` becomes `el.style.cssText = …` (CSSOM),
//   which is also allowed.
//
// The web itself never creates `<style>` elements or `style` attributes (the
// CSP would block them), so the change only affects xterm.js.

let installed = false;

function styleShim(doc, create) {
  const el = create.call(doc, 'xterm-style');
  el.hidden = true;
  const sheet = new CSSStyleSheet();
  let text = '';
  let adopted = false;
  Object.defineProperty(el, 'textContent', {
    configurable: true,
    get: () => text,
    set: (value) => {
      text = value == null ? '' : String(value);
      try {
        sheet.replaceSync(text);
      } catch (e) {
        console.warn('xterm: invalid stylesheet', e);
      }
      if (!adopted) {
        doc.adoptedStyleSheets = [...doc.adoptedStyleSheets, sheet];
        adopted = true;
      }
    },
  });
  const remove = el.remove.bind(el);
  el.remove = () => {
    if (adopted) {
      doc.adoptedStyleSheets = doc.adoptedStyleSheets.filter((s) => s !== sheet);
      adopted = false;
    }
    remove();
  };
  return el;
}

export function installCspShim() {
  if (installed) return;
  installed = true;
  const create = Document.prototype.createElement;
  Document.prototype.createElement = function createElement(tag, options) {
    if (typeof tag === 'string' && tag.toLowerCase() === 'style') return styleShim(this, create);
    return create.call(this, tag, options);
  };
  const setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function setAttr(name, value) {
    if (typeof name === 'string' && name.toLowerCase() === 'style' && this.style) {
      this.style.cssText = String(value);
      return undefined;
    }
    return setAttribute.call(this, name, value);
  };
}

installCspShim();
