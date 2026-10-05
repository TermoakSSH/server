// Terminal of your own session or one shared with you, in the browser.

import { mountTerminal } from '../../term/view.js';
import { shareDialog } from './sessions.js';
import { t } from '../../i18n.js';

export function render(ctx) {
  return mountTerminal({
    sessionId: ctx.params.id,
    title: t('terminal.title'),
    back: { href: '/app/sessions', label: t('sessions.title') },
    onShare: (session) => shareDialog({ id: ctx.params.id, title: (session && session.title) || t('terminal.title') }),
    onCleanup: ctx.onCleanup,
    onTitle: (title) => ctx.setTitle(`${title} · ${t('terminal.title')}`),
  });
}
