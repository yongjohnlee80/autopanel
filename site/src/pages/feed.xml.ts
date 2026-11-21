// The feed: RSS 2.0 of the newest dated documents. Only RSS's own elements,
// no stylesheet instruction: the output check holds the feed to that.
import { config, latest, absolute } from '../lib/input';

// XML 1.0 forbids most control characters even escaped: they are dropped.
const esc = (s: string) => s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g, '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function rfc822(date: string): string {
  const d = new Date(date);
  return Number.isNaN(d.getTime()) ? '' : d.toUTCString();
}

export function GET() {
  const items = latest(20).map((e) => {
    const when = e.date ? rfc822(e.date) : '';
    return `<item><title>${esc(e.title)}</title><link>${esc(absolute(e.path))}</link><guid>${esc(absolute(e.path))}</guid>` +
      (when ? `<pubDate>${when}</pubDate>` : '') + (e.summary ? `<description>${esc(e.summary)}</description>` : '') + `</item>`;
  }).join('');
  const body = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>${esc(config.title)}</title>` +
    `<link>${esc(absolute(''))}</link><description>${esc(config.tagline ?? config.title)}</description>` +
    `<language>${esc(config.language)}</language>${items}</channel></rss>\n`;
  return new Response(body, { headers: { 'Content-Type': 'application/xml; charset=utf-8' } });
}
