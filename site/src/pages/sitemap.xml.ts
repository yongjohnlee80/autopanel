// The sitemap: every public page, the home page first.
import { input, absolute } from '../lib/input';

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function GET() {
  const paths = ['', ...input.folders.map((f) => f.path), ...input.docs.map((d) => d.path)];
  const urls = paths.map((p) => `<url><loc>${esc(absolute(p))}</loc></url>`).join('');
  return new Response(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>\n`,
    { headers: { 'Content-Type': 'application/xml; charset=utf-8' } });
}
