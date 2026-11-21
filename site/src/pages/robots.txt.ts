import { absolute } from '../lib/input';

export function GET() {
  return new Response(`User-agent: *\nAllow: /\nSitemap: ${absolute('').replace(/\/$/, '')}/sitemap.xml\n`,
    { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
