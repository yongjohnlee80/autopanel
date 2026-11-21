// The configuration's look as CSS variables. Each value was validated by the
// core (a colour is # and six hexadecimal digits; a font and a width are one
// of their words), so nothing here can leave the variable it is put in.
import { config } from '../lib/input';

const fonts: Record<string, string> = {
  serif: 'Georgia, "Times New Roman", serif',
  sans: 'system-ui, -apple-system, "Segoe UI", sans-serif',
  mono: 'ui-monospace, "SFMono-Regular", Menlo, monospace',
};
const widths: Record<string, string> = { narrow: '42rem', wide: '60rem' };
const colour = /^#[0-9a-fA-F]{6}$/;

export function GET() {
  const l = config.look ?? {};
  const vars: string[] = [];
  if (l.accent && colour.test(l.accent)) vars.push(`--accent: ${l.accent};`);
  if (l.background && colour.test(l.background)) vars.push(`--background: ${l.background};`);
  if (l.text && colour.test(l.text)) vars.push(`--text: ${l.text};`);
  if (l.font && fonts[l.font]) vars.push(`--font: ${fonts[l.font]};`);
  if (l.width && widths[l.width]) vars.push(`--width: ${widths[l.width]};`);
  return new Response(`:root { ${vars.join(' ')} }\n`, { headers: { 'Content-Type': 'text/css; charset=utf-8' } });
}
