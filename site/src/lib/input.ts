// What the core gives a build (core/site/build.go): the configuration, the
// index of public folders and documents at the paths the core chose, and the
// fragments the renderer made of each document's body. Read once, at build
// time; nothing here reaches the network.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const contentDir = process.env.SITE_CONTENT ?? '/input';
const fragmentsDir = process.env.SITE_FRAGMENTS ?? '/tmp/fragments';

export interface NavLink { label: string; to: string }
export interface Look { accent?: string; background?: string; text?: string; font?: string; width?: string; logo?: string }
export interface Config {
  title: string; tagline?: string; language: string; theme: 'journal' | 'docs';
  home: string; nav?: NavLink[]; footer?: string; look: Look;
}
export interface InputFolder { path: string; title?: string; order?: number; page: string }
export interface InputDoc {
  slug: string; path: string; folder: string; format: 'md' | 'xmd' | 'html'; order?: number;
  active?: boolean; meta?: Record<string, unknown>; source: string; dir: string; page: string; mermaid?: boolean;
}
export interface BuildInput { build: number; host: string; folders: InputFolder[]; docs: InputDoc[] }

function readJSON<T>(name: string): T {
  return JSON.parse(readFileSync(join(contentDir, name), 'utf8')) as T;
}

export const config: Config = readJSON<Config>('site.json');
export const input: BuildInput = readJSON<BuildInput>('build.json');

// A node, as the pages show it.
export interface Entry { kind: 'folder' | 'doc'; path: string; title: string; order: number; date?: string; summary?: string }

function metaString(m: Record<string, unknown> | undefined, key: string): string | undefined {
  const v = m?.[key];
  return typeof v === 'string' && v.length <= 300 ? v : undefined;
}

export function docTitle(d: InputDoc): string {
  return metaString(d.meta, 'title') ?? d.slug;
}

export function entryOfDoc(d: InputDoc): Entry {
  return { kind: 'doc', path: d.path, title: docTitle(d), order: d.order ?? 0,
    date: metaString(d.meta, 'date'), summary: metaString(d.meta, 'summary') };
}

export function entryOfFolder(f: InputFolder): Entry {
  return { kind: 'folder', path: f.path, title: f.title || f.path.split('/').pop() || f.path, order: f.order ?? 0 };
}

function parentOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

// children are a folder's public folders and documents, in their order.
export function children(folder: string): Entry[] {
  const out: Entry[] = [
    ...input.folders.filter((f) => parentOf(f.path) === folder).map(entryOfFolder),
    ...input.docs.filter((d) => d.folder === folder).map(entryOfDoc),
  ];
  return out.sort((a, b) => a.order - b.order || a.title.localeCompare(b.title));
}

// latest are the documents with a date, newest first.
export function latest(n: number): Entry[] {
  return input.docs.map(entryOfDoc).filter((e) => e.date)
    .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '')).slice(0, n);
}

// fragment is a document's body as the renderer made it; the output check
// reads the page it ends up in.
export function fragment(d: InputDoc): string {
  const f = join(fragmentsDir, d.path + '.html');
  return existsSync(f) ? readFileSync(f, 'utf8') : '';
}

export function href(path: string): string {
  return path === '' ? '/' : '/' + path + '/';
}

export function absolute(path: string): string {
  return 'https://' + input.host + href(path);
}
