// AutoPanel's site kit. A build runs in a container with no network; its
// output is checked by the core before anything of it is served
// (docs/decisions/site.md). Nothing here may put a script, a <style> or a
// style attribute on a page: the page's policy, set by the serving process,
// forbids them.
import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'static',
  // The output is the one place a build writes. Inside the project, so that
  // Astro keeps its prerendered files beside it, on the same file system.
  outDir: process.env.SITE_OUT ?? './dist',
  cacheDir: process.env.SITE_CACHE ?? '/tmp/astro-cache',
  trailingSlash: 'always',
  // A held document is built alone and read under a path of its own (its
  // address on the site's host, or /s/<site>/<address> on the app host): its
  // stylesheets and scripts are under that path too.
  base: process.env.SITE_BASE || undefined,
  build: {
    format: 'directory',
    inlineStylesheets: 'never', // a stylesheet is a file, never a <style> in the page
    assets: '_astro',
  },
  devToolbar: { enabled: false },
  // The core sets the page's policy as a header; Astro's own would be a
  // <meta http-equiv>, which the output check refuses.
  security: { csp: false },
});
