import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The bundle is written straight into the embed crate, which is
// gitignored: `npm run build` here is exactly what CI's frontend job runs
// before cargo picks the directory up. See docs/design-admin-ui.md.
export default defineConfig({
  plugins: [svelte()],
  // Must match `saltator_cs_api::ADMIN_UI_PREFIX`: every asset URL in the
  // emitted index.html is resolved against it.
  base: '/_saltator/admin/ui/',
  build: {
    outDir: '../../crates/saltator-admin-ui/dist',
    // The output lives outside the project root, so this has to be
    // explicit or Vite refuses to clear it.
    emptyOutDir: true,
    // Nothing is served from a CDN and nothing loads remotely: the CSP is
    // `script-src 'self'` with no exceptions, so everything is inlined or
    // fingerprinted next to the shell.
    assetsInlineLimit: 4096,
    // No source maps: the bundle is embedded in the server binary, and
    // this is an operator tool, not something to debug in production.
    sourcemap: false,
  },
  server: {
    // `npm run dev` proxies the API to a locally running saltator, so the
    // console can be developed against a real server without embedding.
    proxy: {
      '/_saltator/admin/v1': 'http://127.0.0.1:8008',
      '/_matrix': 'http://127.0.0.1:8008',
    },
  },
});
