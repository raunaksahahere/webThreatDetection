import { defineConfig, loadEnv, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

// Strict Content-Security-Policy for the production build only. The dev server injects inline
// scripts for hot reload, so the policy is added at build time. No third-party origins are needed:
// fonts and icons are bundled. The API is same-origin unless VITE_API_BASE names a separate backend
// (e.g. the Vercel dashboard talking to the Render API), which is then the only extra connect-src.
function apiOrigin(mode: string): string {
  const base = (loadEnv(mode, '.', 'VITE_').VITE_API_BASE ?? '').trim(); // includes VITE_* environment variables
  if (!base) return '';
  const u = new URL(base); // throws on a malformed value: fail the build rather than ship a broken CSP
  if (u.protocol !== 'https:' && u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') throw new Error('VITE_API_BASE must be https');
  return u.origin;
}

const cspFor = (mode: string) => [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  `connect-src 'self'${apiOrigin(mode) ? ' ' + apiOrigin(mode) : ''}`,
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-src 'none'",
].join('; ');

function cspPlugin(mode: string): Plugin {
  const csp = cspFor(mode);
  return {
    name: 'wtd-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace('<!-- CSP -->', `<meta http-equiv="Content-Security-Policy" content="${csp}" />`);
    },
  };
}

const apiProxy = {
  '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false },
};

export default defineConfig(({ mode }) => ({
  base: './',
  plugins: [react(), cspPlugin(mode)],
  server: { port: 5173, strictPort: false, proxy: apiProxy },
  preview: { port: 4173, proxy: apiProxy },
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, assetsInlineLimit: 0 },
}));
