import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

// Strict Content-Security-Policy for the production build only. The dev server injects inline
// scripts for hot reload, so the policy is added at build time. No third-party origins are needed:
// fonts and icons are bundled, and the API is same-origin.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-src 'none'",
].join('; ');

function cspPlugin(): Plugin {
  return {
    name: 'wtd-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace('<!-- CSP -->', `<meta http-equiv="Content-Security-Policy" content="${CSP}" />`);
    },
  };
}

const apiProxy = {
  '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false },
};

export default defineConfig({
  base: './',
  plugins: [react(), cspPlugin()],
  server: { port: 5173, strictPort: false, proxy: apiProxy },
  preview: { port: 4173, proxy: apiProxy },
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, assetsInlineLimit: 0 },
});
