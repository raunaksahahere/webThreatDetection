// Minimal hash router. Hash routing keeps deep links (#/r/<id>) working no matter how the backend
// serves dist/ (no server-side SPA fallback needed). Only internal paths are ever put in hrefs.
import { useSyncExternalStore } from 'react';

export type Route =
  | { name: 'investigate' }
  | { name: 'report'; id: string }
  | { name: 'history' }
  | { name: 'incidents' }
  | { name: 'notfound'; path: string };

function currentPath(): string {
  const raw = window.location.hash.replace(/^#/, '');
  const path = raw.split('?')[0] || '/';
  return path.startsWith('/') ? path : '/' + path;
}

export function parsePath(path: string): Route {
  if (path === '/' || path === '') return { name: 'investigate' };
  if (path === '/history') return { name: 'history' };
  if (path === '/incidents') return { name: 'incidents' };
  const m = /^\/r\/([^/]+)\/?$/.exec(path);
  if (m) {
    try {
      return { name: 'report', id: decodeURIComponent(m[1]) };
    } catch {
      return { name: 'notfound', path };
    }
  }
  return { name: 'notfound', path };
}

function subscribe(cb: () => void) {
  window.addEventListener('hashchange', cb);
  return () => window.removeEventListener('hashchange', cb);
}

export function usePath(): string {
  return useSyncExternalStore(subscribe, currentPath, () => '/');
}

export function useRoute(): Route {
  return parsePath(usePath());
}

/** Internal href for an app path, e.g. href('/r/abc') -> '#/r/abc'. */
export function href(path: string): string {
  return '#' + path;
}

export function reportPath(id: string): string {
  return '/r/' + encodeURIComponent(id);
}

export function navigate(path: string): void {
  window.location.hash = path;
  window.scrollTo({ top: 0 });
}
