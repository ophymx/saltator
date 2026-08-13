// A ~40-line client-side router.
//
// The console has six screens; a routing library would be more code than
// the routes. Paths are real (not hash fragments) because the server's
// embed serves `index.html` for any path without a file extension, so a
// reload or a pasted link lands on the right screen.

/// Must match `saltator_cs_api::ADMIN_UI_PREFIX` and Vite's `base`.
export const BASE = '/_saltator/admin/ui';

function currentPath(): string {
  const path = location.pathname.startsWith(BASE)
    ? location.pathname.slice(BASE.length)
    : location.pathname;
  if (path === '' || path === '/') return '/';
  return path.endsWith('/') ? path.slice(0, -1) : path;
}

export const route = $state({ path: currentPath() });

export function href(to: string): string {
  return `${BASE}${to === '/' ? '/' : to}`;
}

export function navigate(to: string): void {
  history.pushState({}, '', href(to));
  route.path = currentPath();
}

/// `onclick` for in-app links: keeps the anchor a real link (middle-click
/// and "open in new tab" still work) while handling the ordinary click
/// without a page load.
export function link(event: MouseEvent): void {
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
  const anchor = (event.currentTarget as HTMLAnchorElement).getAttribute('href');
  if (anchor === null) return;
  event.preventDefault();
  navigate(anchor.startsWith(BASE) ? anchor.slice(BASE.length) || '/' : anchor);
}

window.addEventListener('popstate', () => {
  route.path = currentPath();
});
