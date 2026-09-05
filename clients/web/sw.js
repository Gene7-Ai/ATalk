const SHELL = 'atalk-shell-v5';
const FILES = ['/', '/index.html', '/style.css', '/app.js', '/app/core.js', '/manifest.webmanifest'];
self.addEventListener('install', e => { e.waitUntil(caches.open(SHELL).then(c => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== SHELL).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.pathname.startsWith('/api/') || e.request.method !== 'GET') return;
  e.respondWith(fetch(e.request).then(r => { const copy = r.clone(); caches.open(SHELL).then(c => c.put(e.request, copy)).catch(() => {}); return r; }).catch(() => caches.match(e.request).then(m => m || caches.match('/index.html'))));
});
