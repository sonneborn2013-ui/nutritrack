// Paydar — service worker: funciona sin internet y recibe avisos con la app cerrada.
// IMPORTANTE: cada vez que publiques cambios, sube el número de versión.
const CACHE = 'paydar-v2.1.0';
const ASSETS = ['./', './index.html', './app.js', './config.js', './styles.css', './manifest.webmanifest', './icon.svg', './icon-192.png', './icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== self.location.origin) return;
  e.respondWith(caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || fetch(e.request)));
});

// Aviso enviado por el servidor (recordatorio de pago)
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Paydar', {
    body: d.body || 'Tienes un pago próximo.',
    tag: d.tag || 'paydar',
    icon: 'icon-192.png',
    badge: 'icon-192.png',
    data: { url: './' },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((cs) =>
      cs.length ? cs[0].focus() : self.clients.openWindow('./')
    )
  );
});
