'use strict';

// Strona dodana do ekranu telefonu: zawsze najpierw sieć (świeże rozkazy i nowa wersja strony),
// a bez internetu ostatnia pobrana kopia. Plik z danymi jest zaszyfrowany tak samo jak na serwerze,
// więc kopia w telefonie nie zdradza niczego bez klucza. Odpowiedź z kopii ma nagłówek
// X-KPB-Offline, żeby strona mogła dopisać, że to stan sprzed utraty internetu.
const CACHE = 'moja-sluzba-v1';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    for (const name of await caches.keys()) {
      if (name !== CACHE) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET' || new URL(request.url).origin !== self.location.origin) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const key = request.mode === 'navigate' ? new Request('./') : new Request(request.url);
    try {
      // Zawsze pyta serwer, czy plik się zmienił, żeby po aktualizacji nie mieszać starych i nowych plików.
      const fresh = request.mode === 'navigate'
        ? new Request(request.url, { cache: 'no-cache' })
        : new Request(request, { cache: request.cache === 'no-store' ? 'no-store' : 'no-cache' });
      const response = await fetch(fresh);
      if (response.ok) await cache.put(key, response.clone());
      return response;
    } catch (error) {
      const cached = await cache.match(key, { ignoreSearch: true });
      if (!cached) throw error;
      const headers = new Headers(cached.headers);
      headers.set('X-KPB-Offline', '1');
      return new Response(await cached.blob(), { status: cached.status, statusText: cached.statusText, headers });
    }
  })());
});

// Przypomnienie z wysyłki (treść przychodzi zaszyfrowana, odszyfrowuje ją przeglądarka). Bez nazwisk.
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { /* zostaje treść domyślna */ }
  event.waitUntil(self.registration.showNotification(data.title || 'Moja służba', {
    body: data.body || 'Sprawdź swoją służbę.',
    tag: data.tag,
    icon: 'icon-192.png',
    data: { url: './' }
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil((async () => {
    const open = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (open.length > 0) return open[0].focus();
    return self.clients.openWindow('./');
  })());
});
