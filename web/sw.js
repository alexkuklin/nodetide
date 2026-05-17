/**
 * Service Worker - offline support for Nodetide web client
 */

const CACHE_NAME = 'nodetide-v6';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/js/app.js',
  '/manifest.json',
  '/icon.svg',
];

// Install - cache static assets only
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      // Cache static assets individually to handle failures gracefully
      for (const url of STATIC_ASSETS) {
        try {
          await cache.add(url);
        } catch (e) {
          console.warn('Failed to cache:', url, e);
        }
      }
    })
  );

  // Activate immediately
  self.skipWaiting();
});

// Activate - clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );

  // Take control immediately
  self.clients.claim();
});

// Fetch - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Skip non-GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  // CDN requests - pass through to network (don't intercept)
  if (url.hostname.includes('cdn.jsdelivr.net')) {
    return;
  }

  // API requests - network first, no cache
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).catch(() => {
        return new Response(
          JSON.stringify({ error: 'Offline', offline: true }),
          {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      })
    );
    return;
  }

  // Static assets - cache first, fallback to network
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Return cached, but also update cache in background
        event.waitUntil(
          fetch(event.request).then((networkResponse) => {
            if (networkResponse.ok) {
              caches.open(CACHE_NAME).then((cache) => {
                cache.put(event.request, networkResponse);
              });
            }
          }).catch(() => {})
        );
        return cachedResponse;
      }

      // Not in cache - fetch from network and cache
      return fetch(event.request).then((networkResponse) => {
        if (networkResponse.ok) {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      });
    })
  );
});

// Handle messages from the client
self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }

  if (event.data === 'clearCache') {
    caches.delete(CACHE_NAME).then(() => {
      event.ports[0].postMessage({ cleared: true });
    });
  }
});

// Background sync for queued messages
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-messages') {
    event.waitUntil(syncMessages());
  }
});

async function syncMessages() {
  // Get queued messages from IndexedDB
  // This would be implemented with actual IndexedDB access
  console.log('Background sync: syncing queued messages');
}

// Push notifications (for future use)
self.addEventListener('push', (event) => {
  if (!event.data) return;

  const data = event.data.json();

  event.waitUntil(
    self.registration.showNotification(data.title || 'Nodetide', {
      body: data.body,
      icon: '/icon-192.png',
      badge: '/badge-72.png',
      tag: data.tag || 'default',
      data: data.data,
    })
  );
});

// Notification click
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((clientList) => {
      // Focus existing window if available
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      // Otherwise open new window
      return clients.openWindow('/');
    })
  );
});
