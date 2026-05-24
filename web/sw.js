// WolfStack Service Worker — enables PWA install and offline shell.
// Bump CACHE_NAME on any change to SHELL_ASSETS or the fetch handler so
// every client's activate event evicts the stale cache and rebuilds.
const CACHE_NAME = 'wolfstack-v24.6.0';
const SHELL_ASSETS = [
    '/',
    '/index.html',
    '/login.html',
    '/css/style.css',
    '/js/app.js',
    '/js/vendor/three.min.js',
    '/images/wolfstack-logo.png',
    '/images/wolfstack-icon-192.png',
    '/images/wolfstack-icon-512.png',
    '/manifest.json',
];

// Cache shell assets on install
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS))
    );
    self.skipWaiting();
});

// Clean up old caches on activate
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
        )
    );
    self.clients.claim();
});

// Network-first strategy: try network, fall back to cache for shell assets
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Never cache API calls or WebSocket connections
    if (url.pathname.startsWith('/api/') || event.request.mode === 'websocket') {
        return;
    }

    event.respondWith(
        fetch(event.request)
            .then((response) => {
                // Cache successful responses for shell assets, but ONLY when:
                //   • status is 2xx (response.ok)
                //   • the response wasn't followed from a redirect — Cache.put
                //     rejects redirected responses with the "Failed to execute
                //     'put' on 'Cache': Cache.put() encountered a network
                //     error" we were seeing whenever an unauthenticated user
                //     hit `/` and the server 302'd them to `/login.html`
                //   • the response type is "basic" (same-origin, full body
                //     readable) — opaque cross-origin responses can't be put
                //     either. Belt and braces.
                // Defensive catch on the put itself so any other browser-
                // specific rejection doesn't bubble up as an uncaught
                // promise rejection in the console.
                if (response.ok
                    && !response.redirected
                    && response.type === 'basic'
                    && SHELL_ASSETS.includes(url.pathname))
                {
                    const clone = response.clone();
                    caches.open(CACHE_NAME)
                        .then((cache) => cache.put(event.request, clone))
                        .catch(() => { /* cache full / quota / browser quirk — non-fatal */ });
                }
                return response;
            })
            // Network failed — fall back to cache. caches.match resolves
            // to `undefined` when the request isn't cached; respondWith()
            // then throws "Failed to convert value to 'Response'". Always
            // hand back a real Response so the FetchEvent resolves cleanly.
            .catch(() => caches.match(event.request).then((cached) =>
                cached || new Response('Offline — resource not cached.', {
                    status: 503,
                    statusText: 'Service Unavailable',
                    headers: { 'Content-Type': 'text/plain' },
                })
            ))
    );
});
