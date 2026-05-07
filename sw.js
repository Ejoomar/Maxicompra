/* Maxicompra Service Worker — Cache-first para assets estáticos */
'use strict';

var CACHE = 'maxicompra-v1';
var SHELL = [
  './',
  './index.html',
  'https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/webfonts/fa-solid-900.woff2',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/webfonts/fa-brands-400.woff2'
];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE).then(function(c) { return c.addAll(SHELL.map(function(u){ return new Request(u, {mode:'no-cors'}); })); })
    .then(function(){ return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(keys.filter(function(k){ return k !== CACHE; }).map(function(k){ return caches.delete(k); }));
    }).then(function(){ return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function(e) {
  var url = e.request.url;
  // Skip non-GET, API calls, and Mercado Pago
  if (e.request.method !== 'GET') return;
  if (url.includes('maxicompra-api') || url.includes('mercadopago') || url.includes('sdk.mercadopago')) return;

  // index.html — Network-first (always fresh)
  if (url.endsWith('/') || url.endsWith('/index.html') || url.split('?')[0].endsWith('.html')) {
    e.respondWith(
      fetch(e.request).then(function(r) {
        var clone = r.clone();
        caches.open(CACHE).then(function(c){ c.put(e.request, clone); });
        return r;
      }).catch(function() { return caches.match(e.request); })
    );
    return;
  }

  // Everything else — Cache-first with network fallback
  e.respondWith(
    caches.match(e.request).then(function(cached) {
      if (cached) return cached;
      return fetch(e.request).then(function(r) {
        if (!r || r.status !== 200) return r;
        var clone = r.clone();
        caches.open(CACHE).then(function(c){ c.put(e.request, clone); });
        return r;
      });
    })
  );
});
