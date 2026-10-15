# Maxicompra — tienda web

SPA en HTML/CSS/JS vanilla servida por Cloudflare Pages, con un Worker (`worker/`) como API
(pedidos, Mercado Pago, admin, productos en KV).

## Estructura

```
index.html            Estructura HTML + meta/SEO (sin CSS ni JS inline pesado)
assets/css/main.css   Estilos
assets/js/app.js      Tienda: catálogo, carrito, checkout, búsqueda, PDP
assets/js/admin.js    Panel admin — se descarga SOLO al abrir /#__admin
sw.js                 Service worker (cache de assets, network-first para HTML)
_headers / _redirects Cabeceras de seguridad/caché y ruteo SPA (Cloudflare Pages)
functions/            Pages Functions: sitemap.xml, feed.xml, middleware
worker/               API (Cloudflare Worker): src/index.js + wrangler.toml
tools/                stamp.py (hashes), tests/, legacy/ (scripts one-off), data/ (ignorado)
```

## Flujo de trabajo

1. Editar `assets/` o `index.html`.
2. `python tools/stamp.py` — actualiza `?v=<hash>` en index.html, sw.js y app.js
   (cache-busting; los assets se sirven con `immutable`, así que **es obligatorio**).
3. `node --test tools/tests/order-total.test.mjs` — tests de la validación de pedidos.
4. Commit + push. CI (`.github/workflows/ci.yml`) verifica sintaxis, hashes y tests;
   push a `main` despliega Pages automáticamente.

El Worker se despliega aparte: `cd worker && npx wrangler deploy`
(secretos: `ADMIN_PASSWORD_HASH`, `JWT_SECRET`, `MP_ACCESS_TOKEN`, `MP_WEBHOOK_SECRET`, `RESEND_API_KEY`).

## Probar en local

`npx serve -p 5500 .` — la API rechaza `localhost` por CORS, así que el catálogo no carga
desde KV; inyectar productos desde la consola para probar la UI.
