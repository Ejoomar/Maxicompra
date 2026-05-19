/**
 * Maxicompra — Cloudflare Pages Middleware
 * Intercepta requests de bots (Googlebot, etc.) y devuelve HTML pre-renderizado
 * con contenido real de producto/categoría en vez de la SPA vacía.
 *
 * Esto resuelve el problema crítico de crawlabilidad: la SPA tarda 4-7 segundos
 * en renderizar contenido real, y bots no siempre esperan tanto.
 */

const BOT_UA = /Googlebot|Bingbot|Slurp|DuckDuckBot|Applebot|facebookexternalhit|Twitterbot|LinkedInBot|YandexBot|WhatsApp/i;
const WORKER_API = 'https://maxicompra-api.elflaco0800.workers.dev';
const SITE = 'https://maxicompra.cl';

/* ── Helpers ──────────────────────────────────────────────────── */

function esc(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fp(n) {
  return '$' + Math.round(n || 0).toLocaleString('es-CL');
}

function _toSlug(str) {
  return (str || '').toLowerCase()
    .replace(/[áàäâ]/g, 'a').replace(/[éèëê]/g, 'e').replace(/[íìïî]/g, 'i')
    .replace(/[óòöô]/g, 'o').replace(/[úùüû]/g, 'u').replace(/ñ/g, 'n')
    .replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-')
    .slice(0, 60).replace(/^-|-$/, '');
}

function baseHead({ title, desc, canonical, ogType = 'website', ogImage = `${SITE}/og.png`, schema = [] }) {
  const schemaBlocks = schema
    .map(s => `<script type="application/ld+json">${JSON.stringify(s)}</script>`)
    .join('\n');
  return `<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta property="og:type" content="${ogType}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${esc(canonical)}">
<meta property="og:image" content="${esc(ogImage)}">
<meta property="og:site_name" content="Maxicompra.cl">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(desc)}">
<meta name="twitter:image" content="${esc(ogImage)}">
<link rel="canonical" href="${esc(canonical)}">
<link rel="alternate" hreflang="es-CL" href="${esc(canonical)}">
${schemaBlocks}
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fafaf7;color:#1a1a2e;line-height:1.6;padding:0 16px}
  .wrap{max-width:900px;margin:0 auto;padding:24px 0 60px}
  nav{font-size:13px;color:#888;margin-bottom:20px}
  nav a{color:#E8175D;text-decoration:none}
  h1{font-size:clamp(1.3rem,4vw,2rem);font-weight:700;margin-bottom:8px;color:#0f0f1a}
  .price{font-size:1.8rem;font-weight:800;color:#E8175D;margin:16px 0}
  .product-img{width:100%;max-width:400px;height:auto;border-radius:12px;background:#f0f0f0;display:block;margin-bottom:24px}
  .desc{color:#555;margin-bottom:20px;font-size:15px}
  .meta{font-size:13px;color:#888;margin-bottom:6px}
  .cta{display:inline-block;background:#E8175D;color:#fff;text-decoration:none;padding:14px 28px;border-radius:10px;font-weight:600;font-size:15px;margin-top:16px}
  .products{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:16px;margin-top:24px}
  .prod-card{background:#fff;border-radius:10px;padding:14px;text-decoration:none;color:inherit;box-shadow:0 1px 4px rgba(0,0,0,.08)}
  .prod-card img{width:100%;aspect-ratio:1;object-fit:contain;border-radius:6px;background:#f5f5f5}
  .prod-card h2{font-size:13px;margin:10px 0 4px;font-weight:500;line-height:1.4}
  .prod-card .p{font-size:14px;font-weight:700;color:#E8175D}
  .cat-title{font-size:1.4rem;font-weight:700;margin-bottom:4px;color:#0f0f1a}
  .cat-desc{font-size:14px;color:#666;margin-bottom:20px}
</style>
</head>`;
}

/* ── Prerender: Producto ────────────────────────────────────────── */

function renderProduct(p) {
  const img = p.imgs?.find(u => u?.startsWith('http')) || '';
  const slug = p.slug || _toSlug(p.name) + '-' + (p.id || '').slice(-4);
  const catSlug = _toSlug(p.cat || '');
  const canonical = `${SITE}/p/${slug}`;
  const title = `${p.name} — Maxicompra.cl`;
  const desc = (p.desc || p.name || '').slice(0, 160);
  const price = Math.round(p.price || 0);

  const schema = [
    {
      '@context': 'https://schema.org',
      '@type': 'Product',
      name: p.name,
      url: canonical,
      image: img ? [img] : undefined,
      description: p.desc || p.name,
      brand: p.brand ? { '@type': 'Brand', name: p.brand } : undefined,
      offers: {
        '@type': 'Offer',
        price,
        priceCurrency: 'CLP',
        availability: 'https://schema.org/InStock',
        url: canonical,
      },
    },
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Inicio', item: `${SITE}/` },
        { '@type': 'ListItem', position: 2, name: p.cat || 'Productos', item: `${SITE}/c/${catSlug}` },
        { '@type': 'ListItem', position: 3, name: p.name, item: canonical },
      ],
    },
  ];

  return `<!DOCTYPE html>
<html lang="es">
${baseHead({ title, desc, canonical, ogType: 'product', ogImage: img || `${SITE}/og.png`, schema })}
<body>
<div class="wrap">
  <nav aria-label="Migas de pan">
    <a href="/">Inicio</a> ›
    <a href="/c/${esc(catSlug)}">${esc(p.cat || 'Productos')}</a> ›
    ${esc(p.name)}
  </nav>
  ${img ? `<img class="product-img" src="${esc(img)}" alt="${esc(p.name)}" width="400" height="400" loading="eager" fetchpriority="high">` : ''}
  <h1>${esc(p.name)}</h1>
  ${p.brand ? `<p class="meta">Marca: <strong>${esc(p.brand)}</strong></p>` : ''}
  <div class="price">${fp(price)}</div>
  ${p.desc ? `<p class="desc">${esc(p.desc)}</p>` : ''}
  <a class="cta" href="/p/${esc(slug)}">Ver producto en Maxicompra →</a>
</div>
</body>
</html>`;
}

/* ── Prerender: Categoría ───────────────────────────────────────── */

function renderCategory(catId, products) {
  const catName = products[0]?.cat || catId;
  const canonical = `${SITE}/c/${catId}`;
  const title = `${catName} — Maxicompra.cl`;
  const desc = `Los mejores productos de ${catName} al mejor precio. Envío a todo Chile.`;

  const schema = [
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Inicio', item: `${SITE}/` },
        { '@type': 'ListItem', position: 2, name: catName, item: canonical },
      ],
    },
    {
      '@context': 'https://schema.org',
      '@type': 'ItemList',
      name: catName,
      url: canonical,
      numberOfItems: products.length,
      itemListElement: products.slice(0, 50).map((p, i) => ({
        '@type': 'ListItem',
        position: i + 1,
        name: p.name,
        url: `${SITE}/p/${p.slug || _toSlug(p.name) + '-' + (p.id || '').slice(-4)}`,
      })),
    },
  ];

  const cards = products.slice(0, 48).map(p => {
    const img = p.imgs?.find(u => u?.startsWith('http')) || '';
    const slug = p.slug || _toSlug(p.name) + '-' + (p.id || '').slice(-4);
    return `<a class="prod-card" href="/p/${esc(slug)}">
      ${img ? `<img src="${esc(img)}" alt="${esc(p.name)}" width="180" height="180" loading="lazy">` : '<div style="aspect-ratio:1;background:#f0f0f0;border-radius:6px"></div>'}
      <h2>${esc(p.name)}</h2>
      <div class="p">${fp(p.price)}</div>
    </a>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="es">
${baseHead({ title, desc, canonical, schema })}
<body>
<div class="wrap">
  <nav aria-label="Migas de pan"><a href="/">Inicio</a> › ${esc(catName)}</nav>
  <h1 class="cat-title">${esc(catName)}</h1>
  <p class="cat-desc">${esc(desc)}</p>
  <div class="products">${cards}</div>
  <br>
  <a class="cta" href="/c/${esc(catId)}">Ver todos en Maxicompra →</a>
</div>
</body>
</html>`;
}

/* ── Entry point ─────────────────────────────────────────────────── */

export async function onRequest(context) {
  const ua = context.request.headers.get('user-agent') || '';
  const url = new URL(context.request.url);
  const path = url.pathname;

  // Usuarios normales en rutas SPA → servir index.html directamente
  if (!BOT_UA.test(ua) && (path.startsWith('/p/') || path.startsWith('/c/'))) {
    return context.env.ASSETS.fetch(new Request(new URL('/', context.request.url).toString(), context.request));
  }

  // Solo interceptar requests de bots reconocidos
  if (!BOT_UA.test(ua)) return context.next();

  /* Producto: /p/{slug} */
  if (path.startsWith('/p/')) {
    const slug = path.slice(3);
    if (!slug || slug.length > 120) return context.next();

    try {
      const res = await fetch(`${WORKER_API}/api/product/slug/${encodeURIComponent(slug)}`, {
        headers: { 'User-Agent': 'MaxicompraBot/1.0 (Cloudflare Pages Middleware)' },
        cf: { cacheTtl: 3600, cacheEverything: true },
      });
      if (!res.ok) return context.next();
      const data = await res.json();
      if (!data?.product) return context.next();

      return new Response(renderProduct(data.product), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=3600, s-maxage=86400, stale-while-revalidate=3600',
          'X-Robots-Tag': 'index, follow',
          'X-Prerendered': '1',
        },
      });
    } catch {
      return context.next();
    }
  }

  /* Categoría: /c/{catId} */
  if (path.startsWith('/c/')) {
    const catId = path.slice(3);
    if (!catId || catId.length > 80) return context.next();

    try {
      const res = await fetch(`${WORKER_API}/api/products`, {
        headers: { 'User-Agent': 'MaxicompraBot/1.0 (Cloudflare Pages Middleware)' },
        cf: { cacheTtl: 3600, cacheEverything: true },
      });
      if (!res.ok) return context.next();
      const data = await res.json();
      const all = data?.products || [];
      const filtered = all.filter(p => p.visible !== false && _toSlug(p.cat || '') === catId);
      if (!filtered.length) return context.next();

      return new Response(renderCategory(catId, filtered), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=1800, s-maxage=43200, stale-while-revalidate=3600',
          'X-Robots-Tag': 'index, follow',
          'X-Prerendered': '1',
        },
      });
    } catch {
      return context.next();
    }
  }

  return context.next();
}
