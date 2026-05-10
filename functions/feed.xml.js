/**
 * Google Merchant Center Product Feed
 * Served at: https://maxicompra.cl/feed.xml
 * Format: RSS 2.0 with Google Base namespace (g:)
 * Cache: 1 hour
 */

function esc(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export async function onRequest() {
  let products = [];
  try {
    const res = await fetch('https://maxicompra-api.elflaco0800.workers.dev/api/products');
    const data = await res.json();
    products = data.products || [];
  } catch {
    return new Response('Error fetching products', { status: 502 });
  }

  const today = new Date().toISOString().slice(0, 10);

  const items = products
    .filter(p => p.visible !== false && p.name && p.price > 0 && p.slug)
    .map(p => {
      const imageUrl = p.imgs && p.imgs.find(u => u && u.startsWith('http'));
      const price    = Math.round(p.price);
      const desc     = esc((p.desc || p.name).slice(0, 5000));
      const brand    = esc(p.brand || 'Maxicompra');
      const cat      = esc(p.cat || 'General');

      return `    <item>
      <g:id>${esc(p.id)}</g:id>
      <g:title>${esc(p.name)}</g:title>
      <g:description>${desc}</g:description>
      <g:link>https://maxicompra.cl/p/${esc(p.slug)}</g:link>
      ${imageUrl ? `<g:image_link>${esc(imageUrl)}</g:image_link>` : ''}
      <g:price>${price} CLP</g:price>
      <g:availability>in stock</g:availability>
      <g:condition>new</g:condition>
      <g:brand>${brand}</g:brand>
      <g:google_product_category>${cat}</g:google_product_category>
      <g:identifier_exists>no</g:identifier_exists>
    </item>`;
    }).join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:g="http://base.google.com/ns/1.0">
  <channel>
    <title>Maxicompra.cl</title>
    <link>https://maxicompra.cl</link>
    <description>Tienda online de electrónica, hogar y tecnología. Envíos a todo Chile.</description>
${items}
  </channel>
</rss>`;

  return new Response(xml, {
    headers: {
      'Content-Type': 'application/rss+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
