export async function onRequest() {
  const res = await fetch('https://maxicompra-api.elflaco0800.workers.dev/sitemap.xml');
  const xml = await res.text();
  return new Response(xml, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
