/**
 * Maxicompra API — Cloudflare Worker
 * Secrets: ADMIN_PASSWORD_HASH, JWT_SECRET, MP_ACCESS_TOKEN, RESEND_API_KEY
 * KV: ORDERS, CONFIG
 */

// ─── CORS ────────────────────────────────────────────────────────────────────

function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  // Permitir cualquier subdominio de maxicompra y pages.dev en desarrollo
  const isAllowed = origin === 'https://maxicompra.cl'
    || origin === 'https://www.maxicompra.cl'
    || origin.endsWith('.maxicompra.pages.dev')
    || origin === 'https://maxicompra.pages.dev';
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : 'https://maxicompra.cl',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// ─── Utilidades ──────────────────────────────────────────────────────────────

function json(data, status = 200, req = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(req) },
  });
}

function err(msg, status = 400, req = null) {
  return json({ ok: false, error: msg }, status, req);
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes,
      new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const pl = JSON.parse(atob(body));
    if (pl.exp && Date.now() > pl.exp) return null;
    return pl;
  } catch { return null; }
}

async function requireAuth(request, env) {
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '');
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET);
}

function genOrderId() {
  return `MC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2,6).toUpperCase()}`;
}

// ─── Cupones ─────────────────────────────────────────────────────────────────

const DEFAULT_COUPONS = {
  BIENVENIDA10:  { pct: 10, active: true, desc: '10% descuento bienvenida' },
  MAXIDESCUENTO: { pct: 15, active: true, desc: '15% descuento especial' },
  PRIMERACOMPRA: { pct: 10, active: true, desc: '10% primera compra' },
};

async function getCoupons(env) {
  try { return (await env.CONFIG.get('coupons', 'json')) || DEFAULT_COUPONS; }
  catch { return DEFAULT_COUPONS; }
}

// ─── Email (Resend) ───────────────────────────────────────────────────────────

async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) return; // silently skip if not configured
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'Maxicompra <pedidos@maxicompra.cl>', to, subject, html }),
  });
}

function emailOrderConfirmation(order) {
  const items = order.items.map(i =>
    `<tr><td style="padding:8px;border-bottom:1px solid #eee">${i.name}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:center">${i.qty}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:right">$${i.price.toLocaleString('es-CL')}</td></tr>`
  ).join('');
  const payNames = { webpay: 'Webpay Plus', mp: 'Mercado Pago', transfer: 'Transferencia', cash: 'Efectivo' };
  return `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:20px">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden">
    <div style="background:#E8175D;padding:28px 32px;text-align:center">
      <h1 style="color:#fff;margin:0;font-size:24px">¡Pedido recibido!</h1>
      <p style="color:rgba(255,255,255,.85);margin:6px 0 0">Orden #${order.id}</p>
    </div>
    <div style="padding:28px 32px">
      <p style="color:#333">Hola <strong>${order.customer.name}</strong>, confirmamos tu pedido en Maxicompra.</p>
      <table style="width:100%;border-collapse:collapse;margin:20px 0">
        <thead><tr style="background:#f8f8f8">
          <th style="padding:8px;text-align:left;font-size:13px">Producto</th>
          <th style="padding:8px;text-align:center;font-size:13px">Cant.</th>
          <th style="padding:8px;text-align:right;font-size:13px">Precio</th>
        </tr></thead>
        <tbody>${items}</tbody>
      </table>
      ${order.discount ? `<p style="color:#22c55e;font-size:14px">Descuento aplicado: -${order.discount}%</p>` : ''}
      <p style="font-size:20px;font-weight:700;color:#E8175D;text-align:right">Total: $${order.total.toLocaleString('es-CL')}</p>
      <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
      <p style="color:#555;font-size:14px"><strong>Método de pago:</strong> ${payNames[order.payment] || order.payment}</p>
      <p style="color:#555;font-size:14px"><strong>Dirección:</strong> ${order.customer.address || '—'}</p>
      ${order.payment === 'mp' ? '<div style="background:#e8f5e9;border-radius:8px;padding:14px;margin-top:16px"><p style="color:#2e7d32;margin:0;font-size:14px">✅ Completa tu pago en Mercado Pago para confirmar el despacho.</p></div>' : ''}
      ${order.payment === 'transfer' ? `<div style="background:#e3f2fd;border-radius:8px;padding:14px;margin-top:16px">
        <p style="color:#1565c0;margin:0 0 6px;font-size:14px"><strong>Datos para transferencia:</strong></p>
        <p style="color:#1565c0;margin:0;font-size:13px">Banco: Mercado Pago · Titular: Maxicompra SpA<br>RUT: 78.219.298-1 · Cuenta Vista: 1086521092<br>Email: maxicompraoficial23@gmail.com</p>
      </div>` : ''}
    </div>
    <div style="background:#f8f8f8;padding:18px 32px;text-align:center">
      <p style="color:#888;font-size:12px;margin:0">Maxicompra.cl · maxicompraoficial23@gmail.com</p>
    </div>
  </div></body></html>`;
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async function handleHealth(request, env) {
  return json({ ok: true, store: env.STORE_NAME || 'Maxicompra', version: '1.1.0',
    mp: !!env.MP_ACCESS_TOKEN, email: !!env.RESEND_API_KEY, ts: new Date().toISOString() }, 200, request);
}

// POST /api/order
async function handleCreateOrder(request, env) {
  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }

  const { items, customer, payment, coupon, total } = body;
  if (!items?.length)       return err('items requeridos', 400, request);
  if (!customer?.name)      return err('nombre requerido', 400, request);
  if (!customer?.phone)     return err('teléfono requerido', 400, request);
  if (!payment)             return err('método de pago requerido', 400, request);
  if (!total || total <= 0) return err('total inválido', 400, request);

  let discount = 0;
  if (coupon) {
    const coupons = await getCoupons(env);
    const c = coupons[coupon.toUpperCase()];
    if (!c || !c.active) return err('Cupón inválido o expirado', 400, request);
    discount = c.pct;
  }

  const orderId = genOrderId();
  const order = {
    id: orderId, status: 'pending', items, customer, payment,
    coupon: coupon?.toUpperCase() || null, discount, total,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  };

  await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: 90 * 24 * 60 * 60 });

  // Índice diario
  const dateKey = `date:${new Date().toISOString().slice(0, 10)}`;
  const existing = await env.ORDERS.get(dateKey, 'json') || [];
  existing.push(orderId);
  await env.ORDERS.put(dateKey, JSON.stringify(existing), { expirationTtl: 90 * 24 * 60 * 60 });

  // WhatsApp link
  const itemsText = items.map(i => `• ${i.name} x${i.qty} — $${i.price.toLocaleString('es-CL')}`).join('\n');
  const waMsg = encodeURIComponent(
    `*🛒 Nuevo pedido ${orderId}*\n\n${itemsText}\n\n*Total: $${total.toLocaleString('es-CL')}*\n\nCliente: ${customer.name}\nTel: ${customer.phone}\nPago: ${payment}`
  );
  const waUrl = `https://wa.me/${env.WHATSAPP_NUMBER || '56958498763'}?text=${waMsg}`;

  // Email de confirmación (no-wait)
  if (customer.email) {
    sendEmail(env, {
      to: customer.email,
      subject: `Maxicompra — Pedido #${orderId} recibido`,
      html: emailOrderConfirmation(order),
    }).catch(() => {});
  }

  return json({ ok: true, orderId, waUrl, status: 'pending',
    message: 'Orden creada. Completa el pago para confirmar.' }, 200, request);
}

// GET /api/order/:id
async function handleGetOrder(orderId, request, env) {
  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return err('Orden no encontrada', 404, request);
  const { customer, items, total, status, discount, coupon, createdAt, payment } = order;
  return json({ ok: true, order: { id: orderId, customer, items, total, status, discount, coupon, createdAt, payment } }, 200, request);
}

// GET /api/coupon/:code
async function handleValidateCoupon(code, request, env) {
  const coupons = await getCoupons(env);
  const c = coupons[code.toUpperCase()];
  if (!c || !c.active) return json({ ok: false, valid: false }, 200, request);
  return json({ ok: true, valid: true, pct: c.pct, desc: c.desc }, 200, request);
}

// POST /api/admin/login
async function handleAdminLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }
  if (!body.password) return err('Contraseña requerida', 400, request);

  const hash = await sha256(body.password);
  if (hash !== env.ADMIN_PASSWORD_HASH) return err('Credenciales incorrectas', 401, request);

  const token = await signToken(
    { role: 'admin', exp: Date.now() + 8 * 60 * 60 * 1000 },
    env.JWT_SECRET
  );
  return json({ ok: true, token, expiresIn: '8h' }, 200, request);
}

// GET /api/admin/orders
async function handleListOrders(request, env) {
  const payload = await requireAuth(request, env);
  if (!payload) return err('No autorizado', 401, request);

  const url = new URL(request.url);
  const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const orderIds = await env.ORDERS.get(`date:${date}`, 'json') || [];
  const orders = await Promise.all(orderIds.map(id => env.ORDERS.get(id, 'json')));
  return json({ ok: true, date, orders: orders.filter(Boolean) }, 200, request);
}

// PATCH /api/admin/order/:id/status
async function handleUpdateOrderStatus(request, orderId, env) {
  const payload = await requireAuth(request, env);
  if (!payload) return err('No autorizado', 401, request);

  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return err('Orden no encontrada', 404, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }

  const VALID = ['pending', 'paid', 'shipped', 'delivered', 'cancelled', 'payment_pending', 'payment_failed'];
  if (!VALID.includes(body.status)) return err('Estado inválido', 400, request);

  order.status = body.status;
  order.updatedAt = new Date().toISOString();
  await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: 90 * 24 * 60 * 60 });

  // Email cuando se marca como enviado
  if (body.status === 'shipped' && order.customer?.email) {
    sendEmail(env, {
      to: order.customer.email,
      subject: `Maxicompra — Tu pedido #${orderId} fue enviado 🚚`,
      html: `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:28px">
        <h2 style="color:#E8175D">¡Tu pedido está en camino!</h2>
        <p>Hola ${order.customer.name}, tu pedido <strong>#${orderId}</strong> ha sido despachado.</p>
        <p>Recibirás tu compra en 24-48 horas hábiles.</p>
        <p style="color:#888;font-size:13px">Maxicompra.cl</p>
      </div>`,
    }).catch(() => {});
  }

  return json({ ok: true, orderId, status: order.status }, 200, request);
}

// POST /api/admin/coupon
async function handleUpsertCoupon(request, env) {
  const payload = await requireAuth(request, env);
  if (!payload) return err('No autorizado', 401, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }
  if (!body.code) return err('code requerido', 400, request);

  const coupons = await getCoupons(env);
  coupons[body.code.toUpperCase()] = {
    pct: body.pct ?? coupons[body.code.toUpperCase()]?.pct ?? 10,
    active: body.active ?? true,
    desc: body.desc || '',
  };
  await env.CONFIG.put('coupons', JSON.stringify(coupons));
  return json({ ok: true, code: body.code.toUpperCase(), coupon: coupons[body.code.toUpperCase()] }, 200, request);
}

// POST /api/payment/preference
async function handleMPPreference(request, env) {
  if (!env.MP_ACCESS_TOKEN) return err('Mercado Pago no configurado', 503, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }

  const { orderId, items, payer } = body;
  if (!orderId || !items?.length) return err('orderId e items requeridos', 400, request);

  const preference = {
    items: items.map(i => ({
      title: String(i.title || i.name).substring(0, 256),
      quantity: Number(i.quantity || i.qty) || 1,
      unit_price: Number(i.unit_price || i.price),
      currency_id: 'CLP',
    })),
    payer: payer?.email ? { email: payer.email } : undefined,
    external_reference: orderId,
    back_urls: {
      success: `https://maxicompra.cl?payment=success&order=${orderId}`,
      failure: `https://maxicompra.cl?payment=failure&order=${orderId}`,
      pending: `https://maxicompra.cl?payment=pending&order=${orderId}`,
    },
    auto_return: 'approved',
    notification_url: 'https://maxicompra-api.elflaco0800.workers.dev/api/payment/webhook',
    statement_descriptor: 'MAXICOMPRA',
  };

  const mpRes = await fetch('https://api.mercadopago.com/checkout/preferences', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.MP_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
      'X-Idempotency-Key': orderId,
    },
    body: JSON.stringify(preference),
  });

  const mpData = await mpRes.json();
  if (!mpRes.ok) return err(`Error MP: ${mpData.message || mpRes.status}`, 502, request);

  // Actualizar orden
  const order = await env.ORDERS.get(orderId, 'json');
  if (order) {
    order.mp_preference_id = mpData.id;
    order.status = 'payment_pending';
    order.updatedAt = new Date().toISOString();
    await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: 90 * 24 * 60 * 60 });
  }

  return json({
    ok: true,
    preference_id: mpData.id,
    init_point: mpData.init_point,
    sandbox_init_point: mpData.sandbox_init_point,
  }, 200, request);
}

// POST /api/payment/webhook
async function handleMPWebhook(request, env) {
  if (!env.MP_ACCESS_TOKEN) return new Response('OK', { status: 200 });

  const url = new URL(request.url);
  const type   = url.searchParams.get('type') || url.searchParams.get('topic');
  const dataId = url.searchParams.get('data.id') || url.searchParams.get('id');
  if (type !== 'payment' || !dataId) return new Response('OK', { status: 200 });

  const payRes = await fetch(`https://api.mercadopago.com/v1/payments/${dataId}`, {
    headers: { 'Authorization': `Bearer ${env.MP_ACCESS_TOKEN}` },
  });
  if (!payRes.ok) return new Response('OK', { status: 200 });

  const payment = await payRes.json();
  const orderId = payment.external_reference;
  if (!orderId) return new Response('OK', { status: 200 });

  const order = await env.ORDERS.get(orderId, 'json');
  if (order) {
    const statusMap = { approved: 'paid', pending: 'payment_pending', rejected: 'payment_failed' };
    order.status = statusMap[payment.status] || payment.status;
    order.mp_payment_id = payment.id;
    order.mp_payment_status = payment.status;
    order.updatedAt = new Date().toISOString();
    await env.ORDERS.put(orderId, JSON.stringify(order), { expirationTtl: 90 * 24 * 60 * 60 });

    // Email confirmación pago
    if (payment.status === 'approved' && order.customer?.email) {
      sendEmail(env, {
        to: order.customer.email,
        subject: `Maxicompra — ¡Pago confirmado! Pedido #${orderId}`,
        html: emailOrderConfirmation({ ...order, status: 'paid' }),
      }).catch(() => {});
    }
  }

  return new Response('OK', { status: 200 });
}

// ─── Router ──────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (path === '/api/health'                                   && method === 'GET')   return handleHealth(request, env);
    if (path === '/api/order'                                    && method === 'POST')  return handleCreateOrder(request, env);
    if (path.startsWith('/api/order/')                           && method === 'GET')   return handleGetOrder(path.split('/')[3], request, env);
    if (path.startsWith('/api/coupon/')                          && method === 'GET')   return handleValidateCoupon(path.split('/')[3], request, env);
    if (path === '/api/admin/login'                              && method === 'POST')  return handleAdminLogin(request, env);
    if (path === '/api/admin/orders'                             && method === 'GET')   return handleListOrders(request, env);
    if (path.startsWith('/api/admin/order/') && path.endsWith('/status') && method === 'PATCH') return handleUpdateOrderStatus(request, path.split('/')[4], env);
    if (path === '/api/admin/coupon'                             && method === 'POST')  return handleUpsertCoupon(request, env);
    if (path === '/api/payment/preference'                       && method === 'POST')  return handleMPPreference(request, env);
    if (path === '/api/payment/webhook'                          && method === 'POST')  return handleMPWebhook(request, env);

    return err('Ruta no encontrada', 404, request);
  },
};
