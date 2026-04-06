/**
 * Maxicompra API — Cloudflare Worker v2.0
 * Secrets: ADMIN_PASSWORD_HASH, JWT_SECRET, MP_ACCESS_TOKEN, RESEND_API_KEY
 * Optional secrets: MP_WEBHOOK_SECRET (set in MP dashboard → Notificaciones → Webhook)
 * KV: ORDERS (orders + date indices), CONFIG (coupons, rate limits, token blacklist, webhooks)
 */

// ─── CORS ─────────────────────────────────────────────────────────────────────

function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const ALLOWED = new Set([
    'https://maxicompra.cl',
    'https://www.maxicompra.cl',
    'https://maxicompra.pages.dev',
  ]);
  const isAllowed = ALLOWED.has(origin) || origin.endsWith('.maxicompra.pages.dev');
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : 'null',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// ─── Utilities ────────────────────────────────────────────────────────────────

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

async function hmacSha256(message, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyToken(token, secret, env) {
  try {
    const [header, body, sig] = token.split('.');
    if (!header || !body || !sig) return null;

    // Check token blacklist (logout)
    const tokenId = await sha256(sig);
    const blacklisted = await env.CONFIG.get(`blacklist:${tokenId}`);
    if (blacklisted) return null;

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
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if (!token) return null;
  const payload = await verifyToken(token, env.JWT_SECRET, env);
  if (!payload) return null;
  return { payload, token };
}

function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0].trim()
    || 'unknown';
}

function genOrderId() {
  return `MC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2,6).toUpperCase()}`;
}

// ─── Rate Limiting (KV-based, sliding window) ────────────────────────────────

async function checkRateLimit(env, identifier, maxReqs, windowSecs) {
  const window = Math.floor(Date.now() / 1000 / windowSecs);
  const key = `rl:${identifier}:${window}`;
  try {
    const current = parseInt(await env.CONFIG.get(key) || '0', 10);
    if (current >= maxReqs) return false;
    await env.CONFIG.put(key, String(current + 1), { expirationTtl: windowSecs * 2 });
    return true;
  } catch { return true; } // fail open if KV unavailable
}

// ─── State Machine ───────────────────────────────────────────────────────────

const STATE_TRANSITIONS = {
  pending:         ['paid', 'payment_pending', 'payment_failed', 'cancelled'],
  payment_pending: ['paid', 'payment_failed', 'cancelled', 'pending'],
  payment_failed:  ['payment_pending', 'cancelled'],
  paid:            ['shipped', 'cancelled'],
  shipped:         ['delivered', 'cancelled'],
  delivered:       [],
  cancelled:       [],
};

function canTransition(from, to) {
  if (from === to) return false; // no-op transitions not allowed
  return (STATE_TRANSITIONS[from] || []).includes(to);
}

// ─── Coupons ──────────────────────────────────────────────────────────────────

const DEFAULT_COUPONS = {
  BIENVENIDA10:  { pct: 10, active: true, desc: '10% descuento bienvenida' },
  MAXIDESCUENTO: { pct: 15, active: true, desc: '15% descuento especial' },
  PRIMERACOMPRA: { pct: 10, active: true, desc: '10% primera compra' },
};

async function getCoupons(env) {
  try { return (await env.CONFIG.get('coupons', 'json')) || DEFAULT_COUPONS; }
  catch { return DEFAULT_COUPONS; }
}

// ─── Email Templates (Resend) ─────────────────────────────────────────────────

async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY || !to) return false;
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'Maxicompra <pedidos@maxicompra.cl>',
        to,
        subject,
        html,
      }),
    });
    return res.ok;
  } catch { return false; }
}

function emailBase(title, color, content) {
  return `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:20px">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden">
    <div style="background:${color};padding:28px 32px;text-align:center">
      <h1 style="color:#fff;margin:0;font-size:24px">${title}</h1>
    </div>
    <div style="padding:28px 32px">${content}</div>
    <div style="background:#f8f8f8;padding:18px 32px;text-align:center">
      <p style="color:#888;font-size:12px;margin:0">Maxicompra.cl &middot; maxicompraoficial23@gmail.com</p>
    </div>
  </div></body></html>`;
}

function emailOrderConfirmation(order) {
  const items = order.items.map(i =>
    `<tr><td style="padding:8px;border-bottom:1px solid #eee">${String(i.name).substring(0,100)}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:center">${Number(i.qty||1)}</td>
     <td style="padding:8px;border-bottom:1px solid #eee;text-align:right">$${Number(i.price).toLocaleString('es-CL')}</td></tr>`
  ).join('');
  const payNames = { webpay:'Webpay Plus', mp:'Mercado Pago', transfer:'Transferencia', cash:'Efectivo' };
  const content = `
    <p style="color:#333">Hola <strong>${order.customer.name}</strong>, confirmamos tu pedido en Maxicompra.</p>
    <p style="color:#555;font-size:13px">Orden <strong>#${order.id}</strong></p>
    <table style="width:100%;border-collapse:collapse;margin:20px 0">
      <thead><tr style="background:#f8f8f8">
        <th style="padding:8px;text-align:left;font-size:13px">Producto</th>
        <th style="padding:8px;text-align:center;font-size:13px">Cant.</th>
        <th style="padding:8px;text-align:right;font-size:13px">Precio</th>
      </tr></thead>
      <tbody>${items}</tbody>
    </table>
    ${order.discount ? `<p style="color:#22c55e;font-size:14px">Descuento aplicado: -${order.discount}%</p>` : ''}
    <p style="font-size:20px;font-weight:700;color:#E8175D;text-align:right">Total: $${Number(order.total).toLocaleString('es-CL')}</p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
    <p style="color:#555;font-size:14px"><strong>Método de pago:</strong> ${payNames[order.payment]||order.payment}</p>
    <p style="color:#555;font-size:14px"><strong>Dirección:</strong> ${order.customer.address||'—'}</p>
    ${order.payment==='mp'?'<div style="background:#e8f5e9;border-radius:8px;padding:14px;margin-top:16px"><p style="color:#2e7d32;margin:0;font-size:14px">✅ Completa tu pago en Mercado Pago para confirmar el despacho.</p></div>':''}
    ${order.payment==='transfer'?`<div style="background:#e3f2fd;border-radius:8px;padding:14px;margin-top:16px">
      <p style="color:#1565c0;margin:0 0 6px;font-size:14px"><strong>Datos para transferencia:</strong></p>
      <p style="color:#1565c0;margin:0;font-size:13px">Banco: Mercado Pago &middot; Titular: Maxicompra SpA<br>RUT: 78.219.298-1 &middot; Cuenta Vista: 1086521092<br>Email: maxicompraoficial23@gmail.com</p>
    </div>`:''}
  `;
  return emailBase('¡Pedido recibido!', '#E8175D', content);
}

function emailPaymentConfirmed(order) {
  return emailBase('¡Pago confirmado! ✅', '#22c55e', `
    <p style="color:#333">Hola <strong>${order.customer.name}</strong>, tu pago fue confirmado.</p>
    <p style="color:#555;font-size:14px">Pedido <strong>#${order.id}</strong> · Total: <strong>$${Number(order.total).toLocaleString('es-CL')}</strong></p>
    <p style="color:#555;font-size:14px">Estamos preparando tu pedido para despacho. Recibirás otra notificación cuando sea enviado.</p>
    <div style="background:#e8f5e9;border-radius:8px;padding:14px;margin-top:16px">
      <p style="color:#2e7d32;margin:0;font-size:14px">✅ Tu compra está confirmada y en preparación.</p>
    </div>
  `);
}

function emailShipped(order) {
  return emailBase('¡Tu pedido está en camino! 🚚', '#3b82f6', `
    <p style="color:#333">Hola <strong>${order.customer.name}</strong>, tu pedido fue despachado.</p>
    <p style="color:#555;font-size:14px">Pedido <strong>#${order.id}</strong></p>
    <p style="color:#555;font-size:14px">Llegará en <strong>24-48 horas hábiles</strong> a:</p>
    <p style="color:#333;font-weight:600;font-size:15px">${order.customer.address||'—'}</p>
    <p style="color:#555;font-size:13px;margin-top:16px">¿Preguntas? Escríbenos por WhatsApp: <a href="https://wa.me/56958498763" style="color:#3b82f6">+56 9 5849 8763</a></p>
  `);
}

function emailDelivered(order) {
  return emailBase('¡Pedido entregado! 🎉', '#22c55e', `
    <p style="color:#333">Hola <strong>${order.customer.name}</strong>, confirmamos la entrega de tu pedido.</p>
    <p style="color:#555;font-size:14px">Pedido <strong>#${order.id}</strong></p>
    <p style="color:#555;font-size:14px">¡Esperamos que estés feliz con tu compra! Si tienes algún problema, contáctanos dentro de 7 días.</p>
    <p style="color:#555;font-size:13px">WhatsApp: <a href="https://wa.me/56958498763" style="color:#22c55e">+56 9 5849 8763</a></p>
  `);
}

function emailCancelled(order) {
  return emailBase('Pedido cancelado', '#ef4444', `
    <p style="color:#333">Hola <strong>${order.customer.name}</strong>, tu pedido <strong>#${order.id}</strong> fue cancelado.</p>
    <p style="color:#555;font-size:14px">Total de la orden: $${Number(order.total).toLocaleString('es-CL')}</p>
    <p style="color:#555;font-size:14px">Si realizaste un pago y no iniciaste la cancelación, contáctanos de inmediato.</p>
    <div style="background:#fef2f2;border-radius:8px;padding:14px;margin-top:16px">
      <p style="color:#dc2626;margin:0;font-size:14px">WhatsApp: <a href="https://wa.me/56958498763" style="color:#dc2626">+56 9 5849 8763</a></p>
    </div>
  `);
}

function emailPaymentFailed(order) {
  return emailBase('Pago no procesado ⚠️', '#f59e0b', `
    <p style="color:#333">Hola <strong>${order.customer.name}</strong>, tu pago para el pedido <strong>#${order.id}</strong> no fue aprobado.</p>
    <p style="color:#555;font-size:14px">Puedes intentar nuevamente con otra tarjeta o elige otro método de pago.</p>
    <div style="background:#fef3c7;border-radius:8px;padding:14px;margin-top:16px">
      <p style="color:#92400e;margin:0;font-size:14px">⚠️ Tu pedido sigue reservado. Contáctanos para coordinar: <a href="https://wa.me/56958498763" style="color:#92400e">+56 9 5849 8763</a></p>
    </div>
  `);
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

async function handleHealth(request, env) {
  return json({
    ok: true, store: env.STORE_NAME || 'Maxicompra', version: '2.0.0',
    mp: !!env.MP_ACCESS_TOKEN, email: !!env.RESEND_API_KEY,
    webhookSecret: !!env.MP_WEBHOOK_SECRET, ts: new Date().toISOString(),
  }, 200, request);
}

// POST /api/order
async function handleCreateOrder(request, env) {
  const ip = getClientIP(request);
  if (!(await checkRateLimit(env, `order:${ip}`, 10, 60)))
    return err('Demasiadas solicitudes. Intenta en un minuto.', 429, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }

  const { items, customer, payment, coupon, total } = body;

  if (!Array.isArray(items) || items.length === 0) return err('items requeridos', 400, request);
  if (items.length > 50) return err('Máximo 50 productos por orden', 400, request);
  if (!customer?.name || typeof customer.name !== 'string' || customer.name.trim().length < 2 || customer.name.length > 100)
    return err('nombre inválido (2-100 caracteres)', 400, request);
  if (!customer?.phone) return err('teléfono requerido', 400, request);
  if (!payment) return err('método de pago requerido', 400, request);
  if (!total || !Number.isFinite(Number(total)) || Number(total) <= 0)
    return err('total inválido', 400, request);

  // Validate each item
  for (const item of items) {
    if (!item.name || typeof item.name !== 'string') return err('item.name inválido', 400, request);
    const price = Number(item.price);
    const qty   = Number(item.qty || item.quantity || 1);
    if (!Number.isFinite(price) || price <= 0) return err(`Precio inválido: ${String(item.name).substring(0,40)}`, 400, request);
    if (!Number.isInteger(qty)  || qty < 1 || qty > 50) return err(`Cantidad inválida: ${String(item.name).substring(0,40)}`, 400, request);
  }

  // Validate total is in a reasonable range relative to items sum
  const itemsSum = items.reduce((acc, i) => acc + Number(i.price) * Number(i.qty || i.quantity || 1), 0);
  if (Number(total) > itemsSum * 1.10 || Number(total) < itemsSum * 0.40)
    return err('Total no coincide con los productos del carrito', 400, request);

  let discount = 0;
  if (coupon) {
    if (typeof coupon !== 'string' || coupon.length > 50 || !/^[A-Z0-9_-]+$/i.test(coupon))
      return err('Cupón inválido', 400, request);
    const coupons = await getCoupons(env);
    const c = coupons[coupon.toUpperCase()];
    if (!c || !c.active) return err('Cupón inválido o expirado', 400, request);
    discount = c.pct;
  }

  const orderId = genOrderId();
  const order = {
    id: orderId, status: 'pending', items, customer, payment,
    coupon: coupon?.toUpperCase() || null, discount, total: Number(total),
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    statusHistory: [{ status: 'pending', ts: new Date().toISOString() }],
  };

  // Save order WITHOUT TTL (persistent — never auto-delete)
  await env.ORDERS.put(orderId, JSON.stringify(order));

  // Daily index
  const dateKey = `date:${new Date().toISOString().slice(0, 10)}`;
  const existing = await env.ORDERS.get(dateKey, 'json') || [];
  existing.push(orderId);
  await env.ORDERS.put(dateKey, JSON.stringify(existing));

  // WhatsApp link
  const itemsText = items.map(i => `• ${i.name} x${i.qty||1} — $${Number(i.price).toLocaleString('es-CL')}`).join('\n');
  const waMsg = encodeURIComponent(
    `*🛒 Nuevo pedido ${orderId}*\n\n${itemsText}\n\n*Total: $${Number(total).toLocaleString('es-CL')}*\n\nCliente: ${customer.name}\nTel: ${customer.phone}\nPago: ${payment}`
  );
  const waUrl = `https://wa.me/${env.WHATSAPP_NUMBER||'56958498763'}?text=${waMsg}`;

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
  if (!orderId || orderId.length > 50) return err('ID inválido', 400, request);
  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return err('Orden no encontrada', 404, request);
  const { customer, items, total, status, discount, coupon, createdAt, payment } = order;
  return json({ ok: true, order: { id: orderId, customer, items, total, status, discount, coupon, createdAt, payment } }, 200, request);
}

// GET /api/coupon/:code
async function handleValidateCoupon(code, request, env) {
  if (!code || code.length > 50) return json({ ok: false, valid: false }, 200, request);
  const coupons = await getCoupons(env);
  const c = coupons[code.toUpperCase()];
  if (!c || !c.active) return json({ ok: false, valid: false }, 200, request);
  return json({ ok: true, valid: true, pct: c.pct, desc: c.desc }, 200, request);
}

// POST /api/admin/login
async function handleAdminLogin(request, env) {
  const ip = getClientIP(request);
  if (!(await checkRateLimit(env, `login:${ip}`, 5, 300)))
    return err('Demasiados intentos. Espera 5 minutos.', 429, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }
  if (!body.password || typeof body.password !== 'string' || body.password.length > 200)
    return err('Contraseña requerida', 400, request);

  // Support both plain SHA-256 (legacy) and HMAC-SHA256 salted with JWT_SECRET (new)
  const plainHash  = await sha256(body.password);
  const saltedHash = await hmacSha256(body.password, env.JWT_SECRET);
  const isValid    = plainHash === env.ADMIN_PASSWORD_HASH || saltedHash === env.ADMIN_PASSWORD_HASH;

  if (!isValid) return err('Credenciales incorrectas', 401, request);

  const token = await signToken(
    { role: 'admin', iat: Date.now(), exp: Date.now() + 4 * 60 * 60 * 1000 },
    env.JWT_SECRET
  );
  return json({ ok: true, token, expiresIn: '4h' }, 200, request);
}

// POST /api/admin/logout
async function handleAdminLogout(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);

  const sig = auth.token.split('.')[2];
  if (sig) {
    const tokenId = await sha256(sig);
    const ttl = auth.payload.exp
      ? Math.max(10, Math.ceil((auth.payload.exp - Date.now()) / 1000) + 10)
      : 14400;
    await env.CONFIG.put(`blacklist:${tokenId}`, '1', { expirationTtl: ttl });
  }
  return json({ ok: true, message: 'Sesión cerrada correctamente' }, 200, request);
}

// GET /api/admin/orders
async function handleListOrders(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);

  const url    = new URL(request.url);
  const date   = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const search = (url.searchParams.get('search') || '').toLowerCase().trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return err('Formato de fecha inválido', 400, request);

  const orderIds = await env.ORDERS.get(`date:${date}`, 'json') || [];
  let orders = (await Promise.all(orderIds.map(id => env.ORDERS.get(id, 'json')))).filter(Boolean);

  if (search) {
    orders = orders.filter(o =>
      o.id.toLowerCase().includes(search) ||
      o.customer?.name?.toLowerCase().includes(search) ||
      o.customer?.email?.toLowerCase().includes(search) ||
      o.customer?.phone?.includes(search)
    );
  }

  return json({ ok: true, date, orders, total: orders.length }, 200, request);
}

// GET /api/admin/order/:id  (direct lookup by ID)
async function handleGetOrderAdmin(orderId, request, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);
  if (!orderId || orderId.length > 50) return err('ID inválido', 400, request);
  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return err('Orden no encontrada', 404, request);
  return json({ ok: true, order }, 200, request);
}

// PATCH /api/admin/order/:id/status
async function handleUpdateOrderStatus(request, orderId, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);

  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return err('Orden no encontrada', 404, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }

  const VALID = Object.keys(STATE_TRANSITIONS);
  if (!VALID.includes(body.status)) return err('Estado inválido', 400, request);

  if (!canTransition(order.status, body.status))
    return err(`Transición inválida: "${order.status}" → "${body.status}"`, 400, request);

  const prevStatus = order.status;
  order.status    = body.status;
  order.updatedAt = new Date().toISOString();
  if (!order.statusHistory) order.statusHistory = [];
  order.statusHistory.push({
    status: body.status,
    ts: new Date().toISOString(),
    note: String(body.note || '').substring(0, 200),
  });

  await env.ORDERS.put(orderId, JSON.stringify(order));

  // Transactional emails
  if (order.customer?.email) {
    const emailFns = {
      shipped:        () => sendEmail(env, { to: order.customer.email, subject: `Maxicompra — Tu pedido #${orderId} fue enviado 🚚`, html: emailShipped(order) }),
      delivered:      () => sendEmail(env, { to: order.customer.email, subject: `Maxicompra — ¡Pedido entregado! #${orderId}`, html: emailDelivered(order) }),
      cancelled:      () => sendEmail(env, { to: order.customer.email, subject: `Maxicompra — Tu pedido #${orderId} fue cancelado`, html: emailCancelled(order) }),
      payment_failed: () => sendEmail(env, { to: order.customer.email, subject: `Maxicompra — Pago rechazado #${orderId}`, html: emailPaymentFailed(order) }),
    };
    if (emailFns[body.status]) emailFns[body.status]().catch(() => {});
  }

  return json({ ok: true, orderId, status: order.status, prevStatus }, 200, request);
}

// GET /api/admin/coupons
async function handleListCoupons(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);
  const coupons = await getCoupons(env);
  return json({ ok: true, coupons }, 200, request);
}

// POST /api/admin/coupon
async function handleUpsertCoupon(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }
  if (!body.code || typeof body.code !== 'string') return err('code requerido', 400, request);
  if (body.code.length > 30) return err('código muy largo (máx 30)', 400, request);
  if (!/^[A-Z0-9_-]+$/i.test(body.code)) return err('código solo admite letras, números, - y _', 400, request);

  const coupons = await getCoupons(env);
  const code    = body.code.toUpperCase();
  coupons[code] = {
    pct:    Math.min(100, Math.max(1, Math.floor(Number(body.pct) || coupons[code]?.pct || 10))),
    active: body.active ?? true,
    desc:   String(body.desc || '').substring(0, 200),
  };
  await env.CONFIG.put('coupons', JSON.stringify(coupons));
  return json({ ok: true, code, coupon: coupons[code] }, 200, request);
}

// DELETE /api/admin/coupon/:code
async function handleDeleteCoupon(request, code, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);
  const coupons = await getCoupons(env);
  const upper   = (code || '').toUpperCase();
  if (!coupons[upper]) return err('Cupón no encontrado', 404, request);
  delete coupons[upper];
  await env.CONFIG.put('coupons', JSON.stringify(coupons));
  return json({ ok: true, deleted: upper }, 200, request);
}

// GET /api/admin/stats?days=7
async function handleStats(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth) return err('No autorizado', 401, request);

  const url  = new URL(request.url);
  const days = Math.min(30, Math.max(1, parseInt(url.searchParams.get('days') || '7', 10)));

  const stats = { totalOrders: 0, revenue: 0, paid: 0, pending: 0, shipped: 0, cancelled: 0, byDay: [] };

  for (let i = 0; i < days; i++) {
    const d   = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    const ids = await env.ORDERS.get(`date:${d}`, 'json') || [];
    const dayOrders = (await Promise.all(ids.map(id => env.ORDERS.get(id, 'json')))).filter(Boolean);

    let dayRevenue = 0;
    let dayPaid = 0, dayPending = 0, dayShipped = 0, dayCancelled = 0;

    for (const o of dayOrders) {
      if (['paid', 'shipped', 'delivered'].includes(o.status)) {
        dayRevenue += Number(o.total); dayPaid++;
      } else if (['pending', 'payment_pending', 'payment_failed'].includes(o.status)) {
        dayPending++;
      } else if (o.status === 'shipped') {
        dayShipped++;
      } else if (o.status === 'cancelled') {
        dayCancelled++;
      }
    }

    stats.byDay.unshift({ date: d, orders: dayOrders.length, revenue: dayRevenue });
    stats.totalOrders += dayOrders.length;
    stats.revenue     += dayRevenue;
    stats.paid        += dayPaid;
    stats.pending     += dayPending;
    stats.shipped     += dayShipped;
    stats.cancelled   += dayCancelled;
  }

  return json({ ok: true, days, stats }, 200, request);
}

// POST /api/payment/preference
async function handleMPPreference(request, env) {
  if (!env.MP_ACCESS_TOKEN) return err('Mercado Pago no configurado', 503, request);

  const ip = getClientIP(request);
  if (!(await checkRateLimit(env, `mpref:${ip}`, 10, 60)))
    return err('Demasiadas solicitudes', 429, request);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido', 400, request); }

  const { orderId, items, payer } = body;
  if (!orderId || typeof orderId !== 'string' || orderId.length > 50) return err('orderId inválido', 400, request);
  if (!Array.isArray(items) || !items.length) return err('items requeridos', 400, request);

  // Validate item prices
  for (const item of items) {
    const price = Number(item.unit_price || item.price);
    const qty   = Number(item.quantity   || item.qty || 1);
    if (!Number.isFinite(price) || price <= 0)          return err('Precio de item inválido', 400, request);
    if (!Number.isFinite(qty)   || qty < 1 || qty > 50) return err('Cantidad de item inválida', 400, request);
  }

  // Cross-check total against stored order
  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return err('Orden no encontrada — crea la orden primero', 404, request);

  const itemsTotal = items.reduce((acc, i) =>
    acc + Number(i.unit_price || i.price) * Number(i.quantity || i.qty || 1), 0);
  if (itemsTotal > order.total * 1.10 || itemsTotal < order.total * 0.40)
    return err('Total no coincide con la orden registrada', 400, request);

  const preference = {
    items: items.map(i => ({
      title:      String(i.title || i.name).substring(0, 256),
      quantity:   Math.max(1, Math.floor(Number(i.quantity || i.qty || 1))),
      unit_price: Math.max(1, Math.floor(Number(i.unit_price || i.price))),
      currency_id: 'CLP',
    })),
    payer: payer?.email ? { email: String(payer.email).substring(0, 256) } : undefined,
    external_reference: orderId,
    back_urls: {
      success: `${env.STORE_URL||'https://maxicompra.cl'}?payment=success&order=${orderId}`,
      failure: `${env.STORE_URL||'https://maxicompra.cl'}?payment=failure&order=${orderId}`,
      pending: `${env.STORE_URL||'https://maxicompra.cl'}?payment=pending&order=${orderId}`,
    },
    auto_return: 'approved',
    notification_url: 'https://maxicompra-api.elflaco0800.workers.dev/api/payment/webhook',
    statement_descriptor: 'MAXICOMPRA',
  };

  const mpRes = await fetch('https://api.mercadopago.com/checkout/preferences', {
    method: 'POST',
    headers: {
      'Authorization':     `Bearer ${env.MP_ACCESS_TOKEN}`,
      'Content-Type':      'application/json',
      'X-Idempotency-Key': orderId,
    },
    body: JSON.stringify(preference),
  });

  const mpData = await mpRes.json();
  if (!mpRes.ok) return err(`Error Mercado Pago: ${mpData.message || mpRes.status}`, 502, request);

  order.mp_preference_id = mpData.id;
  order.status           = 'payment_pending';
  order.updatedAt        = new Date().toISOString();
  if (!order.statusHistory) order.statusHistory = [];
  order.statusHistory.push({ status: 'payment_pending', ts: new Date().toISOString() });
  await env.ORDERS.put(orderId, JSON.stringify(order));

  return json({
    ok:                 true,
    preference_id:      mpData.id,
    init_point:         mpData.init_point,
    sandbox_init_point: mpData.sandbox_init_point,
  }, 200, request);
}

// POST /api/payment/webhook  (also accepts GET from MP ping)
async function handleMPWebhook(request, env) {
  if (!env.MP_ACCESS_TOKEN) return new Response('OK', { status: 200 });

  // ── Validate MP signature (requires MP_WEBHOOK_SECRET in dashboard) ──
  if (env.MP_WEBHOOK_SECRET) {
    const sig = request.headers.get('x-signature');
    if (sig) {
      const url    = new URL(request.url);
      const dataId = url.searchParams.get('data.id') || url.searchParams.get('id') || '';
      const parts  = Object.fromEntries(
        sig.split(',').map(p => { const [k,...v] = p.split('='); return [k.trim(), v.join('=').trim()]; })
      );
      const ts = parts.ts;
      const v1 = parts.v1;
      if (ts && v1) {
        const manifest = `id:${dataId};request-date:${ts};`;
        const expected = await hmacSha256(manifest, env.MP_WEBHOOK_SECRET);
        if (expected !== v1) return new Response('Unauthorized', { status: 401 });
      }
    }
  }

  const url    = new URL(request.url);
  const type   = url.searchParams.get('type') || url.searchParams.get('topic');
  const dataId = url.searchParams.get('data.id') || url.searchParams.get('id');
  if (type !== 'payment' || !dataId) return new Response('OK', { status: 200 });

  // ── Webhook deduplication ──
  const reqId = request.headers.get('x-request-id');
  if (reqId) {
    const dedupKey  = `webhook:${reqId}`;
    const processed = await env.CONFIG.get(dedupKey);
    if (processed) return new Response('OK', { status: 200 });
    await env.CONFIG.put(dedupKey, '1', { expirationTtl: 3600 });
  }

  const payRes = await fetch(`https://api.mercadopago.com/v1/payments/${dataId}`, {
    headers: { 'Authorization': `Bearer ${env.MP_ACCESS_TOKEN}` },
  });
  if (!payRes.ok) return new Response('OK', { status: 200 });

  const payment = await payRes.json();
  const orderId = payment.external_reference;
  if (!orderId) return new Response('OK', { status: 200 });

  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return new Response('OK', { status: 200 });

  const statusMap = {
    approved:     'paid',
    authorized:   'paid',
    pending:      'payment_pending',
    in_process:   'payment_pending',
    in_mediation: 'payment_pending',
    rejected:     'payment_failed',
    charged_back: 'cancelled',
    cancelled:    'cancelled',
  };

  const newStatus = statusMap[payment.status];
  if (!newStatus || !canTransition(order.status, newStatus)) {
    return new Response('OK', { status: 200 }); // skip invalid/same-state transitions
  }

  order.status           = newStatus;
  order.mp_payment_id    = payment.id;
  order.mp_payment_status = payment.status;
  order.updatedAt        = new Date().toISOString();
  if (!order.statusHistory) order.statusHistory = [];
  order.statusHistory.push({ status: newStatus, ts: new Date().toISOString(), source: 'mp_webhook' });
  await env.ORDERS.put(orderId, JSON.stringify(order));

  if (order.customer?.email) {
    if (payment.status === 'approved' || payment.status === 'authorized') {
      sendEmail(env, {
        to:      order.customer.email,
        subject: `Maxicompra — ¡Pago confirmado! Pedido #${orderId}`,
        html:    emailPaymentConfirmed(order),
      }).catch(() => {});
    } else if (payment.status === 'rejected') {
      sendEmail(env, {
        to:      order.customer.email,
        subject: `Maxicompra — Pago rechazado #${orderId}`,
        html:    emailPaymentFailed(order),
      }).catch(() => {});
    }
  }

  return new Response('OK', { status: 200 });
}

// ─── Router ───────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // Public routes
    if (path === '/api/health'              && method === 'GET')    return handleHealth(request, env);
    if (path === '/api/order'               && method === 'POST')   return handleCreateOrder(request, env);
    if (path.startsWith('/api/order/')      && method === 'GET')    return handleGetOrder(path.split('/')[3], request, env);
    if (path.startsWith('/api/coupon/')     && method === 'GET')    return handleValidateCoupon(path.split('/')[3], request, env);

    // Auth
    if (path === '/api/admin/login'         && method === 'POST')   return handleAdminLogin(request, env);
    if (path === '/api/admin/logout'        && method === 'POST')   return handleAdminLogout(request, env);

    // Admin routes
    if (path === '/api/admin/orders'        && method === 'GET')    return handleListOrders(request, env);
    if (path === '/api/admin/stats'         && method === 'GET')    return handleStats(request, env);
    if (path === '/api/admin/coupons'       && method === 'GET')    return handleListCoupons(request, env);
    if (path === '/api/admin/coupon'        && method === 'POST')   return handleUpsertCoupon(request, env);
    if (path.startsWith('/api/admin/coupon/') && method === 'DELETE')
      return handleDeleteCoupon(request, path.split('/')[4], env);
    if (path.match(/^\/api\/admin\/order\/[^/]+\/status$/) && method === 'PATCH')
      return handleUpdateOrderStatus(request, path.split('/')[4], env);
    if (path.match(/^\/api\/admin\/order\/[^/]+$/) && method === 'GET')
      return handleGetOrderAdmin(path.split('/')[4], request, env);

    // Payments
    if (path === '/api/payment/preference'  && method === 'POST')   return handleMPPreference(request, env);
    if (path === '/api/payment/webhook')                             return handleMPWebhook(request, env);

    return err('Ruta no encontrada', 404, request);
  },
};
