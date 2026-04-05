/**
 * Maxicompra API — Cloudflare Worker
 * Phase 1: Orders + Coupons + Admin Auth
 * Phase 2: Mercado Pago integration (cuando Edgar tenga cuenta MP)
 *
 * KV Bindings: ORDERS, CONFIG
 * Secrets: ADMIN_PASSWORD_HASH, JWT_SECRET, MP_ACCESS_TOKEN (Phase 2)
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://maxicompra.cl',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// ─── Utilidades ─────────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function error(msg, status = 400) {
  return json({ ok: false, error: msg }, status);
}

async function sha256(text) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function signToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${header}.${body}`)
  );
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${header}.${body}.${sigB64}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      new TextEncoder().encode(`${header}.${body}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET);
}

function generateOrderId() {
  const ts = Date.now().toString(36).toUpperCase();
  const rand = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `MC-${ts}-${rand}`;
}

// ─── Cupones (servidor) ──────────────────────────────────────────────────────

const DEFAULT_COUPONS = {
  BIENVENIDA10:   { pct: 10, active: true, desc: '10% de descuento bienvenida' },
  MAXIDESCUENTO:  { pct: 15, active: true, desc: '15% de descuento especial' },
  PRIMERACOMPRA:  { pct: 10, active: true, desc: '10% primera compra' },
};

async function getCoupons(env) {
  try {
    const stored = await env.CONFIG.get('coupons', 'json');
    return stored || DEFAULT_COUPONS;
  } catch {
    return DEFAULT_COUPONS;
  }
}

// ─── Rutas ───────────────────────────────────────────────────────────────────

async function handleHealth(env) {
  return json({
    ok: true,
    store: env.STORE_NAME || 'Maxicompra',
    version: '1.0.0',
    phase: 1,
    ts: new Date().toISOString(),
  });
}

// POST /api/order
// Body: { items, customer, payment, coupon?, total }
async function handleCreateOrder(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return error('JSON inválido');
  }

  const { items, customer, payment, coupon, total } = body;

  if (!items?.length)        return error('items requeridos');
  if (!customer?.name)       return error('nombre requerido');
  if (!customer?.phone)      return error('teléfono requerido');
  if (!payment)              return error('método de pago requerido');
  if (!total || total <= 0)  return error('total inválido');

  // Validar cupón si se envió
  let discount = 0;
  if (coupon) {
    const coupons = await getCoupons(env);
    const c = coupons[coupon.toUpperCase()];
    if (!c || !c.active) return error('Cupón inválido o expirado');
    discount = c.pct;
  }

  const orderId = generateOrderId();
  const order = {
    id: orderId,
    status: 'pending',
    items,
    customer,
    payment,
    coupon: coupon?.toUpperCase() || null,
    discount,
    total,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  // Guardar en KV (expira en 90 días)
  await env.ORDERS.put(orderId, JSON.stringify(order), {
    expirationTtl: 90 * 24 * 60 * 60,
  });

  // Índice por fecha (para listar órdenes)
  const dateKey = `date:${new Date().toISOString().slice(0, 10)}`;
  const existing = await env.ORDERS.get(dateKey, 'json') || [];
  existing.push(orderId);
  await env.ORDERS.put(dateKey, JSON.stringify(existing), {
    expirationTtl: 90 * 24 * 60 * 60,
  });

  // Mensaje WhatsApp pre-armado
  const itemsText = items
    .map(i => `• ${i.name} x${i.qty} — $${i.price.toLocaleString('es-CL')}`)
    .join('\n');
  const waMsg = encodeURIComponent(
    `*Nuevo pedido ${orderId}*\n\n${itemsText}\n\n*Total: $${total.toLocaleString('es-CL')}*\n\nCliente: ${customer.name}\nTeléfono: ${customer.phone}\nPago: ${payment}`
  );
  const waUrl = `https://wa.me/${env.WHATSAPP_NUMBER || '56958498763'}?text=${waMsg}`;

  return json({
    ok: true,
    orderId,
    waUrl,
    status: 'pending',
    message: 'Orden creada. Completa el pago para confirmar.',
  });
}

// GET /api/order/:id
async function handleGetOrder(orderId, env) {
  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return error('Orden no encontrada', 404);
  // No exponer datos internos al cliente
  const { customer, items, total, status, discount, coupon, createdAt } = order;
  return json({ ok: true, order: { id: orderId, customer, items, total, status, discount, coupon, createdAt } });
}

// GET /api/coupon/:code
async function handleValidateCoupon(code, env) {
  const coupons = await getCoupons(env);
  const c = coupons[code.toUpperCase()];
  if (!c || !c.active) return json({ ok: false, valid: false });
  return json({ ok: true, valid: true, pct: c.pct, desc: c.desc });
}

// POST /api/admin/login
// Body: { password }
async function handleAdminLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return error('JSON inválido'); }

  const { password } = body;
  if (!password) return error('Contraseña requerida');

  const hash = await sha256(password);
  if (hash !== env.ADMIN_PASSWORD_HASH) {
    return error('Credenciales incorrectas', 401);
  }

  const token = await signToken(
    { role: 'admin', exp: Date.now() + 8 * 60 * 60 * 1000 }, // 8 horas
    env.JWT_SECRET
  );

  return json({ ok: true, token, expiresIn: '8h' });
}

// GET /api/admin/orders
async function handleListOrders(request, env) {
  const payload = await requireAuth(request, env);
  if (!payload) return error('No autorizado', 401);

  const url = new URL(request.url);
  const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);

  const dateKey = `date:${date}`;
  const orderIds = await env.ORDERS.get(dateKey, 'json') || [];

  const orders = await Promise.all(
    orderIds.map(id => env.ORDERS.get(id, 'json'))
  );

  return json({ ok: true, date, orders: orders.filter(Boolean) });
}

// PATCH /api/admin/order/:id/status
// Body: { status: 'pending'|'paid'|'shipped'|'delivered'|'cancelled' }
async function handleUpdateOrderStatus(request, orderId, env) {
  const payload = await requireAuth(request, env);
  if (!payload) return error('No autorizado', 401);

  const order = await env.ORDERS.get(orderId, 'json');
  if (!order) return error('Orden no encontrada', 404);

  let body;
  try { body = await request.json(); } catch { return error('JSON inválido'); }

  const VALID_STATUSES = ['pending', 'paid', 'shipped', 'delivered', 'cancelled'];
  if (!VALID_STATUSES.includes(body.status)) return error('Estado inválido');

  order.status = body.status;
  order.updatedAt = new Date().toISOString();

  await env.ORDERS.put(orderId, JSON.stringify(order), {
    expirationTtl: 90 * 24 * 60 * 60,
  });

  return json({ ok: true, orderId, status: order.status });
}

// POST /api/admin/coupon — crear/editar cupón
async function handleUpsertCoupon(request, env) {
  const payload = await requireAuth(request, env);
  if (!payload) return error('No autorizado', 401);

  let body;
  try { body = await request.json(); } catch { return error('JSON inválido'); }

  const { code, pct, active, desc } = body;
  if (!code) return error('code requerido');

  const coupons = await getCoupons(env);
  coupons[code.toUpperCase()] = {
    pct: pct ?? coupons[code.toUpperCase()]?.pct ?? 10,
    active: active ?? true,
    desc: desc || '',
  };

  await env.CONFIG.put('coupons', JSON.stringify(coupons));
  return json({ ok: true, code: code.toUpperCase(), coupon: coupons[code.toUpperCase()] });
}

// ─── PHASE 2 placeholder — Mercado Pago ──────────────────────────────────────
// Se activa cuando Edgar tenga Access Token de MP
async function handleMPPreference(request, env) {
  if (!env.MP_ACCESS_TOKEN) {
    return error('Mercado Pago no configurado aún. Fase 2 pendiente.', 503);
  }
  // TODO Phase 2:
  // 1. Recibir orderId + items del frontend
  // 2. POST a https://api.mercadopago.com/checkout/preferences con items
  // 3. Devolver init_point (URL de pago MP) al frontend
  return error('Implementación Fase 2 pendiente', 501);
}

async function handleMPWebhook(request, env) {
  if (!env.MP_ACCESS_TOKEN) return json({ ok: true }); // silently ignore
  // TODO Phase 2:
  // 1. Verificar x-signature de MP
  // 2. GET /v1/payments/:id para verificar estado
  // 3. Actualizar estado en KV
  // 4. Enviar WhatsApp a Edgar
  return json({ ok: true });
}

// ─── Router principal ────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Preflight CORS
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Rutas
    if (path === '/api/health' && method === 'GET') {
      return handleHealth(env);
    }

    if (path === '/api/order' && method === 'POST') {
      return handleCreateOrder(request, env);
    }

    if (path.startsWith('/api/order/') && method === 'GET') {
      const orderId = path.split('/')[3];
      return handleGetOrder(orderId, env);
    }

    if (path.startsWith('/api/coupon/') && method === 'GET') {
      const code = path.split('/')[3];
      return handleValidateCoupon(code, env);
    }

    if (path === '/api/admin/login' && method === 'POST') {
      return handleAdminLogin(request, env);
    }

    if (path === '/api/admin/orders' && method === 'GET') {
      return handleListOrders(request, env);
    }

    if (path.startsWith('/api/admin/order/') && path.endsWith('/status') && method === 'PATCH') {
      const orderId = path.split('/')[4];
      return handleUpdateOrderStatus(request, orderId, env);
    }

    if (path === '/api/admin/coupon' && method === 'POST') {
      return handleUpsertCoupon(request, env);
    }

    // Phase 2 — Mercado Pago
    if (path === '/api/payment/preference' && method === 'POST') {
      return handleMPPreference(request, env);
    }

    if (path === '/api/payment/webhook' && method === 'POST') {
      return handleMPWebhook(request, env);
    }

    return error('Ruta no encontrada', 404);
  },
};
