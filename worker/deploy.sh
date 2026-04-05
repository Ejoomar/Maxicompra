#!/bin/bash
# deploy.sh — Despliega el worker de Maxicompra
# Uso: bash deploy.sh
# Requisitos: wrangler instalado, haber corrido `wrangler login`

set -e

echo "=== Maxicompra API Deploy ==="
echo ""

# 1. Crear KV namespaces si no existen
echo "[1/4] Creando KV namespaces..."
echo "Corre estos comandos UNA SOLA VEZ y pega los IDs en wrangler.toml:"
echo ""
echo "  wrangler kv namespace create ORDERS"
echo "  wrangler kv namespace create ORDERS --preview"
echo "  wrangler kv namespace create CONFIG"
echo "  wrangler kv namespace create CONFIG --preview"
echo ""
read -p "¿Ya tienes los IDs en wrangler.toml? (s/n): " ans
if [ "$ans" != "s" ]; then
  echo "Actualiza wrangler.toml primero y vuelve a correr este script."
  exit 1
fi

# 2. Configurar secretos
echo ""
echo "[2/4] Configurando secretos..."
echo "Necesitas definir 2 secretos:"
echo ""
echo "  wrangler secret put ADMIN_PASSWORD_HASH"
echo "  (pega el SHA-256 de tu contraseña admin)"
echo ""
echo "  Para generar el hash de 'TuPasswordAqui':"
echo "  node -e \"require('crypto').createHash('sha256').update('TuPasswordAqui').digest('hex').then?console.log:console.log(require('crypto').createHash('sha256').update('TuPasswordAqui').digest('hex'))\""
echo ""
echo "  wrangler secret put JWT_SECRET"
echo "  (pega cualquier string largo y aleatorio, ej: openssl rand -hex 32)"
echo ""
read -p "¿Secretos configurados? (s/n): " ans2
if [ "$ans2" != "s" ]; then
  echo "Configura los secretos primero."
  exit 1
fi

# 3. Deploy
echo ""
echo "[3/4] Desplegando worker..."
wrangler deploy

echo ""
echo "[4/4] ¡Listo!"
echo ""
echo "Tu API está en: https://maxicompra-api.<tu-subdominio>.workers.dev"
echo ""
echo "Endpoints disponibles:"
echo "  GET  /api/health"
echo "  POST /api/order"
echo "  GET  /api/order/:id"
echo "  GET  /api/coupon/:code"
echo "  POST /api/admin/login"
echo "  GET  /api/admin/orders"
echo "  PATCH /api/admin/order/:id/status"
echo "  POST /api/admin/coupon"
echo ""
echo "Siguiente paso: actualiza la URL del API en index.html"
echo "  const API = 'https://maxicompra-api.<subdominio>.workers.dev';"
