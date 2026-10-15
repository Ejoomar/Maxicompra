// Ejecutar: node --test tools/tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import { isPlausibleOrderTotal } from '../../worker/src/index.js';

const item = (price, qty = 1) => ({ name: 'x', price, qty });

test('carrito barato + envío RM pasa (caso que rompía Mercado Pago)', () => {
  assert.equal(isPlausibleOrderTotal([item(2000)], 2000 + 2990), true);
});

test('carrito barato + envío máximo pasa', () => {
  assert.equal(isPlausibleOrderTotal([item(1500)], 1500 + 7990), true);
});

test('total con cupón (descuento) pasa', () => {
  assert.equal(isPlausibleOrderTotal([item(20000)], 20000 * 0.9), true);
});

test('envío gratis (total = items) pasa', () => {
  assert.equal(isPlausibleOrderTotal([item(25000, 2)], 50000), true);
});

test('total inflado sobre items + envío máximo se rechaza', () => {
  assert.equal(isPlausibleOrderTotal([item(5000)], 5000 + 9000), false);
});

test('total absurdamente bajo se rechaza', () => {
  assert.equal(isPlausibleOrderTotal([item(10000)], 500), false);
});
