# -*- coding: utf-8 -*-
"""Migración única: saca CSS/JS inline de index.html a assets/ y separa el panel admin.
Uso: python tools/split_assets.py  (corre sobre el index.html monolítico)"""
import re, io, sys

ROOT = '.'
html = open(f'{ROOT}/index.html', encoding='utf-8').read()

css_m = max(re.finditer(r'<style\b[^>]*>(.*?)</style>', html, re.S), key=lambda m: len(m.group(1)))
js_m  = max(re.finditer(r'<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html, re.S), key=lambda m: len(m.group(1)))
css, js = css_m.group(1), js_m.group(1)

lines = js.split('\n')
# Rango del panel admin: de "BANNER EDITOR" hasta antes de "SCROLL REVEAL + COUNTERS"
def find(title, start=0):
    for i in range(start, len(lines)):
        if title in lines[i]:
            return i
    raise SystemExit('no encontré sección: ' + title)
a = find('BANNER EDITOR') - 1            # incluye la línea "/* ═══" previa
b = find('SCROLL REVEAL + COUNTERS') - 1 # exclusivo
assert lines[a].lstrip().startswith('/*') and lines[b].lstrip().startswith('/*'), (lines[a], lines[b])

admin = lines[a:b]
app   = lines[:a] + lines[b:]

# El watcher de #__admin vive en app.js (debe existir antes de cargar admin.js)
hash_i = next(i for i, l in enumerate(admin) if l.startswith('(function(){function _chkHash'))
hash_line = admin.pop(hash_i)

# openAdmin real pasa a admin.js; en app.js queda un stub que carga el bundle bajo demanda
loader = '''/* ═══ ADMIN: carga bajo demanda (assets/js/admin.js) ═══ */
var _admBundle = null;
function loadAdminBundle(){
  if(_admBundle) return _admBundle;
  _admBundle = new Promise(function(res, rej){
    var s = document.createElement('script');
    s.src = 'assets/js/admin.js?v=__V_ADMIN__';
    s.onload = res;
    s.onerror = function(){ _admBundle = null; rej(new Error('admin bundle')); };
    document.head.appendChild(s);
  });
  return _admBundle;
}
// Stubs: admin.js los reemplaza al cargarse (declaraciones de función globales)
function openAdmin(){
  loadAdminBundle().then(function(){ if(!openAdmin.__stub) openAdmin(); })
    .catch(function(){ showToast('No se pudo cargar el panel. Revisa tu conexión.','error'); });
}
openAdmin.__stub = true;
function closeAdmin(){}
''' 
app_text = '\n'.join(app)
marker = '/* ═══════════ FAQ MODAL ═══════════ */'
assert marker in app_text
app_text = app_text.replace(marker, loader + '\n' + hash_line + '\n\n' + marker, 1)

open(f'{ROOT}/assets/css/main.css', 'w', encoding='utf-8', newline='').write(css.strip('\n') + '\n')
open(f'{ROOT}/assets/js/app.js',   'w', encoding='utf-8', newline='').write(app_text.rstrip('\n') + '\n')
open(f'{ROOT}/assets/js/admin.js', 'w', encoding='utf-8', newline='').write('\n'.join(admin).rstrip('\n') + '\n')

new_html = html[:css_m.start()] + '<link rel="stylesheet" href="assets/css/main.css?v=__V_CSS__">' + html[css_m.end():]
# recalcular tras reemplazo (offsets cambiaron)
js_m2 = max(re.finditer(r'<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>', new_html, re.S), key=lambda m: len(m.group(1)))
new_html = new_html[:js_m2.start()] + '<script src="assets/js/app.js?v=__V_APP__"></script>' + new_html[js_m2.end():]
open(f'{ROOT}/index.html', 'w', encoding='utf-8', newline='').write(new_html)
print('css', len(css), 'app', len(app_text), 'admin', len('\n'.join(admin)), 'html', len(new_html))
