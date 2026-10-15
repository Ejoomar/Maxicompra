# -*- coding: utf-8 -*-
"""Pone un hash de contenido en las URLs de assets (?v=...) para cache-busting seguro.
Correr SIEMPRE antes de commitear cambios en assets/ :  python tools/stamp.py"""
import hashlib, re, sys

def h(path_or_text):
    data = path_or_text.encode('utf-8') if isinstance(path_or_text, str) else path_or_text
    return hashlib.sha1(data).hexdigest()[:8]

read = lambda p: open(p, encoding='utf-8').read()
def write(p, t): open(p, 'w', encoding='utf-8', newline='').write(t)

CHECK = '--check' in sys.argv
orig = {p: read(p) for p in ('assets/js/app.js', 'index.html', 'sw.js')}
if CHECK:
    _write = write
    def write(p, t):  # modo verificación: no escribe, solo compara
        if orig.get(p) != t:
            print(f'DESACTUALIZADO: {p} (corre: python tools/stamp.py)'); sys.exit(1)

admin_v = h(read('assets/js/admin.js'))
app = re.sub(r'admin\.js\?v=\w+', f'admin.js?v={admin_v}', read('assets/js/app.js'))
write('assets/js/app.js', app)
css_v, app_v = h(read('assets/css/main.css')), h(app)

html = read('index.html')
html = re.sub(r'assets/css/main\.css\?v=\w+', f'assets/css/main.css?v={css_v}', html)
html = re.sub(r'assets/js/app\.js\?v=\w+',    f'assets/js/app.js?v={app_v}', html)
write('index.html', html)

sw = read('sw.js')
sw = re.sub(r"var CACHE = '[^']*';", f"var CACHE = 'maxicompra-{css_v}{app_v}';", sw)
sw = re.sub(r'assets/css/main\.css\?v=\w+', f'assets/css/main.css?v={css_v}', sw)
sw = re.sub(r'assets/js/app\.js\?v=\w+',    f'assets/js/app.js?v={app_v}', sw)
write('sw.js', sw)
print('css', css_v, 'app', app_v, 'admin', admin_v)
