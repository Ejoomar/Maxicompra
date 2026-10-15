
'use strict';
/* ═══════════════════════════════════════════════════════════
   MAXICOMPRA — FULL APPLICATION LOGIC
═══════════════════════════════════════════════════════════ */

/* ── STORAGE KEYS ── */
const KP='mx_prods', KC='mx_cart', KW='mx_wish', KCF='mx_cfg', KPW='mx_pw', KB='mx_banners_v2', KCS='mx_cats', KR='mx_reviews';

/* ── PRODUCTOS ── */
// Cargados desde caché localStorage; actualizados desde la API al iniciar
const DEFAULT_PRODUCTS = [];

/* ── STORAGE SAFE (funciona en iOS file://, Safari privado, etc.) ── */
let _ls = { getItem(k){return null;}, setItem(){} };
try { localStorage.setItem('_t','1'); localStorage.removeItem('_t'); _ls = localStorage; } catch(e) {}
function lsGet(k,def){ try{ const v=_ls.getItem(k); return v!=null?JSON.parse(v):def; }catch(e){return def;} }
function lsSet(k,v){ try{ _ls.setItem(k,JSON.stringify(v)); return true; }catch(e){ if(e && (e.name==='QuotaExceededError'||e.code===22)){ showToast('⚠️ Almacenamiento lleno. Usa URLs de imagen en vez de cargar archivos.','error'); } return false; } }
/* Comprime imagen con canvas antes de guardar como base64 */
function _compressImg(file, maxPx, quality, cb){
  const img=new Image(); const url=URL.createObjectURL(file);
  img.onload=()=>{
    let {width:w,height:h}=img;
    if(w>maxPx||h>maxPx){ if(w>h){h=Math.round(h*maxPx/w);w=maxPx;}else{w=Math.round(w*maxPx/h);h=maxPx;} }
    const c=document.createElement('canvas'); c.width=w; c.height=h;
    c.getContext('2d').drawImage(img,0,0,w,h);
    URL.revokeObjectURL(url);
    cb(c.toDataURL('image/jpeg',quality));
  };
  img.onerror=()=>{ URL.revokeObjectURL(url); cb(null); };
  img.src=url;
}
/* ── TEMA CLARO / OSCURO ── */
function toggleTheme(){
  const dark = document.documentElement.getAttribute('data-theme')==='dark';
  const next = dark ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  const icon = document.getElementById('themeIcon');
  if(icon){ icon.className = next==='dark' ? 'fas fa-sun' : 'fas fa-moon'; icon.style.color = next==='dark' ? '#FFD600' : '#90CAF9'; }
  lsSet('mx_theme', next);
}
// Aplicar tema guardado antes de renderizar
(function applyTheme(){
  const saved = lsGet('mx_theme','light');
  const icon = document.getElementById('themeIcon');
  if(saved==='dark'){
    document.documentElement.setAttribute('data-theme','dark');
    if(icon) icon.className='fas fa-sun';
  } else {
    if(icon) icon.className='fas fa-moon';
  }
})();


/* ── STATE ── */
// Productos desde caché localStorage (se actualizan tras fetch API)
let products = lsGet(KP, []);
let cart    = lsGet(KC,  []);
let wish    = lsGet(KW,  []);
let config  = lsGet(KCF, {});
let banners = lsGet(KB,  null);
let cats    = lsGet(KCS, null);
let reviewsDB = lsGet(KR, {});

/* ── SAVE HELPERS ── */
const saveP   = () => lsSet(KP,  products);
const saveC   = () => lsSet(KC,  cart);
const saveW   = () => lsSet(KW,  wish);
const saveCfg = () => lsSet(KCF, config);
const saveBan = () => lsSet(KB,  banners);
const saveCats    = () => lsSet(KCS, cats);
const saveReviews = () => lsSet(KR,  reviewsDB);
const uid     = () => Date.now().toString(36) + Math.random().toString(36).slice(2,6);
const fp      = p => '$' + Math.round(p).toLocaleString('es-CL');
const esc     = s => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

/* ── DEFAULT CONFIG ── */
const DCFG = {
  name:'Maxicompra',
  tag:'Calidad asegurada, exclusividad garantizada.',
  phone:'+56977462964',
  email:'maxicompraoficial23@gmail.com',
  desc:'Tu tienda online de confianza. Los mejores productos al mejor precio. Envíos a todo Chile.',
  fship:'$19.990',
  shrm:'$3.000',
  shreg:'$3.500 a $7.800',
  cuotas:'12',
  hours:'Lunes a Domingo · 9:00 AM – 8:00 PM',
  ret:'30',
  banner:'Envío gratis desde $19.990 | Hasta 12 cuotas sin interés | Paga seguro con Mercado Pago | Retira el mismo día en tienda',
  promoImg:'',
  addr:'Santiago, Chile'
};
const gc = k => config[k] !== undefined ? config[k] : DCFG[k];

/* ── DEFAULT CATEGORIES ── */
const DEFAULT_CATS = [
  {id:'electronica',      name:'Electrónica',       emoji:'⚡', color:'rgba(255,215,0,.18)',  bg:''},
  {id:'audio',            name:'Audio',              emoji:'🎧', color:'rgba(0,198,255,.18)',  bg:''},
  {id:'general',          name:'General',            emoji:'🛍️', color:'rgba(232,23,93,.18)',  bg:''},
  {id:'tecnologia',       name:'Tecnología',         emoji:'📱', color:'rgba(0,230,118,.18)',  bg:''},
  {id:'computacion',      name:'Computación',        emoji:'💻', color:'rgba(138,43,226,.18)', bg:''},
  {id:'hogar',            name:'Hogar',              emoji:'🏠', color:'rgba(0,198,255,.18)',  bg:''},
  {id:'juguetes',         name:'Juguetes',           emoji:'🎮', color:'rgba(255,152,0,.18)',  bg:''},
  {id:'salud-belleza',    name:'Salud & Belleza',    emoji:'💄', color:'rgba(255,68,68,.18)',  bg:''},
  {id:'cocina',           name:'Cocina',             emoji:'🍳', color:'rgba(255,152,0,.18)',  bg:''},
  {id:'telefonia',        name:'Telefonía',          emoji:'📞', color:'rgba(0,198,255,.18)',  bg:''},
  {id:'accesorios',       name:'Accesorios',         emoji:'👜', color:'rgba(138,43,226,.18)', bg:''},
  {id:'deportes',         name:'Deportes',           emoji:'⚽', color:'rgba(0,230,118,.18)',  bg:''},
];
// Siempre usar DEFAULT_CATS para que coincidan con los productos
cats = DEFAULT_CATS; saveCats();

/* ── SUBCATEGORÍAS (agrupación visual dentro de cada categoría) ── */
const SUBCAT_ORDER = ['pilas','power-bank','cargadores-cables','parlantes','audifonos','depiladoras',
  'cuidado-personal','alargadores','almacenamiento','mouse-teclado','redes','radios','iluminacion',
  'telefonia','camaras-video','accesorios-auto','electrodomesticos','cocina','balanzas','salud',
  'herramientas','juguetes','otros'];
const SUBCAT_META = {
  'pilas':            {label:'Pilas y Baterías',                 emoji:'🔌'},
  'power-bank':        {label:'Power Bank y Baterías Externas',   emoji:'🔋'},
  'cargadores-cables': {label:'Cargadores y Cables',               emoji:'🔌'},
  'parlantes':         {label:'Parlantes y Karaoke',               emoji:'🔊'},
  'audifonos':         {label:'Audífonos y Auriculares',           emoji:'🎧'},
  'depiladoras':       {label:'Máquinas de Afeitar y Depilar',     emoji:'✂️'},
  'cuidado-personal':  {label:'Cuidado Personal',                  emoji:'💇'},
  'alargadores':       {label:'Alargadores y Enchufes',            emoji:'🔌'},
  'almacenamiento':    {label:'Almacenamiento y Memorias',         emoji:'💾'},
  'mouse-teclado':     {label:'Mouse y Teclados',                  emoji:'🖱️'},
  'redes':             {label:'Redes y Conectividad',              emoji:'🌐'},
  'radios':            {label:'Radios',                            emoji:'📻'},
  'iluminacion':       {label:'Linternas y Focos',                 emoji:'🔦'},
  'telefonia':         {label:'Teléfonos y Celulares',             emoji:'📱'},
  'camaras-video':     {label:'Cámaras, TV y Video',               emoji:'📷'},
  'accesorios-auto':   {label:'Accesorios para Auto',              emoji:'🚗'},
  'electrodomesticos': {label:'Electrodomésticos del Hogar',       emoji:'🏠'},
  'cocina':            {label:'Utensilios de Cocina',              emoji:'🍳'},
  'balanzas':          {label:'Balanzas y Pesas',                  emoji:'⚖️'},
  'salud':             {label:'Salud y Bienestar',                 emoji:'⚕️'},
  'herramientas':      {label:'Herramientas y Ferretería',         emoji:'🔧'},
  'juguetes':          {label:'Juguetes y Disfraces',              emoji:'🧸'},
  'otros':             {label:'Otros',                             emoji:'📦'},
};
function _groupBySubcat(list) {
  var idx = {};
  SUBCAT_ORDER.forEach(function(id,i){ idx[id]=i; });
  return list.slice().sort(function(a,b){
    var ia = idx[a.subcat] !== undefined ? idx[a.subcat] : SUBCAT_ORDER.length;
    var ib = idx[b.subcat] !== undefined ? idx[b.subcat] : SUBCAT_ORDER.length;
    return ia - ib;
  });
}

/* ── DEFAULT BANNERS ── */
const DEFAULT_BANNERS = [
  {
    badge:'🎧 Audio & Electrónica',
    title:'Audífonos JBL\ndesde $8.590',
    sub:'TWS inalámbricos, over-ear y parlantes Bluetooth. Sonido premium para cada estilo de vida.',
    detail:'JBL · Master·G · Aiwa · Maxell',
    price:'🔥 Hasta 30% OFF esta semana',
    btnText:'Ver audio',
    btnColor:'linear-gradient(135deg,#E8175D,#9B1238)',
    bg:'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=1400&q=80&fit=crop',
    overlay:'linear-gradient(100deg,rgba(10,8,20,.93) 45%,rgba(232,23,93,.18) 100%)',
  },
  {
    badge:'⚡ Ofertas de temporada',
    title:'Hasta 40% OFF\nen tecnología',
    sub:'Power banks, cargadores rápidos, cables USB-C y accesorios para tus dispositivos.',
    detail:'Stock limitado · Precio válido hasta agotar',
    price:'💳 12 cuotas sin interés',
    btnText:'Ver ofertas',
    btnColor:'linear-gradient(135deg,#F97316,#DC2626)',
    bg:'https://images.unsplash.com/photo-1491933382434-500287f9b54b?w=1400&q=80&fit=crop',
    overlay:'linear-gradient(100deg,rgba(8,12,22,.92) 45%,rgba(249,115,22,.15) 100%)',
  },
  {
    badge:'🚀 Despacho express',
    title:'Envío gratis\na todo Chile',
    sub:'Despachamos con Chilexpress y Starken. Entrega en 24-48 horas hábiles a tu puerta.',
    detail:'RM y regiones · Compras desde $19.990',
    price:'📦 También retiro en tienda el mismo día',
    btnText:'Comprar ahora',
    btnColor:'linear-gradient(135deg,#059669,#065F46)',
    bg:'https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?w=1400&q=80&fit=crop',
    overlay:'linear-gradient(100deg,rgba(5,10,18,.93) 45%,rgba(5,150,105,.2) 100%)',
  },
  {
    badge:'💳 Mercado Pago',
    title:'Paga en cuotas\nsin interés',
    sub:'Todas las tarjetas de crédito, débito y transferencia. Proceso 100% seguro y encriptado.',
    detail:'Visa · Mastercard · Redcompra · CMR · American Express',
    price:'🔒 Pago protegido por Mercado Pago',
    btnText:'Ver catálogo',
    btnColor:'linear-gradient(135deg,#2563EB,#1D4ED8)',
    bg:'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=1400&q=80&fit=crop',
    overlay:'linear-gradient(100deg,rgba(8,10,22,.93) 45%,rgba(37,99,235,.2) 100%)',
  },
];
if (!banners || !banners.some(b => b.bg)) { banners = DEFAULT_BANNERS; saveBan(); }

/* ── NAVIGATION STATE ── */
let currentView = 'home';
let currentCat  = '';
let prevView    = '';
let currentProd = null;
let pdpQty      = 1;
let editId      = null;
let formImgs    = [];
let specData    = [];
let featData    = [];
let sortMode    = 'def';
let sliderIdx   = 0;

/* ═════════════════════════════════════
   VIEW NAVIGATION
═════════════════════════════════════ */
function showView(v) {
  document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
  document.getElementById('view-' + v).classList.add('active');
  currentView = v;
  window.scrollTo({top: 0, behavior: 'smooth'});
}

function goHome() {
  currentCat = '';
  document.getElementById('searchInp').value = '';
  renderNavBar();
  renderHomeProducts('');
  if(typeof renderRecent==='function') renderRecent();
  showView('home');
  if(typeof hideStickyPdp==='function') hideStickyPdp();
  var _n = gc('name') || 'Maxicompra';
  var _t = gc('tag')  || 'Calidad asegurada, exclusividad garantizada.';
  history.pushState({view:'home'}, _n, '/');
  var _bc = document.getElementById('seo-breadcrumb');
  if (_bc) _bc.remove();
  var _cs = document.getElementById('seo-cat-schema');
  if (_cs) _cs.remove();
  _updateSeoMeta(
    _n + ' — ' + _t,
    'Los mejores productos de electrónica, hogar y más al mejor precio. Envío gratis a todo Chile.',
    'https://maxicompra.cl'
  );
}

function openCatView(catId) {
  currentCat = catId;
  const cat = cats.find(c => c.id === catId) || {name: catId, emoji:'📦', bg:'', color:'rgba(232,23,93,.18)'};
  // ── Color sólido por categoría ──
  const CAT_BG = {
    electronica:     '#1C2A1A',
    audio:           '#0D1F2D',
    general:         '#1F0D1A',
    tecnologia:      '#0D1F18',
    computacion:     '#180D2B',
    hogar:           '#0D1A2B',
    juguetes:        '#2B1A0D',
    'salud-belleza': '#2B0D1A',
    cocina:          '#2B150D',
    telefonia:       '#0D1F2B',
    accesorios:      '#1A0D2B',
    deportes:        '#0D2B15'
  };
  const CAT_ACCENT = {
    electronica:'#F5A623', audio:'#00C6FF', general:'#E8175D',
    tecnologia:'#00E676', computacion:'#B44EF5', hogar:'#4FC3F7',
    juguetes:'#FF9800', 'salud-belleza':'#F06292', cocina:'#FF7043',
    telefonia:'#29B6F6', accesorios:'#CE93D8', deportes:'#66BB6A'
  };
  const bgColor  = CAT_BG[catId]     || '#1a1a2e';
  const accent   = CAT_ACCENT[catId] || '#E8175D';

  // ── Hero visual ──
  const hero   = document.getElementById('catPageHero');
  const bg     = document.getElementById('catPageBg');
  const overlay= document.getElementById('catPageOverlay');
  const glow   = document.getElementById('catPageGlow');
  const deco   = document.getElementById('catPageDecoEmoji');
  hero.style.background = bgColor;
  if(cat.bg){
    bg.style.backgroundImage = `url('${cat.bg.replace(/'/g,'%27')}')`;
    overlay.style.cssText = `background:linear-gradient(105deg,${bgColor}F2 38%,${bgColor}99 70%,transparent 100%);`;
  } else {
    bg.style.backgroundImage = '';
    overlay.style.cssText = `background:linear-gradient(105deg,${bgColor} 30%,${bgColor}CC 65%,transparent 100%);`;
  }
  if(glow) glow.style.background = accent;
  if(deco) deco.textContent = cat.emoji || '📦';

  // ── Chip / pill ──
  const chip = document.getElementById('catPageChip');
  const chipDot = document.getElementById('catPageChipDot');
  const chipLabel = document.getElementById('catPageChipLabel');
  if(chip){ chip.style.borderColor = accent+'33'; chip.style.background = accent+'15'; }
  if(chipDot) chipDot.style.background = accent;
  if(chipLabel) chipLabel.textContent = cat.name;

  // ── Textos ──
  const CAT_DESC = {
    electronica:      'Power banks, cargadores rápidos, cables USB-C y gadgets que hacen la diferencia. Revisa nuestro catálogo — hay más de lo que crees.',
    audio:            'Parlantes JBL, audífonos inalámbricos, soundbars y más. Buscamos lo que suena bien sin que te pese el bolsillo.',
    general:          'Productos prácticos que sirven de verdad. Si no lo encontraste en otra categoría, probablemente está acá.',
    tecnologia:       'Smartwatches, tablets, drones y gadgets que recién llegaron. Tecnología nueva sin lista de espera ni sobreprecio.',
    computacion:      'Teclados, mouses, sillas gamer, fundas para laptop y todo lo que le falta a tu setup. Sin drama, con despacho.',
    hogar:            'Aspiradoras robot, purificadores de aire, organizadores y cosas que hacen la casa funcionar mejor. Útil primero, bonito también.',
    juguetes:         'Juguetes STEM, figuras de colección, juegos de mesa y regalos para distintas edades. Sin armar sin instrucciones imposibles.',
    'salud-belleza':  'Depiladores, masajeadores, cremas y cuidado personal que realmente usas. Cuídate sin gastar demás.',
    cocina:           'Freidoras de aire, ollas eléctricas, cuchillos y gadgets de cocina que sí sirven. Para los que cocinan y para los que quieren empezar.',
    telefonia:        'Fundas, cargadores inalámbricos, auriculares y accesorios para tu celular. Todo compatible, todo con stock real.',
    accesorios:       'Mochilas, carteras, cinturones y accesorios que combinan con lo que ya tienes. Sin tallas raras ni envíos de 30 días.',
    deportes:         'Ropa técnica, pesas, colchonetas y accesorios para entrenar donde quieras. Actívate sin excusas ni sobreprecio.'
  };
  const _desc = CAT_DESC[catId] || ('Explora nuestra selección de ' + cat.name + '. Despacho a todo Chile con seguimiento en tiempo real.');
  document.getElementById('catPageName').textContent  = cat.name;
  document.getElementById('catPageCrumb').textContent = cat.name;
  document.getElementById('catPageDesc').textContent  = _desc;

  // Render products
  renderCatProducts(catId);
  renderNavBar();
  showView('category');
  prevView = 'home';
  var _sn = gc('name') || 'Maxicompra';
  var _catUrl = '/c/' + catId;
  history.pushState({view:'category', cat:catId}, cat.name + ' | ' + _sn, _catUrl);
  var _bc = document.getElementById('seo-breadcrumb');
  if (_bc) _bc.remove();
  _updateSeoMeta(
    cat.name + ' | ' + _sn,
    _desc.slice(0, 155),
    'https://maxicompra.cl' + _catUrl
  );
  _injectCatItemList(catId, cat.name, _catUrl);
}

function _injectCatItemList(catId, catName, catUrl) {
  var old = document.getElementById('seo-cat-schema');
  if (old) old.remove();
  var catProds = getProductList(catId).slice(0, 50);
  if (!catProds.length) return;
  var items = catProds.map(function(p, i) {
    var slug = p.slug || (_toSlug(p.name) + '-' + p.id.slice(-4));
    return {
      '@type': 'ListItem',
      'position': i + 1,
      'name': p.name,
      'url': 'https://maxicompra.cl/p/' + slug
    };
  });
  var el = document.createElement('script');
  el.type = 'application/ld+json';
  el.id = 'seo-cat-schema';
  el.textContent = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'ItemList',
    'name': catName,
    'description': document.getElementById('catPageDesc').textContent,
    'url': 'https://maxicompra.cl' + catUrl,
    'numberOfItems': catProds.length,
    'itemListElement': items
  });
  document.head.appendChild(el);
}

function openPDP(id) {
  const p = products.find(x => x.id === id);
  if (!p) return;
  currentProd = p;
  if(typeof trackRecent==='function') trackRecent(id);
  pdpQty = 1;
  prevView = currentView;
  populatePDP(p);
  renderNavBar();
  showView('product');
  // Sticky bar + stock warning
  if(typeof showPdpStock==='function') showPdpStock(p);
  if(typeof initStickyPdp==='function') initStickyPdp(p);
  // Schema.org Product + AggregateRating
  _injectProductSchema(p);
  // SEO: dynamic title, canonical, og tags + real URL
  var _sn = gc('name') || 'Maxicompra';
  var _desc = p.desc ? p.desc.slice(0, 150) + (p.desc.length > 150 ? '…' : '') : p.name;
  var _slug = p.slug || (_toSlug(p.name) + '-' + p.id.slice(-4));
  var _url = '/p/' + _slug;
  history.pushState({view:'product', id:p.id, slug:_slug}, p.name, _url);
  var _img = (p.imgs && p.imgs[0] && p.imgs[0].startsWith('http')) ? p.imgs[0] : null;
  _updateSeoMeta(
    p.name + ' — ' + _sn,
    _desc + ' | ' + _sn + '.cl',
    'https://maxicompra.cl' + _url,
    _img
  );
  var _cs2 = document.getElementById('seo-cat-schema');
  if (_cs2) _cs2.remove();
  var _bcEl = document.getElementById('seo-breadcrumb');
  if (!_bcEl) {
    _bcEl = document.createElement('script');
    _bcEl.type = 'application/ld+json';
    _bcEl.id = 'seo-breadcrumb';
    document.head.appendChild(_bcEl);
  }
  var _catName = p.cat || 'General';
  var _catObj  = cats.find(function(c){ return c.name === _catName; });
  var _catId   = _catObj ? _catObj.id : _toSlug(_catName);
  _bcEl.textContent = JSON.stringify({
    "@context":"https://schema.org","@type":"BreadcrumbList",
    "itemListElement":[
      {"@type":"ListItem","position":1,"name":"Inicio","item":"https://maxicompra.cl/"},
      {"@type":"ListItem","position":2,"name":_catName,"item":"https://maxicompra.cl/c/"+_catId},
      {"@type":"ListItem","position":3,"name":p.name,"item":"https://maxicompra.cl/p/"+_slug}
    ]
  });
}

function _injectProductSchema(p) {
  var old = document.getElementById('pdp-schema');
  if (old) old.remove();
  var imgUrl = (p.imgs && p.imgs[0]) || p.img || '';
  var safeImg = imgUrl && !imgUrl.startsWith('data:') && !imgUrl.startsWith('blob:')
    ? ['https://maxicompra.cl' + (imgUrl.startsWith('/')?'':'/') + imgUrl]
    : undefined;
  var schema = {
    '@context': 'https://schema.org',
    '@type': 'Product',
    name: p.name,
    description: p.desc || p.name,
    brand: p.brand ? {'@type':'Brand', name: p.brand} : undefined,
    image: safeImg,
    offers: {
      '@type': 'Offer',
      price: p.price,
      priceCurrency: 'CLP',
      url: 'https://maxicompra.cl/p/' + (p.slug || (_toSlug(p.name) + '-' + p.id.slice(-4))),
      availability: 'https://schema.org/InStock',
      seller: {'@type':'Organization', name:'Maxicompra'}
    }
  };
  var _prodRevs = reviewsDB[p.id] || [];
  var _rat, _cnt;
  if (_prodRevs.length > 0) {
    _rat = Math.min(5, _prodRevs.reduce(function(a,r){ return a+r.rating; }, 0) / _prodRevs.length);
    _cnt = _prodRevs.length;
  } else {
    _rat = p.rat;
    _cnt = p.rev && p.rev > 0 ? p.rev : 0;
  }
  if (_rat && _rat > 0) {
    schema.aggregateRating = {
      '@type': 'AggregateRating',
      ratingValue: Math.min(_rat, 5).toFixed(1),
      bestRating: '5',
      worstRating: '1',
      reviewCount: _cnt > 0 ? _cnt : 1
    };
  }
  // Clean undefined keys
  Object.keys(schema).forEach(function(k){ if(schema[k]===undefined) delete schema[k]; });
  if(schema.offers) Object.keys(schema.offers).forEach(function(k){ if(schema.offers[k]===undefined) delete schema.offers[k]; });
  var s = document.createElement('script');
  s.type = 'application/ld+json';
  s.id   = 'pdp-schema';
  s.textContent = JSON.stringify(schema);
  document.head.appendChild(s);
}

function pdpGoBack() {
  if (prevView === 'category' && currentCat) openCatView(currentCat);
  else goHome();
}

/* ═════════════════════════════════════
   RENDER NAV BAR
═════════════════════════════════════ */
function renderNavBar() {
  const activeCats = [...new Set(products.filter(p=>p.visible!==false).map(p=>p.cat).filter(Boolean))];
  const nav = document.getElementById('navBar');
  const NV_ICONS = {
    electronica:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 8a4 4 0 0 1 4-4h12a4 4 0 0 1 4 4v8a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8Z"/><path d="M12 8v4m-3-2h6"/></svg>`,
    audio:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 18a3 3 0 1 1-6 0V9a9 9 0 1 1 18 0v9a3 3 0 1 1-6 0"/></svg>`,
    tecnologia:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></svg>`,
    computacion:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 6h16v10H4z"/><path d="M2 20h20"/></svg>`,
    telefonia:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4"/></svg>`,
    'salud-belleza':`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 21s-8-5-8-11a5 5 0 0 1 9-3 5 5 0 0 1 9 3c0 6-8 11-10 11Z"/></svg>`,
    hogar:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
    juguetes:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M12 6v12M8 6v12M16 6v12"/></svg>`,
    general:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg>`,
    accesorios:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 2v6a3 3 0 0 0 6 0V2M6 2h12M6 20h12"/></svg>`,
    deportes:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><path d="M4.9 4.9 19.1 19.1M4.9 19.1 19.1 4.9" opacity=".4"/></svg>`,
    cocina:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 11V5a2 2 0 0 1 2-2h2v8M7 3v8M3 11h18v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`,
  };
  const NV_ACCENT = {
    electronica:'#3B82F6',audio:'#8B5CF6',tecnologia:'#06B6D4',computacion:'#0EA5E9',
    telefonia:'#10B981','salud-belleza':'#EC4899',hogar:'#F59E0B',juguetes:'#EF4444',
    general:'#6366F1',accesorios:'#14B8A6',deportes:'#22C55E',cocina:'#F97316',
  };
  const allIcon = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`;
  const isHome = !currentCat && currentView==='home';

  nav.innerHTML =
    `<div class="nav-item sale ${isHome ? 'active' : ''}" onclick="goHome()">` +
      `<span class="nv-ico" style="background:rgba(232,23,93,.25);">${allIcon}</span>Todos` +
    `</div>` +
    cats.filter(c => activeCats.includes(c.name)).map(c => {
      const col      = NV_ACCENT[c.id] || '#888';
      const isActive = currentCat === c.id && currentView==='category';
      const icon     = NV_ICONS[c.id] || `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/></svg>`;
      const icoBg    = isActive ? col+'30' : col+'18';
      const icoClr   = isActive ? col : 'rgba(255,255,255,.5)';
      return `<div class="nav-item ${isActive ? 'active' : ''}" onclick="openCatView('${c.id}')"` +
        ` style="${isActive ? `border-bottom-color:${col};` : ''}">` +
        `<span class="nv-ico" style="background:${icoBg};color:${icoClr};">${icon}</span>${esc(c.name)}` +
      `</div>`;
    }).join('');
}

/* ═════════════════════════════════════
   RENDER HOME PRODUCTS
═════════════════════════════════════ */
function getProductList(catId='', search='') {
  let list = products.filter(p => p.visible !== false);
  if (catId) {
    const cat = cats.find(c => c.id === catId);
    if (cat) list = list.filter(p => p.cat === cat.name);
  }
  if (search) {
    const res = _fuzzySearch(search, list);
    if(res.exact.length >= 2 || search.trim().length < 3){
      list = res.exact;
    } else {
      // Fuzzy fallback: combine exact + approximate, deduplicated
      const seen = new Set(res.exact.map(p=>p.id));
      list = res.exact.concat(res.fuzzy.filter(p=>!seen.has(p.id)));
    }
  }
  switch(sortMode) {
    case 'pa': list.sort((a,b) => a.price - b.price); break;
    case 'pd': list.sort((a,b) => b.price - a.price); break;
    case 'az': list.sort((a,b) => a.name.localeCompare(b.name)); break;
    case 'rat': list.sort((a,b) => (b.rat||0) - (a.rat||0)); break;
    default:
      if (catId) list = _groupBySubcat(list);
  }
  return list;
}

let _homeProdList = [];
let _homeProdPage  = 0;
const HOME_PAGE_SIZE = 24;

let _catFilteredList = [];
let _catProdPage = 0;
const CAT_PAGE_SIZE = 24;

function renderHomeProducts(search) {
  _homeProdList = getProductList('', search);
  _homeProdPage = 0;
  const grid  = document.getElementById('homeProductsGrid');
  const empty = document.getElementById('homeEmptyState');
  const count = document.getElementById('homeProdCount');
  document.getElementById('homeSecTitle').innerHTML = search
    ? `Resultados para <span class="acc">"${esc(search)}"</span>`
    : `Nuestros <span class="acc">Productos</span>`;
  count.textContent = _homeProdList.length > 0 ? `${_homeProdList.length} producto${_homeProdList.length!==1?'s':''}` : '';
  // Show skeleton while JS processes the list
  grid.innerHTML = _skelCards(Math.min(_homeProdList.length || 10, 10));
  if (!_homeProdList.length) { grid.innerHTML = ''; empty.style.display = 'block'; _rmLoadMore(); return; }
  empty.style.display = 'none';
  const first = _homeProdList.slice(0, HOME_PAGE_SIZE);
  grid.innerHTML = first.map(p => productCardHTML(p)).join('');
  _homeProdPage = 1;
  _updateLoadMore();
  renderFooterCats();
}

function _updateLoadMore() { _renderPagination(); }
function _rmLoadMore() { const p = document.getElementById('homePagination'); if(p) p.remove(); }
function loadMoreProds() {}

function _renderPagination() {
  const totalPages = Math.ceil(_homeProdList.length / HOME_PAGE_SIZE);
  if (totalPages <= 1) { _rmLoadMore(); return; }
  let pag = document.getElementById('homePagination');
  if (!pag) {
    pag = document.createElement('div');
    pag.id = 'homePagination';
    pag.style.cssText = 'display:flex;align-items:center;justify-content:center;gap:8px;padding:32px 16px;flex-wrap:wrap;';
    document.getElementById('homeProductsGrid').after(pag);
  }
  const cur = _homeProdPage - 1; // 0-indexed current page
  let btns = '';
  // Prev
  btns += `<button onclick="goToPage(${cur-1})" ${cur===0?'disabled':''} style="padding:8px 14px;border-radius:8px;border:1.5px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;font-size:13px;font-weight:600;${cur===0?'opacity:.4;cursor:not-allowed':''}">‹ Anterior</button>`;
  // Pages
  const showPages = [];
  if (totalPages <= 7) { for(let i=0;i<totalPages;i++) showPages.push(i); }
  else {
    showPages.push(0);
    if (cur > 2) showPages.push('...');
    for(let i=Math.max(1,cur-1);i<=Math.min(totalPages-2,cur+1);i++) showPages.push(i);
    if (cur < totalPages-3) showPages.push('...');
    showPages.push(totalPages-1);
  }
  showPages.forEach(p => {
    if (p==='...') { btns += `<span style="padding:8px 4px;color:var(--muted)">…</span>`; return; }
    const active = p===cur;
    btns += `<button onclick="goToPage(${p})" style="width:38px;height:38px;border-radius:8px;border:${active?'none':'1.5px solid var(--border)'};background:${active?'var(--grad)':'var(--card)'};color:${active?'#fff':'var(--text)'};cursor:pointer;font-size:14px;font-weight:700;">${p+1}</button>`;
  });
  // Next
  btns += `<button onclick="goToPage(${cur+1})" ${cur===totalPages-1?'disabled':''} style="padding:8px 14px;border-radius:8px;border:1.5px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;font-size:13px;font-weight:600;${cur===totalPages-1?'opacity:.4;cursor:not-allowed':''}">Siguiente ›</button>`;
  // Page info
  btns += `<span style="font-size:12px;color:var(--muted);margin-left:8px;">Página ${cur+1} de ${totalPages}</span>`;
  pag.innerHTML = btns;
}

function goToPage(pageIdx) {
  const totalPages = Math.ceil(_homeProdList.length / HOME_PAGE_SIZE);
  if (pageIdx < 0 || pageIdx >= totalPages) return;
  _homeProdPage = pageIdx + 1;
  const grid = document.getElementById('homeProductsGrid');
  const start = pageIdx * HOME_PAGE_SIZE;
  const batch = _homeProdList.slice(start, start + HOME_PAGE_SIZE);
  grid.innerHTML = batch.map(p => productCardHTML(p)).join('');
  _renderPagination();
  window.scrollTo({ top: document.getElementById('homeProdsSection')?.offsetTop - 80 || 0, behavior: 'smooth' });
}

/* ═════════════════════════════════════
   FILTER SIDEBAR STATE & LOGIC
═════════════════════════════════════ */
var _FS = { brands: [], priceMin: null, priceMax: null };
var _fsAllList = [];
var _fsPriceBounds = { min: 0, max: 999999 };
var _fsPriceT = null;

function _setFS(patch) { _FS = Object.assign({}, _FS, patch); }

function _fsHasActive() {
  return _FS.brands.length > 0 ||
    (_FS.priceMin !== null && _FS.priceMin > _fsPriceBounds.min) ||
    (_FS.priceMax !== null && _FS.priceMax < _fsPriceBounds.max);
}

function _applyFilters(list) {
  var out = list;
  if (_FS.brands.length) out = out.filter(function(p){ return _FS.brands.includes(p.brand); });
  if (_FS.priceMin !== null) out = out.filter(function(p){ return p.price >= _FS.priceMin; });
  if (_FS.priceMax !== null) out = out.filter(function(p){ return p.price <= _FS.priceMax; });
  return out;
}

function _paintCatGrid(filtered) {
  _catFilteredList = filtered;
  _catProdPage = 0;
  var grid = document.getElementById('catProductsGrid');
  var empty = document.getElementById('catEmptyState');
  var count = document.getElementById('catFilterCount');
  if (!filtered.length) { grid.innerHTML=''; empty.style.display='block'; if(count) count.textContent='0 productos'; _renderCatPagination(); return; }
  empty.style.display='none';
  var first = filtered.slice(0, CAT_PAGE_SIZE);
  grid.innerHTML = _renderCatGridSlice(first);
  if(count) count.textContent = filtered.length + ' producto' + (filtered.length !== 1 ? 's' : '');
  _renderCatPagination();
}
function _renderCatGridSlice(list) {
  var distinctSubcats = new Set(_catFilteredList.map(function(p){ return p.subcat; }));
  var shouldGroup = sortMode === 'def' && distinctSubcats.size > 1;
  if (!shouldGroup) {
    return list.map(function(p){ return productCardHTML(p); }).join('');
  }
  var html = '';
  var lastSubcat = null;
  list.forEach(function(p){
    if (p.subcat !== lastSubcat) {
      var meta = SUBCAT_META[p.subcat] || SUBCAT_META.otros;
      var n = _catFilteredList.filter(function(x){ return x.subcat === p.subcat; }).length;
      html += '<div class="cat-subcat-hdr"><span class="csh-emoji">'+meta.emoji+'</span>'+esc(meta.label)+'<span class="csh-count">'+n+'</span></div>';
      lastSubcat = p.subcat;
    }
    html += productCardHTML(p);
  });
  return html;
}
function _renderCatPagination() {
  var pag = document.getElementById('catPagination');
  if (!pag) return;
  var totalPages = Math.ceil(_catFilteredList.length / CAT_PAGE_SIZE);
  if (totalPages <= 1) { pag.style.display='none'; pag.innerHTML=''; return; }
  pag.style.display = 'flex';
  pag.style.cssText = 'display:flex;align-items:center;justify-content:center;gap:8px;margin-top:32px;flex-wrap:wrap;';
  var cur = _catProdPage;
  var btns = '';
  btns += `<button onclick="catGoToPage(${cur-1})" style="padding:8px 14px;border-radius:8px;background:var(--card);border:1px solid var(--border);color:var(--text);cursor:pointer;font-size:13px;font-family:inherit;transition:all .2s;" ${cur===0?'disabled style="opacity:.4;cursor:default;"':''}>‹ Anterior</button>`;
  var start = Math.max(0, cur-2), end = Math.min(totalPages-1, cur+2);
  if(start>0) btns += `<button onclick="catGoToPage(0)" style="padding:8px 12px;border-radius:8px;background:var(--card);border:1px solid var(--border);color:var(--text);cursor:pointer;font-size:13px;font-family:inherit;">1</button>${start>1?'<span style="color:var(--muted);padding:0 4px">…</span>':''}`;
  for(var i=start;i<=end;i++){
    var active = i===cur;
    btns += `<button onclick="catGoToPage(${i})" style="padding:8px 12px;border-radius:8px;font-size:13px;font-family:inherit;cursor:${active?'default':'pointer'};background:${active?'var(--pink)':'var(--card)'};color:${active?'#fff':'var(--text)'};border:1px solid ${active?'var(--pink)':'var(--border)'};font-weight:${active?'700':'400'};">${i+1}</button>`;
  }
  if(end<totalPages-1) btns += `${end<totalPages-2?'<span style="color:var(--muted);padding:0 4px">…</span>':''}<button onclick="catGoToPage(${totalPages-1})" style="padding:8px 12px;border-radius:8px;background:var(--card);border:1px solid var(--border);color:var(--text);cursor:pointer;font-size:13px;font-family:inherit;">${totalPages}</button>`;
  btns += `<button onclick="catGoToPage(${cur+1})" style="padding:8px 14px;border-radius:8px;background:var(--card);border:1px solid var(--border);color:var(--text);cursor:pointer;font-size:13px;font-family:inherit;transition:all .2s;" ${cur===totalPages-1?'disabled style="opacity:.4;cursor:default;"':''}>Siguiente ›</button>`;
  btns += `<span style="font-size:12px;color:var(--muted);margin-left:8px;">Página ${cur+1} de ${totalPages}</span>`;
  pag.innerHTML = btns;
}
function catGoToPage(pageIdx) {
  var totalPages = Math.ceil(_catFilteredList.length / CAT_PAGE_SIZE);
  if (pageIdx < 0 || pageIdx >= totalPages) return;
  _catProdPage = pageIdx;
  var grid = document.getElementById('catProductsGrid');
  var start = pageIdx * CAT_PAGE_SIZE;
  var batch = _catFilteredList.slice(start, start + CAT_PAGE_SIZE);
  grid.innerHTML = _renderCatGridSlice(batch);
  _renderCatPagination();
  var catSection = document.getElementById('view-category');
  window.scrollTo({ top: catSection ? catSection.offsetTop - 80 : 0, behavior: 'smooth' });
}

function onFilterChange() {
  var filtered = _applyFilters(_fsAllList);
  _paintCatGrid(filtered);
  var badge = document.getElementById('fsBadge');
  var clearBtn = document.getElementById('fsClearBtn');
  var active = _FS.brands.length +
    (_FS.priceMin !== null && _FS.priceMin > _fsPriceBounds.min ? 1 : 0) +
    (_FS.priceMax !== null && _FS.priceMax < _fsPriceBounds.max ? 1 : 0);
  if (badge) { badge.textContent = active; badge.style.display = active ? 'flex' : 'none'; }
  if (clearBtn) clearBtn.classList.toggle('visible', active > 0);
}

function clearFilters() {
  _setFS({ brands: [], priceMin: null, priceMax: null });
  _buildFilterSections();
  onFilterChange();
}

function _fsSectionsHTML(brands) {
  var priceMin = _fsPriceBounds.min, priceMax = _fsPriceBounds.max;
  var curMin = _FS.priceMin !== null ? _FS.priceMin : priceMin;
  var curMax = _FS.priceMax !== null ? _FS.priceMax : priceMax;
  var brandsHTML = brands.length > 1 ? `
    <div class="fs-section">
      <div class="fs-eyebrow">Marca</div>
      ${brands.map(function(b){ var on = _FS.brands.includes(b); return `
        <label class="fs-check-row">
          <input type="checkbox" ${on?'checked':''} onchange="fsToggleBrand('${esc(b)}',this.checked)">
          <span class="fs-check-label">${esc(b)}</span>
          <span class="fs-check-count">${_fsAllList.filter(function(p){return p.brand===b;}).length}</span>
        </label>`; }).join('')}
    </div>` : '';
  return `
    <div class="fs-section">
      <div class="fs-eyebrow">Precio</div>
      <div class="fs-range-wrap" id="fsRangeWrap">
        <div class="fs-range-track"></div>
        <div class="fs-range-fill" id="fsRangeFill"></div>
        <input type="range" id="fsRangeMin" min="${priceMin}" max="${priceMax}" value="${curMin}" oninput="fsRangeInput('min',this.value)">
        <input type="range" id="fsRangeMax" min="${priceMin}" max="${priceMax}" value="${curMax}" oninput="fsRangeInput('max',this.value)">
      </div>
      <div class="fs-price-inputs">
        <div class="fs-price-input-wrap"><span>$</span><input type="number" id="fsPriceMin" value="${curMin}" min="${priceMin}" max="${priceMax}" oninput="fsPriceInput('min',this.value)"></div>
        <span style="color:var(--mute);font-size:12px">—</span>
        <div class="fs-price-input-wrap"><span>$</span><input type="number" id="fsPriceMax" value="${curMax}" min="${priceMin}" max="${priceMax}" oninput="fsPriceInput('max',this.value)"></div>
      </div>
    </div>
    ${brandsHTML}`;
}

function _buildFilterSections() {
  var brands = [...new Set(_fsAllList.map(function(p){ return p.brand; }).filter(Boolean))];
  var html = _fsSectionsHTML(brands);
  var d = document.getElementById('fsSectionsDesktop');
  var m = document.getElementById('fsSectionsMobile');
  if (d) d.innerHTML = html;
  if (m) m.innerHTML = html;
  _updateRangeFill();
}

function fsToggleBrand(brand, checked) {
  var next = checked ? _FS.brands.concat(brand) : _FS.brands.filter(function(b){ return b !== brand; });
  _setFS({ brands: next });
  // sync the other panel
  document.querySelectorAll('input[type=checkbox]').forEach(function(cb){
    if (cb.closest('#fsSectionsDesktop,#fsSectionsMobile')) cb.checked = next.includes(brand) && cb.closest('label') && cb.closest('label').querySelector('input') === cb ? checked : next.includes(cb.closest('label') && cb.closest('label').querySelector('.fs-check-label') ? cb.closest('label').querySelector('.fs-check-label').textContent : '');
  });
  onFilterChange();
}

function fsRangeInput(which, val) {
  val = parseInt(val, 10);
  var minV = parseInt(document.getElementById('fsRangeMin').value, 10);
  var maxV = parseInt(document.getElementById('fsRangeMax').value, 10);
  if (which === 'min' && val >= maxV) val = maxV - 1;
  if (which === 'max' && val <= minV) val = minV + 1;
  if (which === 'min') { document.getElementById('fsRangeMin').value = val; document.getElementById('fsPriceMin').value = val; _setFS({ priceMin: val > _fsPriceBounds.min ? val : null }); }
  else { document.getElementById('fsRangeMax').value = val; document.getElementById('fsPriceMax').value = val; _setFS({ priceMax: val < _fsPriceBounds.max ? val : null }); }
  _updateRangeFill();
  clearTimeout(_fsPriceT); _fsPriceT = setTimeout(onFilterChange, 150);
}

function fsPriceInput(which, val) {
  val = parseInt(val, 10);
  if (isNaN(val)) return;
  if (which === 'min') { _setFS({ priceMin: val > _fsPriceBounds.min ? val : null }); var el=document.getElementById('fsRangeMin'); if(el) el.value=val; }
  else { _setFS({ priceMax: val < _fsPriceBounds.max ? val : null }); var el2=document.getElementById('fsRangeMax'); if(el2) el2.value=val; }
  _updateRangeFill();
  clearTimeout(_fsPriceT); _fsPriceT = setTimeout(onFilterChange, 150);
}

function _updateRangeFill() {
  var fill = document.getElementById('fsRangeFill');
  var minEl = document.getElementById('fsRangeMin');
  var maxEl = document.getElementById('fsRangeMax');
  if (!fill || !minEl || !maxEl) return;
  var lo = (parseInt(minEl.value,10) - _fsPriceBounds.min) / (_fsPriceBounds.max - _fsPriceBounds.min) * 100;
  var hi = (parseInt(maxEl.value,10) - _fsPriceBounds.min) / (_fsPriceBounds.max - _fsPriceBounds.min) * 100;
  fill.style.left = lo + '%';
  fill.style.width = (hi - lo) + '%';
}

function openFilterDrawer() {
  document.getElementById('fsDrawer').classList.add('open');
  document.getElementById('fsBackdrop').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeFilterDrawer() {
  document.getElementById('fsDrawer').classList.remove('open');
  document.getElementById('fsBackdrop').classList.remove('open');
  document.body.style.overflow = '';
}

function renderCatProducts(catId) {
  _setFS({ brands: [], priceMin: null, priceMax: null });
  _fsAllList = getProductList(catId);
  var prices = _fsAllList.map(function(p){ return p.price; }).filter(Boolean);
  _fsPriceBounds = prices.length ? { min: Math.floor(Math.min.apply(null,prices)), max: Math.ceil(Math.max.apply(null,prices)) } : { min: 0, max: 999999 };
  _buildFilterSections();
  _paintCatGrid(_fsAllList);
  var _fcc = document.getElementById('catFilterCount'); if(_fcc) _fcc.textContent = _fsAllList.length + ' producto' + (_fsAllList.length !== 1 ? 's' : '');
  renderFooterCats();
}

/* ═════════════════════════════════════
   PRODUCT CARD HTML
═════════════════════════════════════ */
function productCardHTML(p) {
  const img = p.imgs && p.imgs[0] || p.img || null;
  const inW = wish.includes(p.id);
  var autoPct = (!p.off && p.orig && p.orig > p.price) ? Math.round((1-p.price/p.orig)*100) : 0;
  var offPct = p.off || autoPct;
  var badgeOff = offPct >= 5 ? `<span class="prod-badge off">−${offPct}%</span>` : '';
  var hasRat = p.rat && p.rat > 0;
  var _ratDisp = hasRat ? (Math.round(Math.min(p.rat,5)*10)/10).toFixed(1) : null;
  var _revCount = hasRat && p.rev > 0 ? p.rev : 0;
  var shipHtml = p.envio ? `<div class="prod-ship" style="font-size:11px;letter-spacing:0.05em;text-transform:uppercase;color:var(--accent);display:flex;align-items:center;gap:4px;margin-top:4px;">✓ Envío gratis</div>` : '';
  var cuotasHtml = '';
  var ratHtml = hasRat ? `<div style="display:flex;align-items:center;gap:5px;font-size:11px;color:var(--mute);"><span style="color:#F59E0B;">★</span>${_ratDisp}${_revCount > 0 ? `<span style="opacity:.45">·</span>${_revCount >= 1000 ? (_revCount/1000).toFixed(1)+'k' : _revCount}` : ''}</div>` : '';
  var _pSlug = p.slug || (_toSlug(p.name) + '-' + p.id.slice(-4));
  return `
  <a class="prod" href="/p/${_pSlug}" onclick="event.preventDefault();openPDP('${p.id}')">
    <div class="prod-img" style="aspect-ratio:1;background:var(--bg-2);position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;">
      ${badgeOff ? `<div class="pc-badges" style="flex-direction:row;">${badgeOff}</div>` : ''}
      <button class="prod-wish ${inW?'on':''}" aria-label="${inW?'Quitar de favoritos':'Agregar a favoritos'}" onclick="event.stopPropagation();event.preventDefault();togWishId('${p.id}')">${inW?'♥':'♡'}</button>
      <button class="prod-cmp-btn" id="cmpbtn-${p.id}" aria-label="Agregar a comparar" title="Comparar" onclick="event.stopPropagation();event.preventDefault();cmpToggle('${p.id}')">⇄</button>
      ${img ? `<img src="${img}" alt="${esc(p.name)}" loading="lazy" decoding="async" width="200" height="200" style="width:82%;height:82%;object-fit:contain;mix-blend-mode:multiply;transition:opacity .3s;" onerror="this.onerror=null;this.style.display='none';this.insertAdjacentHTML('afterend','<div class=\\'pc-no-img\\'></div>')" class="prod-img-el">` : '<div class="pc-no-img"></div>'}
    </div>
    <div class="prod-body" style="padding:14px 16px;display:flex;flex-direction:column;gap:4px;flex:1;">
      ${p.brand ? `<div style="font-size:11px;letter-spacing:0.15em;text-transform:uppercase;color:var(--mute-2);font-weight:500;">${esc(p.brand)}</div>` : ''}
      <div style="font-size:14px;line-height:1.35;color:var(--ink);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;min-height:36px;">${esc(p.name)}</div>
      ${ratHtml}
      <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
        <span style="font-size:22px;font-weight:700;letter-spacing:-0.03em;color:var(--ink);font-variant-numeric:tabular-nums;">${fp(p.price)}</span>
        ${p.orig ? `<span style="font-size:12px;color:var(--mute);text-decoration:line-through;">${fp(p.orig)}</span>` : ''}
      </div>
      ${cuotasHtml}
      ${shipHtml}
    </div>
    <div class="prod-foot" style="display:flex;align-items:center;padding:0 16px 14px;gap:8px;">
      <button class="prod-add" id="pcbtn-${p.id}" aria-label="Agregar al carro" onclick="event.stopPropagation();event.preventDefault();addToCart('${p.id}')">Al carro</button>
      <button onclick="event.stopPropagation();event.preventDefault();addToCartN('${p.id}',1,true);checkout()" style="height:38px;padding:0 14px;background:var(--ink);color:var(--bg);font-size:12px;font-weight:500;border-radius:var(--radius);display:flex;align-items:center;gap:6px;transition:opacity .15s;cursor:pointer;font-family:inherit;white-space:nowrap;border:none;">Comprar</button>
    </div>
  </a>`;
}

/* ═════════════════════════════════════
   HOME CATEGORIES GRID
═════════════════════════════════════ */
function renderHomeCats() {
  const activeCats = [...new Set(products.filter(p=>p.visible!==false).map(p=>p.cat).filter(Boolean))];
  const grid = document.getElementById('homeCatGrid');
  const CAT_ICONS = {
    electronica: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 8a4 4 0 0 1 4-4h12a4 4 0 0 1 4 4v8a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8Z"/><path d="M8 20v2m8-2v2M12 8v4m-3-2h6"/></svg>`,
    audio: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 18a3 3 0 1 1-6 0V9a9 9 0 1 1 18 0v9a3 3 0 1 1-6 0"/></svg>`,
    tecnologia: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></svg>`,
    computacion: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 6h16v10H4z"/><path d="M2 20h20"/></svg>`,
    telefonia: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4"/></svg>`,
    'salud-belleza': `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 21s-8-5-8-11a5 5 0 0 1 9-3 5 5 0 0 1 9 3c0 6-8 11-10 11Z"/></svg>`,
    hogar: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
    juguetes: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M12 6v12M8 6v12M16 6v12"/></svg>`,
    general: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg>`,
    accesorios: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 2v6a3 3 0 0 0 6 0V2M6 2h12M6 20h12"/></svg>`,
    deportes: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/></svg>`,
    cocina: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 11V5a2 2 0 0 1 2-2h2v8"/><path d="M7 11V3M11 11V5a2 2 0 0 1 2-2h2v8M15 11V3M3 11h18v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`,
  };
  const CAT_ACCENT = {
    electronica:'var(--cat-tint-1)', audio:'var(--cat-tint-3)', tecnologia:'var(--cat-tint-2)', computacion:'var(--cat-tint-5)',
    telefonia:'var(--cat-tint-4)', 'salud-belleza':'var(--cat-tint-1)', hogar:'var(--cat-tint-6)', juguetes:'var(--cat-tint-2)',
    general:'var(--cat-tint-3)', accesorios:'var(--cat-tint-4)', deportes:'var(--cat-tint-5)', cocina:'var(--cat-tint-6)',
  };
  // Fotos lifestyle (cubren toda la tarjeta, texto en blanco) para categorías sin foto de producto
  const CAT_COVER_IMGS = {
    electronica:     'https://images.unsplash.com/photo-1498049794561-7780e7231661?w=400&h=500&fit=crop&q=85',
    audio:           'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400&h=500&fit=crop&q=85',
    tecnologia:      'https://images.unsplash.com/photo-1519389950473-47ba0277781c?w=400&h=500&fit=crop&q=85',
    computacion:     'https://images.unsplash.com/photo-1517694712202-14dd9538aa97?w=400&h=500&fit=crop&q=85',
    telefonia:       'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400&h=500&fit=crop&q=85',
    'salud-belleza': 'https://images.unsplash.com/photo-1596462502278-27bfdc403348?w=400&h=500&fit=crop&q=85',
    juguetes:        'https://images.unsplash.com/photo-1566576912321-d58ddd7a6088?w=400&h=500&fit=crop&q=85',
    cocina:          'https://images.unsplash.com/photo-1556910103-1c02745aae4d?w=400&h=500&fit=crop&q=85',
    general:         'https://images.unsplash.com/photo-1607082348824-0a96f2a4b9da?w=400&h=500&fit=crop&q=85',
    hogar:           'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=400&h=500&fit=crop&q=85',
    accesorios:      'https://images.unsplash.com/photo-1611652022419-a9419f74343d?w=400&h=500&fit=crop&q=85',
    deportes:        'https://images.unsplash.com/photo-1517836357463-d25dfeac3438?w=400&h=500&fit=crop&q=85',
  };
  grid.innerHTML = cats.map(c => {
    const cnt = products.filter(p=>p.visible!==false && p.cat===c.name).length;
    const accentColor = CAT_ACCENT[c.id] || 'var(--accent)';
    // Producto destacado de la categoría (para el modo imagen flotante)
    const sample = products.find(p=>p.visible!==false && p.cat===c.name && (p.featured||p.hot) && (p.imgs?.[0]||p.img))
                || products.find(p=>p.visible!==false && p.cat===c.name && (p.imgs?.[0]||p.img));
    const productImgSrc = sample ? (sample.imgs?.[0] || sample.img || '') : '';
    // Si el admin puso c.bg → cover; si hay foto stock → cover; si hay producto → flotante con blend
    const coverImg = c.bg || CAT_COVER_IMGS[c.id] || '';
    const isCover = !!coverImg;
    const catIconSvg = CAT_ICONS[c.id] || CAT_ICONS['general'];
    const countLabel = cnt > 0 ? `${cnt} producto${cnt!==1?'s':''}` : '<span style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;opacity:.55">Próximamente</span>';
    if (isCover) {
      // Modo cover: foto de fondo lazy-loaded, gradiente oscuro, texto blanco
      return `<a class="cat-card-ed cat-card-cover" href="/c/${c.id}" onclick="event.preventDefault();openCatView('${c.id}')" data-bg="${coverImg.replace(/"/g,'&quot;')}">
        <div style="position:relative;z-index:2;">
          <div class="cat-text-ink" style="font-family:'Instrument Serif',serif;font-size:21px;line-height:1.1;letter-spacing:-0.01em;color:var(--ink);">${esc(c.name)}</div>
          <div class="cat-count-ink" style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${accentColor};display:flex;align-items:center;gap:5px;margin-top:6px;font-weight:600;">${countLabel}</div>
        </div>
      </a>`;
    }
    // Modo flotante: imagen del producto con blend mode (fondo blanco → transparente)
    return `<a class="cat-card-ed" href="/c/${c.id}" onclick="event.preventDefault();openCatView('${c.id}')">
      <div class="cat-accent-bar" style="background:${accentColor}"></div>
      ${productImgSrc
        ? `<div class="cat-prod-img" style="background-image:url('${productImgSrc.replace(/'/g,'%27')}')" role="img" aria-label="${esc(c.name)}"></div>`
        : `<div class="cat-fallback-icon" style="color:${accentColor}">${catIconSvg}</div>`
      }
      <div style="position:relative;z-index:2;">
        <div style="font-family:'Instrument Serif',serif;font-size:21px;line-height:1.1;letter-spacing:-0.01em;color:var(--ink);">${esc(c.name)}</div>
        <div style="font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:${accentColor};display:flex;align-items:center;gap:5px;margin-top:6px;font-weight:600;">${countLabel}</div>
      </div>
    </a>`;
  }).join('');
  // Lazy-load imágenes cover: IntersectionObserver carga el background-image solo cuando la tarjeta es visible
  const io = new IntersectionObserver((entries, obs) => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const el = e.target;
      const bg = el.dataset.bg;
      if (bg) { el.style.backgroundImage = `url('${bg}')`; delete el.dataset.bg; }
      obs.unobserve(el);
    });
  }, { rootMargin: '200px' });
  grid.querySelectorAll('.cat-card-cover[data-bg]').forEach(el => io.observe(el));
  // Mark grid as rendered so CSS animation doesn't re-fire on next call
  setTimeout(()=>grid.classList.add('cats-rendered'),600);
}

function renderFooterCats() {
  const activeCats = [...new Set(products.filter(p=>p.visible!==false).map(p=>p.cat).filter(Boolean))];
  document.getElementById('footerCats').innerHTML = cats
    .filter(c => activeCats.includes(c.name))
    .map(c => `<li><a href="/c/${c.id}" onclick="event.preventDefault();openCatView('${c.id}')">${esc(c.name)}</a></li>`).join('')
    || '<li><a>Sin categorías</a></li>';
}

/* ═════════════════════════════════════
   PROMO CAROUSEL
═════════════════════════════════════ */
var sliderTimer = null;

function renderHeroSlider() {
  const container = document.getElementById('heroSlider');
  if (!container) return;
  const safe_bg = s => /^#[0-9a-fA-F]{3,8}$|^var\(--[a-z-]+\)$|^linear-gradient/.test(s||'') ? s : 'var(--grad)';
  const side_emoji = s => { const m = (s.badge||'').match(/^\p{Emoji}/u); return m ? m[0] : '🛍️'; };
  const slides = banners.map((s, i) => `
    <div class="slide${i===0?' active':''}" id="slide-${i}" role="group" aria-label="Anuncio ${i+1} de ${banners.length}">
      <div class="slide-bg" style="${s.bg ? `background-image:url('${s.bg.replace(/'/g,'%27')}')` : 'background:var(--ink)'}"></div>
      <div class="slide-overlay" style="background:${esc(s.overlay||'linear-gradient(135deg,rgba(10,13,24,.92) 50%,rgba(232,23,93,.2))')}"></div>
      <div class="slide-content">
        <div class="slide-text">
          <div class="slide-badge">${esc(s.badge||'')}</div>
          <h2 class="slide-title">${esc(s.title||'Bienvenido').replace(/\n/g,'<br>')}</h2>
          <p class="slide-sub">${esc(s.sub||'')}</p>
          <div class="slide-detail">${esc(s.detail||'')}</div>
          <div class="slide-price-txt">${esc(s.price||'')}</div>
          <button class="slide-cta" style="background:${safe_bg(s.btnColor)};color:#fff" onclick="(function(){var t=${JSON.stringify(s.btnText||'')};if(t.toLowerCase().includes('ofert')){showOffersFilter();return;}if(/cat[aá]logo/i.test(t)){goHome();return;}if(t.toLowerCase().includes('term')){openLegal&&openLegal();return;}document.getElementById('homeProdsSection').scrollIntoView({behavior:'smooth'});})()">
            ${esc(s.btnText||'Ver productos')}
          </button>
        </div>
        <div class="slide-side" aria-hidden="true">${side_emoji(s)}</div>
      </div>
    </div>`).join('');
  const dots = banners.map((_,i) => `<button class="dot${i===0?' active':''}" onclick="goSlide(${i})" aria-label="Ir a anuncio ${i+1}"></button>`).join('');
  container.innerHTML = slides +
    `<div class="slide-dots" role="tablist">${dots}</div>` +
    `<div class="slide-arrows">
      <button class="slide-arr" onclick="prevSlide()" aria-label="Anuncio anterior"><i class="fas fa-chevron-left"></i></button>
      <button class="slide-arr" onclick="nextSlide()" aria-label="Siguiente anuncio"><i class="fas fa-chevron-right"></i></button>
    </div>`;
  sliderIdx = 0;
  _startSliderTimer();
  container.addEventListener('mouseenter', _stopSliderTimer);
  container.addEventListener('mouseleave', _startSliderTimer);
  // Touch swipe en mobile
  var _sx = 0, _sy = 0;
  container.addEventListener('touchstart', function(e){ _sx = e.touches[0].clientX; _sy = e.touches[0].clientY; }, {passive:true});
  container.addEventListener('touchend', function(e){
    var dx = e.changedTouches[0].clientX - _sx;
    var dy = e.changedTouches[0].clientY - _sy;
    if (Math.abs(dx) < 40 || Math.abs(dx) < Math.abs(dy)) return;
    if (dx < 0) nextSlide(); else prevSlide();
  }, {passive:true});
}

function _startSliderTimer() {
  _stopSliderTimer();
  sliderTimer = setInterval(function(){ goSlide(sliderIdx + 1); }, 5000);
}
function _stopSliderTimer() {
  if (sliderTimer) { clearInterval(sliderTimer); sliderTimer = null; }
}

function goSlide(n) {
  const s = document.querySelectorAll('#heroSlider .slide');
  const d = document.querySelectorAll('#heroSlider .dot');
  if (!s.length) return;
  s[sliderIdx].classList.remove('active');
  d[sliderIdx].classList.remove('active');
  sliderIdx = (n + s.length) % s.length;
  s[sliderIdx].classList.add('active');
  d[sliderIdx].classList.add('active');
}
function nextSlide() { goSlide(sliderIdx + 1); _startSliderTimer(); }
function prevSlide() { goSlide(sliderIdx - 1); _startSliderTimer(); }

/* ═════════════════════════════════════
   PRODUCT DETAIL PAGE
═════════════════════════════════════ */
function populatePDP(p) {
  // Breadcrumb
  const cat = cats.find(c => c.name === p.cat);
  document.getElementById('pdpBreadcrumb').innerHTML =
    `<span class="bc-link" onclick="goHome()">Inicio</span>
     <i class="fas fa-chevron-right" style="font-size:9px"></i>
     ${p.cat ? `<span class="bc-link" onclick="openCatView('${cat?cat.id:''}')">${esc(p.cat)}</span><i class="fas fa-chevron-right" style="font-size:9px"></i>` : ''}
     <span class="bc-cur">${esc(p.name.length>40?p.name.slice(0,40)+'...':p.name)}</span>`;
  // Back button text
  document.getElementById('pdpBackBtn').innerHTML = `<i class="fas fa-arrow-left"></i>Volver a ${esc(p.cat || 'la tienda')}`;
  // Badges
  document.getElementById('pdpBadges').innerHTML = [
    p.hot     ? '<span class="pdp-badge pdpb-hot">🔥 Más Vendido</span>' : '',
    p.sale    ? '<span class="pdp-badge pdpb-sale">Oferta</span>' : '',
    p.newp    ? '<span class="pdp-badge pdpb-new">Nuevo</span>' : '',
    p.featured? '<span class="pdp-badge pdpb-feat">⭐ Destacado</span>' : '',
  ].filter(Boolean).join('');
  document.getElementById('pdpSku').innerHTML = p.sku ? `SKU: <span style="color:var(--text)">${esc(p.sku)}</span>` : '';
  document.getElementById('pdpTitle').textContent   = p.name;
  document.getElementById('pdpBrand').textContent   = p.brand || '';
  document.getElementById('pdpSeller').textContent  = p.seller || gc('name');
  const _rev = p.rev || 0;
  const starsRow = document.querySelector('.pdp-stars-row');
  if (_rev > 0) {
    const rat = Math.min(5, Math.max(0, p.rat || 4.5));
    document.getElementById('pdpStars').textContent  = '★'.repeat(Math.round(rat)) + '☆'.repeat(5-Math.round(rat));
    document.getElementById('pdpRat').textContent    = rat.toFixed(1);
    document.getElementById('pdpRevCnt').textContent = `(${_rev.toLocaleString('es-CL')} opiniones)`;
    if (starsRow) starsRow.style.display = '';
  } else {
    if (starsRow) starsRow.style.display = 'none';
  }
  // Pricing
  document.getElementById('pdpPriceBig').textContent = fp(p.price);
  if (p.orig) { document.getElementById('pdpPriceStrike').textContent=fp(p.orig); document.getElementById('pdpPriceStrike').style.display=''; }
  else document.getElementById('pdpPriceStrike').style.display='none';
  if (p.off) { document.getElementById('pdpOffPill').textContent=`-${p.off}% OFF`; document.getElementById('pdpOffPill').style.display=''; }
  else document.getElementById('pdpOffPill').style.display='none';
  document.getElementById('pdpCuotasLine').innerHTML = p.cuotas ? `<span>${p.cuotas}</span>` : '';
  document.getElementById('pdpInternet').querySelector('span').textContent = p.off ? `Precio de oferta: ${fp(p.price)}` : 'Precio válido para compras online';
  // Delivery
  const fshipNum = parseInt((gc('fship')||'19990').replace(/[$.,\s]/g,''))||19990;
  const delNorm = document.getElementById('del-normal');
  if (p.envio || p.price >= fshipNum) { delNorm.textContent = 'GRATIS'; delNorm.style.color = 'var(--accent)'; }
  else { delNorm.textContent = gc('shrm'); delNorm.style.color = 'var(--muted)'; }
  // Stock
  const sr = document.getElementById('pdpStockRow');
  if (p.stock != null) {
    sr.style.display = 'block';
    if (p.stock === 0) sr.innerHTML = `<div class="stock-row out"><i class="fas fa-circle" style="font-size:9px"></i>Sin stock · No disponible actualmente</div>`;
    else if (p.stock <= 5) sr.innerHTML = `<div class="stock-row low"><i class="fas fa-circle" style="font-size:9px"></i>Stock limitado — últimas unidades</div>`;
    else sr.innerHTML = `<div class="stock-row ok"><i class="fas fa-circle" style="font-size:9px"></i>En stock · Disponible para envío inmediato</div>`;
    document.getElementById('pdpMaxNote').textContent = p.stock > 0 ? `Máximo ${Math.min(p.stock,20)} unidades` : '';
  } else { sr.style.display='none'; document.getElementById('pdpMaxNote').textContent=''; }
  // Qty
  pdpQty = 1; document.getElementById('pdpQtyNum').textContent = '1';
  // Wish
  const wb = document.getElementById('pdpWishBtn');
  wb.classList.toggle('on', wish.includes(p.id));
  // Gallery
  buildPDPGallery(p);
  // Tabs
  buildPDPTabs(p);
  // Reviews
  buildReviews(p);
  // Related
  buildRelated(p);
  // Update cart badge
  updPdpCartBdg();
}

function buildPDPGallery(p) {
  const imgs = p.imgs && p.imgs.length ? p.imgs : [];
  const mainImg = document.getElementById('pdpMainImg');
  const noImg   = document.getElementById('pdpNoImg');
  const vBox    = document.getElementById('pdpVideoBox');
  vBox.classList.remove('show');
  document.getElementById('pdpVideoContent').innerHTML = '';
  if (imgs.length) { mainImg.src = imgs[0]; mainImg.alt = p.name; mainImg.style.display=''; noImg.style.display='none'; }
  else { mainImg.src=''; mainImg.alt=''; mainImg.style.display='none'; noImg.style.display='flex'; }
  mainImg.onclick = () => { if(mainImg.src) openZoom(mainImg.src); };
  // Swipe táctil horizontal en mobile para navegar entre imágenes
  const wrap = document.getElementById('pdpMainImgWrap');
  wrap._pdpImgIndex = 0;
  wrap.ontouchstart = null; wrap.ontouchend = null;
  if (imgs.length > 1) {
    let _tx0 = 0, _ty0 = 0;
    wrap.ontouchstart = function(e){ _tx0 = e.touches[0].clientX; _ty0 = e.touches[0].clientY; };
    wrap.ontouchend = function(e){
      var dx = e.changedTouches[0].clientX - _tx0;
      var dy = e.changedTouches[0].clientY - _ty0;
      if(Math.abs(dx) < 40 || Math.abs(dx) < Math.abs(dy)) return; // muy corto o más vertical que horizontal
      var cur = parseInt(wrap._pdpImgIndex) || 0;
      if(dx < 0) cur = (cur + 1) % imgs.length;          // desliza izquierda → siguiente
      else       cur = (cur - 1 + imgs.length) % imgs.length; // desliza derecha → anterior
      wrap._pdpImgIndex = cur;
      switchPdpImg(cur);
    };
  }
  // Thumbs
  let html = imgs.map((img,i) =>
    `<div class="thumb-item ${i===0?'active':''}" onclick="switchPdpImg(${i})"><img src="${img}" alt="${esc(p.name)} — imagen ${i+1}" loading="lazy" decoding="async" width="80" height="80"></div>`
  ).join('');
  if (p.video) html += `<div class="thumb-item is-video" onclick="showPdpVideo('${esc(p.video)}')" title="Ver video"></div>`;
  document.getElementById('pdpThumbs').innerHTML = html;
}

function switchPdpImg(i) {
  const p = currentProd;
  if (!p || !p.imgs || !p.imgs[i]) return;
  const mainImg = document.getElementById('pdpMainImg');
  const vBox = document.getElementById('pdpVideoBox');
  vBox.classList.remove('show');
  document.getElementById('pdpVideoContent').innerHTML = '';
  mainImg.style.display = ''; mainImg.src = p.imgs[i];
  document.querySelectorAll('.thumb-item').forEach((t,ti) => t.classList.toggle('active', ti===i));
  // Sync swipe index so swipe siempre continúa desde la imagen actual
  var wrap = document.getElementById('pdpMainImgWrap');
  if(wrap) wrap._pdpImgIndex = i;
}

function showPdpVideo(url) {
  const vBox = document.getElementById('pdpVideoBox');
  const mainImg = document.getElementById('pdpMainImg');
  mainImg.style.display = 'none';
  vBox.classList.add('show');
  let embed = '';
  if (url.includes('youtube.com') || url.includes('youtu.be')) {
    const vid = url.includes('youtu.be') ? url.split('youtu.be/')[1].split('?')[0] : new URL(url).searchParams.get('v');
    embed = `<iframe src="https://www.youtube.com/embed/${vid}?autoplay=1" allow="autoplay;encrypted-media" allowfullscreen style="width:100%;height:100%;border:none;border-radius:10px"></iframe>`;
  } else {
    embed = `<video controls autoplay style="width:100%;height:100%;border-radius:10px"><source src="${url}"></video>`;
  }
  document.getElementById('pdpVideoContent').innerHTML = embed;
  document.querySelectorAll('.thumb-item').forEach(t => t.classList.remove('active'));
  const vt = document.querySelector('.thumb-item.is-video'); if(vt) vt.classList.add('active');
}

function buildPDPTabs(p) {
  // Description
  document.getElementById('pdpDescText').innerHTML = p.desc
    ? p.desc.split(/\n\n+/).map(function(par){ return '<p>'+esc(par.trim()).replace(/\n/g,'<br>')+'</p>'; }).join('')
    : '<p style="color:var(--muted)">Sin descripción disponible.</p>';
  // Features
  const fl = document.getElementById('pdpFeatsList');
  if (p.feats && p.feats.length) { fl.innerHTML = p.feats.map(f=>`<li>${esc(f)}</li>`).join(''); fl.style.display=''; }
  else fl.style.display = 'none';
  // Specs
  const rows = [{k:'Nombre',v:p.name},{k:'Marca',v:p.brand||'–'},{k:'Categoría',v:p.cat||'–'}, ...(p.specs||[])];
  if (p.sku) rows.push({k:'SKU / Modelo',v:p.sku});
  document.getElementById('pdpSpecsTbl').innerHTML = rows.map(r=>`<tr><td>${esc(r.k)}</td><td>${esc(r.v)}</td></tr>`).join('');
  // Video tab
  const nav = document.getElementById('pdpTabsNav');
  const existing = nav.querySelector('.video-tab');
  if (existing) existing.remove();
  if (p.video) {
    const vb = document.createElement('button');
    vb.className = 'tab-btn video-tab'; vb.textContent = '▶ Video';
    vb.onclick = function() { swPdpTab('video',this); showPdpVideo(p.video); };
    nav.appendChild(vb);
  }
}

function swPdpTab(t, btn) {
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('on'));
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('on'));
  if(btn) btn.classList.add('on');
  const pane = document.getElementById('tp-'+t);
  if(pane) pane.classList.add('on');
}

function buildReviews(p) {
  var stored = (reviewsDB[p.id] || []).slice().reverse(); // newest first
  var hasStored = stored.length > 0;
  // Rating summary: use real reviews when available, else fall back to product seed data
  var rat, cnt;
  if (hasStored) {
    var sum = stored.reduce(function(a, r){ return a + r.rating; }, 0);
    rat = Math.min(5, sum / stored.length);
    cnt = stored.length;
  } else {
    rat = Math.min(5, Math.max(0, p.rat || 0));
    cnt = p.rev || 0;
  }
  var reviewsWrap = document.querySelector('#tp-reviews .reviews-wrap');
  if (!hasStored && cnt === 0) {
    if (reviewsWrap) reviewsWrap.style.display = 'none';
  } else {
    if (reviewsWrap) reviewsWrap.style.display = '';
    document.getElementById('revAvg').textContent = rat.toFixed(1);
    document.getElementById('revStars').textContent = '★'.repeat(Math.round(rat)) + '☆'.repeat(5 - Math.round(rat));
    document.getElementById('revCount').textContent = cnt.toLocaleString('es-CL') + ' opiniones';
  }
  // Distribution bars
  var dist;
  if (hasStored) {
    var buckets = [0,0,0,0,0];
    stored.forEach(function(r){ if(r.rating>=1&&r.rating<=5) buckets[r.rating-1]++; });
    dist = [buckets[4], buckets[3], buckets[2], buckets[1], buckets[0]]; // 5★ first
  } else {
    dist = [Math.round(cnt*.6), Math.round(cnt*.2), Math.round(cnt*.12), Math.round(cnt*.05), Math.round(cnt*.03)];
  }
  var total = dist.reduce(function(a,b){ return a+b; }, 0) || 1;
  document.getElementById('ratBarsWrap').innerHTML = [5,4,3,2,1].map(function(s,i){
    return '<div class="rbar-row"><span class="rl">'+s+'★</span><div class="rbar-track"><div class="rbar-fill" style="width:'+Math.round(dist[i]/total*100)+'%"></div></div><span class="rc">'+dist[i].toLocaleString('es-CL')+'</span></div>';
  }).join('');
  // Review cards
  var isAdm = !!(function(){ try{ return sessionStorage.getItem('mx_admin_token'); }catch(e){ return ''; } }());
  var listHtml;
  if (hasStored) {
    listHtml = stored.map(function(r){
      var stars = '★'.repeat(r.rating) + '☆'.repeat(5 - r.rating);
      var delBtn = isAdm ? '<button class="rev-admin-del" onclick="deleteReview(\''+p.id+'\',\''+r.id+'\')" title="Eliminar">✕</button>' : '';
      return '<div class="review-card" id="rev-'+r.id+'">'+delBtn+'<div class="rev-head"><div class="rev-user"><div class="rev-av">'+esc(r.name[0].toUpperCase())+'</div><div><div class="rev-name">'+esc(r.name)+'</div><div class="rev-date">'+esc(r.date)+'</div></div></div><div style="color:#F59E0B;font-size:14px">'+stars+'</div></div><div class="rev-body">'+esc(r.comment)+'</div></div>';
    }).join('');
  } else if (cnt > 0) {
    listHtml = '<p style="color:var(--muted);text-align:center;padding:20px 0">Sé el primero en dejar tu opinión sobre este producto.</p>';
  } else {
    listHtml = '<p style="color:var(--muted);text-align:center;padding:20px 0">Aún no hay opiniones. ¡Sé el primero!</p>';
  }
  // Review form
  var formHtml = '<div class="rev-form">'
    + '<h4>Dejar una opinión</h4>'
    + '<div class="rev-star-pick">'
    + [5,4,3,2,1].map(function(n){ return '<input type="radio" name="rev-rating-'+p.id+'" id="rs'+n+'-'+p.id+'" value="'+n+'"><label for="rs'+n+'-'+p.id+'">★</label>'; }).join('')
    + '</div>'
    + '<div class="rev-form-row"><input type="text" id="rev-name-'+p.id+'" placeholder="Tu nombre (requerido)" maxlength="60"></div>'
    + '<textarea id="rev-comment-'+p.id+'" placeholder="Cuéntanos tu experiencia con este producto (mínimo 10 caracteres)" maxlength="600"></textarea>'
    + '<button class="btn-ed btn-primary-ed" onclick="submitReview(\''+p.id+'\')">Publicar opinión</button>'
    + '</div>';
  document.getElementById('reviewsListWrap').innerHTML = listHtml + formHtml;
}

function submitReview(prodId) {
  var ratingEl = document.querySelector('input[name="rev-rating-'+prodId+'"]:checked');
  var nameEl   = document.getElementById('rev-name-'+prodId);
  var commentEl= document.getElementById('rev-comment-'+prodId);
  if (!ratingEl)              { showToast('Selecciona una calificación ★'); return; }
  if (!nameEl.value.trim())   { showToast('Ingresa tu nombre'); return; }
  if (commentEl.value.trim().length < 10) { showToast('El comentario debe tener al menos 10 caracteres'); return; }
  var now = new Date();
  var months = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
  var dateStr = now.getDate() + ' ' + months[now.getMonth()] + ' ' + now.getFullYear();
  var entry = { id: uid(), name: nameEl.value.trim(), rating: parseInt(ratingEl.value), comment: commentEl.value.trim(), date: dateStr };
  if (!reviewsDB[prodId]) reviewsDB[prodId] = [];
  reviewsDB[prodId].push(entry);
  saveReviews();
  var prod = products.find(function(x){ return x.id === prodId; });
  if (prod) buildReviews(prod);
  showToast('¡Opinión publicada! Gracias por ayudar a otros compradores ✓');
}

function deleteReview(prodId, revId) {
  if (!reviewsDB[prodId]) return;
  reviewsDB[prodId] = reviewsDB[prodId].filter(function(r){ return r.id !== revId; });
  saveReviews();
  var prod = products.find(function(x){ return x.id === prodId; });
  if (prod) buildReviews(prod);
  showToast('Opinión eliminada');
}

function buildRelated(p) {
  const rel = products.filter(x => x.id!==p.id && x.visible!==false && (x.cat===p.cat||x.brand===p.brand)).slice(0,4);
  document.getElementById('relatedGrid').innerHTML = rel.length
    ? rel.map(r => {
        const img = r.imgs&&r.imgs[0]||null;
        const _rSlug = r.slug || (_toSlug(r.name) + '-' + r.id.slice(-4));
        return `<a class="product-card" href="/p/${_rSlug}" onclick="event.preventDefault();openPDP('${r.id}')">
          <div class="pc-img-wrap">${img?`<img src="${img}" alt="${esc(r.name)}" loading="lazy">`:`<div class="pc-no-img">📦</div>`}</div>
          <div class="pc-info">
            <div class="pc-brand">${r.brand||''}</div>
            <div class="pc-name">${r.name}</div>
            <div class="pc-prices"><span class="pc-price-now">${fp(r.price)}</span></div>
            <button class="pc-add" onclick="event.stopPropagation();event.preventDefault();addToCart('${r.id}')"><i class="fas fa-shopping-cart"></i>Agregar</button>
          </div>
        </a>`;
      }).join('')
    : '<p style="color:var(--muted)">Pronto habrá más productos en esta categoría.</p>';
}

function chgPdpQty(d) {
  const max = currentProd?.stock > 0 ? Math.min(currentProd.stock, 20) : 20;
  pdpQty = Math.max(1, Math.min(max, pdpQty + d));
  document.getElementById('pdpQtyNum').textContent = pdpQty;
}

function buyNowPDP(){
  if(!currentProd) return;
  addToCartN(currentProd.id, pdpQty, true); // silent=true: no toast, va directo a checkout
  setTimeout(()=>{ checkout(); }, 120);
}
function addFromPDP() {
  if (!currentProd) return;
  addToCartN(currentProd.id, pdpQty);
  const btn = document.getElementById('pdpAddBtn');
  btn.innerHTML = '<i class="fas fa-check"></i> ¡Agregado al carro!';
  btn.style.background = 'linear-gradient(135deg,var(--green),#00897B)';
  setTimeout(() => { btn.innerHTML='<i class="fas fa-shopping-cart"></i>Agregar al carro'; btn.style.background=''; }, 2200);
}

function togWishPDP() {
  if (!currentProd) return;
  togWishId(currentProd.id);
  document.getElementById('pdpWishBtn').classList.toggle('on', wish.includes(currentProd.id));
}

function shareP(net) {
  const title = currentProd ? currentProd.name : '';
  const url = window.location.href;
  if (net === 'native') {
    if (navigator.share) {
      navigator.share({ title: title, url: url }).catch(function(){});
    } else {
      copyLink();
    }
    return;
  }
  const urls = {
    facebook: `https://facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}`,
    twitter:  `https://twitter.com/intent/tweet?text=${encodeURIComponent(title)}&url=${encodeURIComponent(url)}`,
    whatsapp: `https://wa.me/?text=${encodeURIComponent(title+' - '+url)}`
  };
  if (urls[net]) window.open(urls[net], '_blank', 'width=600,height=400,noopener');
}
function copyLink() {
  var url = window.location.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url)
      .then(function(){ showToast('Enlace copiado — compártelo donde quieras ✓'); })
      .catch(function(){ _copyLinkFallback(url); });
  } else {
    _copyLinkFallback(url);
  }
}
function _copyLinkFallback(text) {
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;pointer-events:none;';
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  try { document.execCommand('copy'); showToast('Enlace copiado — compártelo donde quieras ✓'); }
  catch(e) { showToast('No se pudo copiar el enlace', 'error'); }
  document.body.removeChild(ta);
}
function openZoom(src) { document.getElementById('zoomImg').src=src; document.getElementById('zoomOv').classList.add('open'); }
function closeZoom() { document.getElementById('zoomOv').classList.remove('open'); }
function updPdpCartBdg() { /* badge removido — carro visible en header */ }

/* ═════════════════════════════════════
   CART
═════════════════════════════════════ */
function addToCart(id){
  var btn=document.getElementById('pcbtn-'+id);
  if(btn) _flyToCart(btn);
  addToCartN(id,1);
  if(btn){
    var orig=btn.innerHTML;
    btn.innerHTML='<i class="fas fa-check"></i> ¡Agregado!';
    btn.style.background='var(--pink)';btn.style.color='#fff';
    setTimeout(function(){ btn.innerHTML=orig; btn.style.background=''; btn.style.color=''; },1800);
  }
}
function addToCartN(id, qty=1, silent=false) {
  if(sessionStorage.getItem('mx_mp_pending')){
    if(typeof showToast==='function') showToast('Tienes un pago en proceso. Complétalo antes de agregar más productos.','warn');
    return false;
  }
  const p = products.find(x=>x.id===id); if(!p) return;
  const ex = cart.find(x=>x.id===id);
  if (ex) ex.qty += qty; else cart.push({id:p.id, name:p.name, price:p.price, img:p.imgs&&p.imgs[0]||null, brand:p.brand, qty});
  saveC(); updCartBadge(); renderCart();
  if(!silent) showToast('¡Listo, está en tu carro! 🛒');
  const btn = document.getElementById('pcbtn-'+id);
  if (btn) { btn.classList.add('added'); btn.innerHTML='<i class="fas fa-check"></i> ¡Agregado!'; setTimeout(()=>{btn.classList.remove('added');btn.innerHTML='<i class="fas fa-shopping-cart"></i> Agregar al carro';},2000); }
}
function remFromCart(id) { cart=cart.filter(x=>x.id!==id); saveC(); updCartBadge(); renderCart(); }
function chgQty(id, d) { const i=cart.find(x=>x.id===id); if(!i)return; i.qty+=d; if(i.qty<=0)remFromCart(id); else{saveC();updCartBadge();renderCart();} }
function updCartBadge() { const t=cart.reduce((s,i)=>s+i.qty,0); document.getElementById('cartBdg').textContent=t; updPdpCartBdg(); }
function renderCart() {
  const b=document.getElementById('cartBody'), f=document.getElementById('cartFoot');
  const clearBtn = document.getElementById('clearCartBtn');
  if (!cart.length) { b.innerHTML='<div class="empty-cart"><i class="fas fa-shopping-cart"></i><p>Tu carro está vacío</p></div>'; f.style.display='none'; if(clearBtn) clearBtn.style.display='none'; _updShipBar(); return; }
  if(clearBtn) clearBtn.style.display='block';
  f.style.display = 'block';
  b.innerHTML = cart.map(i => `
    <div class="cart-item">
      ${i.img ? `<img class="ci-thumb" src="${i.img}" alt="">` : `<div class="ci-no-img">📦</div>`}
      <div class="ci-body">
        <h5>${esc(i.name)}</h5>
        <div class="ci-price" style="display:flex;align-items:center;gap:6px">${fp(i.price)}<span style="font-size:11px;color:var(--muted);font-weight:400">c/u</span></div>
        <div class="ci-qty-row">
          <button class="ci-qty-btn" aria-label="Disminuir cantidad" onclick="chgQty('${i.id}',-1)"><i class="fas fa-minus"></i></button>
          <span class="ci-qty-val">${i.qty}</span>
          <button class="ci-qty-btn" aria-label="Aumentar cantidad" onclick="chgQty('${i.id}',1)"><i class="fas fa-plus"></i></button>
          <button class="ci-del" aria-label="Eliminar producto" onclick="remFromCart('${i.id}')"><i class="fas fa-trash"></i></button>
        </div>
        ${i.qty > 1 ? `<div style="font-size:12px;color:var(--pink);font-weight:700;margin-top:3px">Subtotal: ${fp(i.price*i.qty)}</div>` : ''}
      </div>
    </div>`).join('');
  document.getElementById('cartTotal').textContent = fp(cart.reduce((s,i)=>s+i.price*i.qty,0));
  _updShipBar();
}
function _updShipBar(){
  var el=document.getElementById('cartShipProg');
  if(!el)return;
  if(!cart.length){el.innerHTML='';return;}
  var sub=cart.reduce(function(s,i){return s+i.price*i.qty;},0);
  var rawFship=gc('fship')||'$19.990';
  var freeFrom=parseInt(rawFship.replace(/\D/g,''))||19990;
  if(sub>=freeFrom){
    el.innerHTML='<p class="csp-done"><i class="fas fa-check-circle"></i> ¡Envío gratis incluido en tu pedido!</p>';
  } else {
    var remain=freeFrom-sub;
    var pct=Math.min(100,Math.round(sub/freeFrom*100));
    el.innerHTML='<p class="csp-msg">Agrega <strong>'+fp(remain)+'</strong> más para <strong>envío gratis</strong></p><div class="csp-track"><div class="csp-fill" style="width:'+pct+'%"></div></div>';
  }
}
/* ── Focus-trap utility ── */
var _ftCleanups = {};
function _trapFocus(containerId) {
  var el = document.getElementById(containerId);
  if (!el) return;
  var sel = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
  function handler(e) {
    if (e.key !== 'Tab') return;
    var focusable = Array.from(el.querySelectorAll(sel)).filter(function(n){ return !n.closest('[style*="display:none"]'); });
    if (!focusable.length) { e.preventDefault(); return; }
    var first = focusable[0], last = focusable[focusable.length-1];
    if (e.shiftKey) { if (document.activeElement === first) { last.focus(); e.preventDefault(); } }
    else { if (document.activeElement === last) { first.focus(); e.preventDefault(); } }
  }
  el.addEventListener('keydown', handler);
  _ftCleanups[containerId] = function(){ el.removeEventListener('keydown', handler); };
  // set initial focus to first focusable
  var firstEl = el.querySelector(sel);
  if (firstEl) setTimeout(function(){ firstEl.focus(); }, 50);
}
function _releaseFocus(containerId) {
  if (_ftCleanups[containerId]) { _ftCleanups[containerId](); delete _ftCleanups[containerId]; }
}
document.addEventListener('keydown', function(e){
  if (e.key !== 'Escape') return;
  var ck = document.getElementById('ckOverlay');
  if (ck && ck.classList.contains('open')) { closeCheckout(); return; }
  var cartOv = document.getElementById('cartOv');
  if (cartOv && cartOv.classList.contains('open')) { togCart(); return; }
  var zoom = document.getElementById('zoomOv');
  if (zoom && zoom.classList.contains('open')) { closeZoom(); return; }
  var faq = document.getElementById('faqOverlay');
  if (faq && faq.classList.contains('open') && typeof closeFAQ==='function') { closeFAQ(); return; }
});
function togCart() {
  var isOpening = !document.getElementById('cartPan').classList.contains('open');
  document.getElementById('cartOv').classList.toggle('open');
  document.getElementById('cartPan').classList.toggle('open');
  if (isOpening) _trapFocus('cartPan'); else _releaseFocus('cartPan');
}
/* ═══════════ CHECKOUT ═══════════ */
function checkout(){
  if(!cart.length){showToast('El carro está vacío','error');return;}
  // Cerrar carrito
  document.getElementById('cartOv').classList.remove('open');
  document.getElementById('cartPan').classList.remove('open');
  // Poblar resumen
  updateCkSummary();
  // Items del resumen
  const wrap = document.getElementById('ckItems');
  wrap.innerHTML = cart.map(i=>{
    const thumb = i.img ? `<img src="${esc(i.img)}" alt="">` : `<span>📦</span>`;
    return `<div class="ck-item">
      <div class="ck-item-img">${thumb}</div>
      <div class="ck-item-info"><p>${esc(i.name)}</p><span>x${i.qty} · ${esc(i.brand||'')}</span></div>
      <div class="ck-item-price">${fp(i.price*i.qty)}</div>
    </div>`;
  }).join('');
  // Reset cupón
  _coupon=null;
  var _ci=document.getElementById('ckCouponInp'),_cm=document.getElementById('ckCouponMsg');
  if(_ci){_ci.value='';_ci.disabled=false;}
  if(_cm){_cm.className='ck-coupon-msg';_cm.textContent='';}
  // Reset form y mostrar
  document.getElementById('ckForm').style.display = '';
  document.getElementById('ckSummary').style.display = '';
  document.getElementById('ckSuccess').style.display = 'none';
  document.getElementById('ckOverlay').classList.add('open');
  _trapFocus('ckBox');
  // Asegurar label del botón según pago por defecto (MP)
  var ckBtn = document.getElementById('ckConfirmBtn');
  if(ckBtn) ckBtn.innerHTML = '<i class="fas fa-wallet"></i> Pagar con Mercado Pago';
}
function closeCheckout(){
  document.getElementById('ckOverlay').classList.remove('open');
  _releaseFocus('ckBox');
  if(window._mpTimerInterval){clearInterval(window._mpTimerInterval);window._mpTimerInterval=null;}
}
function selPay(el,val){
  document.querySelectorAll('.ck-pay-opt').forEach(o=>o.classList.remove('sel'));
  el.classList.add('sel');
  el.querySelector('input').checked = true;
  // Datos bancarios solo si transferencia
  var bankInfo = document.getElementById('bankInfo');
  if(bankInfo) bankInfo.style.display = (val==='transfer') ? 'block' : 'none';
  // Actualizar resumen sin descuento MP
  updateCkSummary();
  // Texto botón
  var btn = document.querySelector('.ck-confirm-btn');
  if(!btn) return;
  var labels = {
    webpay:   '<i class="fas fa-credit-card"></i> Pagar con Webpay',
    mp:       '<i class="fas fa-wallet"></i> Pagar con Mercado Pago',
    transfer: '<i class="fas fa-paper-plane"></i> Confirmar y enviar datos'
  };
  btn.innerHTML = labels[val] || '<i class="fas fa-lock"></i> Confirmar pedido';
}
const SHIPPING_RATES={
  'Región Metropolitana':2990,
  'Valparaíso':3990,"O'Higgins":3990,'Maule':3990,'Ñuble':3990,
  'Biobío':4990,'La Araucanía':4990,'Los Ríos':4990,'Coquimbo':4990,
  'Los Lagos':5990,'Atacama':5990,
  'Antofagasta':6990,'Tarapacá':6990,
  'Arica y Parinacota':7990,'Aysén':7990,'Magallanes':7990
};
function updateCkSummary(){
  var sub = cart.reduce(function(s,i){return s+i.price*i.qty;},0);
  var region = (document.getElementById('ck-region')||{}).value||'';
  // Parse free-shipping threshold: treat $0 or missing as "no free shipping" (use 999999999)
  var rawFship = (gc('fship')||'').replace(/\D/g,'');
  var freeFrom = rawFship && rawFship!=='0' ? (parseInt(rawFship)||999999999) : 999999999;
  var shipFree = freeFrom < 999999999 && sub >= freeFrom;
  var baseShip = SHIPPING_RATES[region]||3990;
  var shipNum = shipFree ? 0 : baseShip;
  // Coupon discount
  var discount = 0;
  var discEl=document.getElementById('ckDiscountRow'), discValEl=document.getElementById('ck-discount');
  if(_coupon && _coupon.pct > 0){
    discount = Math.round(sub * _coupon.pct / 100);
    if(discEl) discEl.style.display='flex';
    if(discValEl) discValEl.textContent='-'+fp(discount);
  } else {
    if(discEl) discEl.style.display='none';
  }
  var afterDiscount = Math.max(0, sub - discount);
  var subEl=document.getElementById('ck-sub'), shipEl=document.getElementById('ck-ship'), totEl=document.getElementById('ck-total');
  if(subEl) subEl.textContent=fp(sub);
  if(shipEl){
    if(shipFree){shipEl.textContent='GRATIS';shipEl.style.color='var(--green)';}
    else if(!region){shipEl.textContent='Selecciona región';shipEl.style.color='var(--muted)';}
    else{shipEl.textContent=fp(shipNum);shipEl.style.color='var(--text)';}
  }
  if(totEl) totEl.textContent=fp(shipFree?afterDiscount:(region?afterDiscount+shipNum:afterDiscount));
}
/* ── Cupón de descuento ── */
var _coupon = null;
function applyCoupon(){
  var inp = document.getElementById('ckCouponInp');
  var msgEl = document.getElementById('ckCouponMsg');
  var btn = document.getElementById('ckCouponBtn');
  if(!inp || !msgEl) return;
  var code = inp.value.trim().toUpperCase();
  if(!code){ msgEl.className='ck-coupon-msg err'; msgEl.textContent='Ingresa un código.'; return; }
  if(!API_BASE){ msgEl.className='ck-coupon-msg err'; msgEl.textContent='Cupones no disponibles sin conexión.'; return; }
  if(btn){ btn.disabled=true; btn.textContent='...'; }
  fetchWithTimeout(API_BASE+'/api/coupon/'+encodeURIComponent(code),{},6000)
    .then(function(r){return r.json();})
    .then(function(d){
      if(btn){ btn.disabled=false; btn.textContent='Aplicar'; }
      if(!d.ok || !d.valid){
        _coupon=null;
        msgEl.className='ck-coupon-msg err';
        msgEl.innerHTML='<i class="fas fa-times-circle"></i> Cupón inválido o expirado.';
        updateCkSummary(); return;
      }
      _coupon={code:code, pct:d.pct};
      msgEl.className='ck-coupon-msg ok';
      msgEl.innerHTML='<i class="fas fa-tag"></i> ¡'+d.pct+'% de descuento aplicado! <a href="#" style="color:var(--muted);font-size:11px;margin-left:6px;" onclick="removeCoupon();return false;">Quitar</a>';
      if(inp) inp.disabled=true;
      updateCkSummary();
    })
    .catch(function(){
      if(btn){ btn.disabled=false; btn.textContent='Aplicar'; }
      msgEl.className='ck-coupon-msg err';
      msgEl.innerHTML='<i class="fas fa-exclamation-circle"></i> Error al validar. Intenta de nuevo.';
    });
}
function removeCoupon(){
  _coupon=null;
  var inp=document.getElementById('ckCouponInp');
  var msgEl=document.getElementById('ckCouponMsg');
  if(inp){inp.value='';inp.disabled=false;}
  if(msgEl){msgEl.className='ck-coupon-msg';msgEl.textContent='';}
  updateCkSummary();
}
function updateCkSummaryWithMP(applyMP){ updateCkSummary(); } // backward compat
function _launchOrderWA(orderNum, waURL, isTransfer, hasComp){
  document.getElementById('ckOrderNum').textContent = '#'+orderNum;
  document.getElementById('ckForm').style.display = 'none';
  document.getElementById('ckSummary').style.display = 'none';
  var succEl = document.getElementById('ckSuccess');
  succEl.style.display = 'block';

  // Aviso especial para transferencia
  var noticeId = 'ck-transfer-notice';
  var existing = document.getElementById(noticeId);
  if(existing) existing.remove();
  if(isTransfer){
    var notice = document.createElement('div');
    notice.id = noticeId;
    notice.style.cssText = 'background:rgba(255,152,0,.10);border:1.5px solid rgba(255,152,0,.35);border-radius:10px;padding:13px 15px;margin:14px 0 4px;font-size:13px;color:var(--text);line-height:1.6;text-align:left;';
    notice.innerHTML = hasComp
      ? '<i class="fas fa-check-circle" style="color:var(--green)"></i> <strong>Comprobante recibido.</strong> Serás redirigido a WhatsApp con los datos de tu pedido y la confirmación de tu comprobante. Ábrelo y envía el mensaje para que confirmemos tu despacho.'
      : '<i class="fas fa-info-circle" style="color:var(--orange)"></i> Serás redirigido a WhatsApp con los datos de tu pedido ya cargados. Envía el mensaje y adjunta tu captura de transferencia en el chat para confirmar el pago.';
    succEl.insertBefore(notice, succEl.firstChild);
  }

  var cdEl = document.getElementById('ck-wa-countdown');
  if(!cdEl){
    cdEl = document.createElement('div');
    cdEl.id = 'ck-wa-countdown';
    cdEl.style.cssText = 'margin-top:14px;text-align:center;';
    succEl.appendChild(cdEl);
  }
  var waBtnHtml = '<a id="ck-wa-direct-btn" href="'+waURL+'" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:9px;background:#25D366;color:#fff;font-weight:700;font-size:15px;padding:13px 26px;border-radius:10px;text-decoration:none;box-shadow:0 4px 16px rgba(37,211,102,.35)"><i class="fab fa-whatsapp" style="font-size:20px"></i> Enviar pedido por WhatsApp</a>';
  if(isTransfer){
    var cdSecs = 5;
    cdEl.innerHTML = waBtnHtml+'<div id="ck-wa-cdsec" style="margin-top:10px;font-size:13px;color:var(--muted);">Abriendo WhatsApp en <strong id="ck-wa-n" style="color:var(--accent);font-family:\'JetBrains Mono\',monospace;">5</strong>s…</div>';
    var cdTimer = setInterval(function(){
      cdSecs--;
      var nEl = document.getElementById('ck-wa-n');
      if(nEl) nEl.textContent = cdSecs;
      if(cdSecs <= 0){
        clearInterval(cdTimer);
        var secEl = document.getElementById('ck-wa-cdsec');
        if(secEl) secEl.remove();
        window.location.href = waURL;
      }
    }, 1000);
  } else {
    cdEl.innerHTML = waBtnHtml;
  }
  cart = []; saveC(); updCartBadge(); renderCart();
}

/* ── RUT chileno ── */
function _cleanRUT(r){ return r.replace(/[\.\-\s]/g,'').toUpperCase(); }
function _calcDV(num){
  var s=0,f=2,rev=String(num).split('').reverse();
  for(var i=0;i<rev.length;i++){s+=parseInt(rev[i])*(f<8?f++:(f=2));} // 2-7 cycle
  var dv=11-(s%11);
  return dv===11?'0':dv===10?'K':String(dv);
}
function _rutValido(r){
  var c=_cleanRUT(r);
  if(c.length<2) return false;
  var dv=c.slice(-1), num=c.slice(0,-1);
  if(!/^\d+$/.test(num)) return false;
  if(parseInt(num)<1000000) return false;
  return _calcDV(num)===dv;
}
function fmtRUT(inp){
  var raw=inp.value.replace(/[\.\-\s]/g,'').replace(/[^0-9kK]/g,'').toUpperCase();
  if(raw.length<2){inp.value=raw;return;}
  var dv=raw.slice(-1), num=raw.slice(0,-1);
  // add dots every 3 digits from right
  var dotted=num.replace(/\B(?=(\d{3})+(?!\d))/g,'.');
  inp.value=dotted+'-'+dv;
  inp.style.color='';
}
function validateRUT(inp){
  var v=inp.value.trim();
  if(!v) return; // optional
  if(!_rutValido(v)){
    inp.style.color='var(--red)';
    inp.title='RUT inválido';
  } else {
    inp.style.color='var(--good)';
    inp.title='';
  }
}
function confirmOrder(){
  const name   = document.getElementById('ck-fname').value.trim();
  const email  = document.getElementById('ck-email').value.trim();
  const phone  = document.getElementById('ck-phone').value.trim();
  const rut    = (document.getElementById('ck-rut')||{}).value ? document.getElementById('ck-rut').value.trim() : '';
  const addr   = document.getElementById('ck-addr').value.trim();
  const city   = document.getElementById('ck-city').value.trim();
  const region = document.getElementById('ck-region').value;
  if(!name||!email||!phone||!addr||!city||!region){
    showToast('Completa todos los campos obligatorios','error'); return;
  }
  if(name.length < 2 || name.length > 100){ showToast('Nombre debe tener entre 2 y 100 caracteres','error'); return; }
  if(!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/)){ showToast('Email inválido — revisa el formato','error'); return; }
  const phoneClean = phone.replace(/[\s\-\(\)\.]/g,'');
  if(!phoneClean.match(/^(\+?56)?[29]\d{8}$/)){ showToast('Teléfono inválido — ej: +56912345678 o 912345678','error'); return; }
  if(rut && !_rutValido(rut)){ showToast('RUT inválido — revisa el formato (ej: 12.345.678-9)','error'); return; }
  if(addr.length < 5 || addr.length > 200){ showToast('Dirección debe tener entre 5 y 200 caracteres','error'); return; }

  const payEl  = document.querySelector('.ck-pay-opt.sel input');
  const payVal = payEl ? payEl.id.replace('pay-','') : 'webpay';
  const payNames = {webpay:'Webpay Plus (Débito/Crédito)', mp:'Mercado Pago', transfer:'Transferencia bancaria'};
  const payName = payNames[payVal] || payVal;

  const totalEl  = document.getElementById('ck-total');
  const shipEl   = document.getElementById('ck-ship');
  const totalTxt = totalEl ? totalEl.textContent : '$0';
  const shipTxt  = shipEl  ? shipEl.textContent  : 'GRATIS';
  const totalNum = parseInt((totalTxt||'0').replace(/\D/g,'')) || 0;

  const storePhone = (gc('phone')||'+56977462964').replace(/\D/g,'');

  // ── Si API está configurada: guardar pedido en servidor ──
  if(API_BASE){
    var btn = document.getElementById('ckConfirmBtn');
    if(btn){btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Procesando...';}
    const orderPayload = {
      items: cart.map(function(i){ return {id:i.id, name:i.name, qty:i.qty, price:i.price, img:i.img||''}; }),
      customer: {name, email, phone, rut: rut||undefined, address: addr+', '+city+', '+region},
      payment: payVal,
      coupon: _coupon ? _coupon.code : null,
      total: totalNum
    };
    fetchWithTimeout(API_BASE+'/api/order', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(orderPayload)
    }, 15000)
    .then(function(r){return r.json();})
    .then(function(d){
      if(!d.ok){
        if(btn){btn.disabled=false; btn.innerHTML='<i class="fas fa-lock"></i> Confirmar pedido';}
        _confirmOrderFallback(name,email,phone,addr,city,region,payName,shipTxt,totalTxt,storePhone,payVal==='transfer',rut);
        return;
      }
      // Si el pago es Mercado Pago y el API está activo → Checkout Pro
      if(payVal==='mp' && API_BASE){
        _launchMPCheckout(d.orderId, email, totalNum, d.waUrl, name, phone, addr, city, region, payName, shipTxt, totalTxt, storePhone);
      } else {
        var hasComp = false;
        if(payVal==='transfer') {
          var compFile = document.getElementById('ckComprobante');
          hasComp = !!(compFile && compFile.files && compFile.files[0]);
          if(hasComp) _uploadComprobante(d.orderId);
        }
        // Enriquecer mensaje WA con comprobante si fue subido
        var finalWaUrl = d.waUrl;
        if(payVal==='transfer' && hasComp){
          finalWaUrl = d.waUrl + encodeURIComponent('\n\n📎 *Comprobante de transferencia subido al pedido #' + d.orderId + '*');
        }
        _launchOrderWA(d.orderId, finalWaUrl, payVal==='transfer', hasComp);
      }
    })
    .catch(function(){
      if(btn){btn.disabled=false; btn.innerHTML='<i class="fas fa-lock"></i> Confirmar pedido';}
      _confirmOrderFallback(name,email,phone,addr,city,region,payName,shipTxt,totalTxt,storePhone,payVal==='transfer',rut);
    });
    return;
  }
  _confirmOrderFallback(name,email,phone,addr,city,region,payName,shipTxt,totalTxt,storePhone,payVal==='transfer',rut);
}

function _launchMPCheckout(orderId, email, totalNum, waUrl, name, phone, addr, city, region, payName, shipTxt, totalTxt, storePhone){
  var mpItems = cart.map(function(i){ return {title:i.name.substring(0,60), quantity:i.qty, unit_price:i.price}; });
  var btn = document.getElementById('ckConfirmBtn');
  if(btn){btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Conectando con Mercado Pago...';}
  fetchWithTimeout(API_BASE+'/api/payment/preference', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({orderId: orderId, items: mpItems, payer:{email: email}})
  }, 15000)
  .then(function(r){return r.json();})
  .then(function(d){
    if(d.ok && d.init_point){
      try {
        sessionStorage.setItem('mx_mp_pending', JSON.stringify({
          orderId:orderId, name:name, email:email, phone:phone,
          addr:addr, city:city, region:region
        }));
      } catch(e){}
      window.location.href = d.init_point;
    } else {
      // MP no disponible → completar pedido por WhatsApp igual
      if(btn){btn.disabled=false; btn.innerHTML='<i class="fas fa-wallet"></i> Pagar con Mercado Pago';}
      showToast('MP tiene un problema técnico momentáneo. Tu pedido quedó registrado — te contactamos al tiro por WhatsApp.','warning');
      _launchOrderWA(orderId, waUrl, false, false);
    }
  })
  .catch(function(){
    if(btn){btn.disabled=false; btn.innerHTML='<i class="fas fa-wallet"></i> Pagar con Mercado Pago';}
    showToast('Sin conexión con Mercado Pago. Tu pedido quedó guardado — lo coordinamos por WhatsApp sin problema.','warning');
    _launchOrderWA(orderId, waUrl, false, false);
  });
}

function previewComprobante(input){
  var file = input.files[0];
  var preview = document.getElementById('ckComprobantePreview');
  var img = document.getElementById('ckComprobanteImg');
  var nombre = document.getElementById('ckComprobanteNombre');
  var btn = document.querySelector('.ck-comp-btn');
  if(!file || !preview || !img) return;
  if(nombre) nombre.textContent = '📎 ' + file.name;
  if(btn) { btn.innerHTML = '<i class="fas fa-check-circle" style="color:var(--good)"></i> ' + file.name.substring(0,32); }
  preview.style.display='block';
  if(file.type.startsWith('image/')){
    var reader = new FileReader();
    reader.onload = function(e){ img.src = e.target.result; img.style.display='block'; };
    reader.readAsDataURL(file);
  } else {
    img.style.display='none';
  }
}

function _uploadComprobante(orderId){
  var input = document.getElementById('ckComprobante');
  if(!input || !input.files || !input.files[0]) return;
  var file = input.files[0];
  if(file.size > 6*1024*1024){ showToast('Comprobante muy grande (máx 6 MB)','error'); return; }
  var reader = new FileReader();
  reader.onload = function(e){
    var base64 = e.target.result.split(',')[1];
    var mimeType = file.type || 'image/jpeg';
    fetchWithTimeout(API_BASE+'/api/order/'+encodeURIComponent(orderId)+'/comprobante', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({base64:base64, mimeType:mimeType})
    }, 20000)
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.ok) showToast('✅ Comprobante enviado a Maxicompra','success');
    })
    .catch(function(){ /* silencioso — el pedido ya se creó */ });
  };
  reader.readAsDataURL(file);
}

function _confirmOrderFallback(name,email,phone,addr,city,region,payName,shipTxt,totalTxt,storePhone,isTransfer,rut){
  const orderNum = 'MX-' + Date.now().toString().slice(-6);
  const itemLines = cart.map(function(i){
    return '  • '+i.qty+'x '+i.name.substring(0,40)+(i.name.length>40?'...':'') + ' — ' + fp(i.price * i.qty);
  }).join('\n');
  const msg = [
    '🛒 *NUEVO PEDIDO #'+orderNum+'*',
    '━━━━━━━━━━━━━━━━━━━━',
    '',
    '👤 *Cliente:* '+name,
    '📧 Email: '+email,
    '📱 Tel: '+phone,
    (rut ? '🪪 RUT: '+rut : null),
    '',
    '📦 *Productos:*',
    itemLines,
    '',
    '💰 Subtotal: '+(document.getElementById('ck-sub')?document.getElementById('ck-sub').textContent:totalTxt),
    (_coupon ? '🏷️ Cupón '+_coupon.code+' (-'+_coupon.pct+'%): -'+(document.getElementById('ck-discount')?document.getElementById('ck-discount').textContent:'') : null),
    '🚚 Envío: '+shipTxt,
    '✅ *TOTAL: '+totalTxt+'*',
    '',
    '💳 *Pago:* '+payName,
    '📍 *Dirección:* '+addr+', '+city+', '+region,
    '━━━━━━━━━━━━━━━━━━━━',
    '⚡ Pedido enviado desde Maxicompra.cl'
  ].filter(function(l){return l!==null;}).join('\n');
  const waURL = 'https://wa.me/'+storePhone+'?text='+encodeURIComponent(msg);
  _launchOrderWA(orderNum, waURL, !!isTransfer, false);
}

/* ═══════════ WHATSAPP ═══════════ */
function openWA(e){
  e.preventDefault();
  const rawPhone = gc('phone') || '+56977462964';
  const phone = rawPhone.replace(/\D/g,'');
  const storeName = gc('name') || 'Maxicompra';
  // Si hay un pedido recién confirmado, incluir el número de orden en el mensaje
  const orderPill = document.getElementById('ckOrderNum');
  const orderNum = (orderPill && orderPill.textContent && orderPill.textContent !== '#MX-000000')
    ? orderPill.textContent.trim()
    : null;
  const msg = orderNum
    ? encodeURIComponent(`Hola ${storeName}! Quisiera consultar el estado de mi pedido ${orderNum} 📦`)
    : encodeURIComponent(`Hola ${storeName}! Tengo una consulta sobre sus productos 🛍️`);
  window.open(`https://wa.me/${phone}?text=${msg}`, '_blank');
}

/* ═══════════ QUICK VIEW ═══════════ */
let qvProd = null, qvQty = 1;
function openQV(id){
  const p = products.find(x=>x.id===id);
  if(!p) return;
  qvProd = p; qvQty = 1;
  document.getElementById('qvQnum').textContent = 1;
  // Imagen
  const imgs = p.imgs||[];
  if(imgs.length){
    document.getElementById('qvImg').src = imgs[0];
    document.getElementById('qvImg').style.display = '';
    document.getElementById('qvNoImg').style.display = 'none';
  } else {
    document.getElementById('qvImg').style.display = 'none';
    document.getElementById('qvNoImg').style.display = '';
  }
  // Badges
  const tags = [];
  if(p.hot)  tags.push(`<span class="tag tag-hot">🔥 Más Vendido</span>`);
  if(p.sale) tags.push(`<span class="tag tag-pink">Oferta</span>`);
  if(p.newp) tags.push(`<span class="tag tag-new">Nuevo</span>`);
  document.getElementById('qvTags').innerHTML = tags.join('');
  document.getElementById('qvBrand').textContent = p.brand||'';
  document.getElementById('qvTitle').textContent = p.name;
  // Stars
  const rat = Math.min(5, Math.max(0, parseFloat(p.rat)||4.5));
  document.getElementById('qvStars').textContent = '★'.repeat(Math.round(rat)) + '☆'.repeat(5-Math.round(rat));
  document.getElementById('qvRat').textContent = rat.toFixed(1);
  document.getElementById('qvRevCnt').textContent = p.rev ? `(${Number(p.rev).toLocaleString('es-CL')} reseñas)` : '';
  // Precio
  document.getElementById('qvPrice').textContent = fp(p.price);
  const origEl = document.getElementById('qvOrig');
  const offEl  = document.getElementById('qvOff');
  if(p.orig && p.orig > p.price){
    origEl.textContent = fp(p.orig); origEl.style.display = '';
    const pct = Math.round((1 - p.price/p.orig)*100);
    offEl.textContent = `-${pct}%`; offEl.style.display = 'inline-block';
  } else { origEl.style.display='none'; offEl.style.display='none'; }
  // Cuotas
  const cuEl = document.getElementById('qvCuotas');
  if(p.cuotas){ cuEl.innerHTML = `<span>${esc(p.cuotas)}</span>`; cuEl.style.display=''; }
  else cuEl.style.display='none';
  // Envío
  const shEl = document.getElementById('qvShip');
  if(p.envio){ shEl.style.display='flex'; } else shEl.style.display='none';
  // Descripción
  document.getElementById('qvDesc').textContent = p.desc||'Sin descripción disponible.';
  // Mostrar
  document.getElementById('qvOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeQV(){
  document.getElementById('qvOverlay').classList.remove('open');
  document.body.style.overflow = '';
}
function qvChgQty(d){
  qvQty = Math.max(1, qvQty + d);
  if(qvProd?.stock) qvQty = Math.min(qvQty, qvProd.stock);
  document.getElementById('qvQnum').textContent = qvQty;
}
function qvAddCart(){
  if(!qvProd) return;
  for(let i=0;i<qvQty;i++) addToCart(qvProd.id);
  closeQV();
}
function qvGoFull(){
  closeQV();
  if(qvProd) openPDP(qvProd.id);
}

/* ═════════════════════════════════════
   WISHLIST
═════════════════════════════════════ */
function togWishId(id) { if(wish.includes(id))wish=wish.filter(x=>x!==id);else{wish.push(id);showToast('Guardado en favoritos ❤️','wish');} saveW(); document.getElementById('wishCount').textContent=wish.length; renderHomeProducts(document.getElementById('searchInp').value); if(currentView==='category')renderCatProducts(currentCat); }

/* ── WISHLIST PANEL JS ── */
function openWish(){
  renderWishPanel();
  document.getElementById('wishOverlay').classList.add('open');
  document.body.style.overflow='hidden';
}
function closeWish(){
  document.getElementById('wishOverlay').classList.remove('open');
  document.body.style.overflow='';
}
function renderWishPanel(){
  var body=document.getElementById('wishBody');
  var label=document.getElementById('wishCountLabel');
  if(!wish.length){
    label.textContent='';
    body.innerHTML='<div class="wish-empty"><i class="fas fa-heart-broken"></i><p>No tienes productos guardados</p><p style="font-size:13px;margin-top:6px">Toca el ❤️ en cualquier producto para agregarlo aquí</p></div>';
    return;
  }
  label.textContent='('+wish.length+')';
  var items=wish.map(function(id){
    var p=products.find(function(x){return x.id===id;});
    if(!p) return '';
    var img=p.imgs&&p.imgs[0]?p.imgs[0]:'';
    var pid=p.id;
    return '<div class="wish-item">'+
      (img?'<img class="wish-item-img" src="'+img+'" alt="" data-pid="'+pid+'" onclick="closeWish();openPDP(this.dataset.pid)">':'<div class="wish-item-img" data-pid="'+pid+'" onclick="closeWish();openPDP(this.dataset.pid)"></div>')+
      '<div class="wish-item-info" data-pid="'+pid+'" onclick="closeWish();openPDP(this.dataset.pid)">'+
        '<div class="wish-item-name">'+p.name+'</div>'+
        '<div class="wish-item-price">'+fp(p.price)+'</div>'+
      '</div>'+
      '<div style="display:flex;flex-direction:column;gap:6px;align-items:center">'+
        '<button class="wish-item-remove" data-pid="'+pid+'" onclick="removeFromWish(this.dataset.pid)"><i class="fas fa-trash-alt"></i></button>'+
        '<button style="background:var(--grad);border:none;color:#fff;border-radius:7px;padding:6px 10px;font-size:12px;font-weight:700;cursor:pointer" data-pid="'+pid+'" onclick="addToCart(this.dataset.pid);closeWish()"><i class="fas fa-cart-plus"></i></button>'+
      '</div>'+
    '</div>';
  }).join('');
  body.innerHTML=items;
}
function removeFromWish(id){
  wish=wish.filter(function(x){return x!==id;});
  lsSet('mx_wish',wish);
  // Actualizar badges
  try{document.getElementById('wishCount').textContent=wish.length;}catch(e){}
  try{document.getElementById('mobWishBadge').textContent=wish.length;}catch(e){}
  renderWishPanel();
}


/* ═════════════════════════════════════
   SEARCH
═════════════════════════════════════ */
function fetchWithTimeout(url, opts, ms){
  ms = ms || 15000;
  var ctrl = new AbortController();
  var timer = setTimeout(function(){ ctrl.abort(); }, ms);
  return fetch(url, Object.assign({}, opts, { signal: ctrl.signal }))
    .finally(function(){ clearTimeout(timer); });
}
function liveSearch(v) { if(currentView==='home'){renderHomeProducts(v);} }
function sortProducts(v) { sortMode=v; if(currentView==='home')renderHomeProducts(document.getElementById('searchInp').value); else if(currentView==='category')renderCatProducts(currentCat); }
function renderHomeBestsellers(){
  var sec=document.getElementById('homeBestSellersSection');
  var grid=document.getElementById('homeBestSellersGrid');
  if(!sec||!grid)return;
  var hot=products.filter(function(p){return p.hot&&p.vis!==false;}).slice(0,5);
  if(!hot.length){sec.style.display='none';return;}
  sec.style.display='block';
  grid.innerHTML=hot.map(function(p){return productCardHTML(p);}).join('');
}
function showOffersFilter(){
  var hot=products.filter(function(p){return p.sale||(p.orig&&p.price&&p.orig>p.price);});
  if(!hot.length){document.getElementById('homeProdsSection').scrollIntoView({behavior:'smooth'});return;}
  currentCat='';
  document.getElementById('homeSecTitle').innerHTML='Ofertas <span class="acc">Activas</span>';
  var count=document.getElementById('homeProdCount');
  if(count)count.textContent=hot.length+' producto'+(hot.length!==1?'s':'');
  var grid=document.getElementById('homeProductsGrid');
  if(grid)grid.innerHTML=hot.map(function(p){return productCardHTML(p);}).join('');
  document.getElementById('homeProdsSection').scrollIntoView({behavior:'smooth'});
}

/* ═════════════════════════════════════
   CONFIG
═════════════════════════════════════ */
function loadConfig() {
  document.getElementById('cfg-name').value  = gc('name');
  document.getElementById('cfg-tag').value   = gc('tag');
  document.getElementById('cfg-phone').value = gc('phone');
  document.getElementById('cfg-email').value = gc('email');
  document.getElementById('cfg-desc').value  = gc('desc');
  document.getElementById('cfg-fship').value = gc('fship');
  document.getElementById('cfg-shrm').value  = gc('shrm');
  document.getElementById('cfg-shreg').value = gc('shreg');
  document.getElementById('cfg-cuotas').value   = gc('cuotas');
  document.getElementById('cfg-banner').value   = gc('banner');
  document.getElementById('cfg-promo-img').value = gc('promoImg');
  document.getElementById('cfg-addr').value      = gc('addr');
}
function saveConfig() {
  config = {name:document.getElementById('cfg-name').value.trim()||DCFG.name,tag:document.getElementById('cfg-tag').value.trim()||DCFG.tag,phone:document.getElementById('cfg-phone').value.trim()||DCFG.phone,email:document.getElementById('cfg-email').value.trim()||DCFG.email,desc:document.getElementById('cfg-desc').value.trim()||DCFG.desc,fship:document.getElementById('cfg-fship').value.trim()||DCFG.fship,shrm:document.getElementById('cfg-shrm').value.trim()||DCFG.shrm,shreg:document.getElementById('cfg-shreg').value.trim()||DCFG.shreg,cuotas:document.getElementById('cfg-cuotas').value.trim()||DCFG.cuotas,banner:document.getElementById('cfg-banner').value.trim()||DCFG.banner,promoImg:document.getElementById('cfg-promo-img').value.trim(),addr:document.getElementById('cfg-addr').value.trim()||DCFG.addr};
  saveCfg(); applyCfg(); showToast('Cambios guardados y aplicados ✓');
}
function _setEl(id, txt) { const e=document.getElementById(id); if(e) e.textContent=txt; }
function _setHtml(id, h) { const e=document.getElementById(id); if(e) e.innerHTML=h; }
function _toSlug(str) {
  return (str || '').toLowerCase()
    .replace(/[áàäâ]/g,'a').replace(/[éèëê]/g,'e').replace(/[íìïî]/g,'i')
    .replace(/[óòöô]/g,'o').replace(/[úùüû]/g,'u').replace(/ñ/g,'n')
    .replace(/[^a-z0-9\s-]/g,'').replace(/\s+/g,'-').replace(/-+/g,'-')
    .slice(0,60).replace(/^-|-$/g,'');
}
function _updateSeoMeta(title, desc, url, img) {
  document.title = title;
  var can = document.querySelector('link[rel="canonical"]');
  if (can) can.setAttribute('href', url);
  var mDesc  = document.querySelector('meta[name="description"]');
  var ogT    = document.querySelector('meta[property="og:title"]');
  var ogD    = document.querySelector('meta[property="og:description"]');
  var ogU    = document.querySelector('meta[property="og:url"]');
  var ogImg  = document.querySelector('meta[property="og:image"]');
  var ogTyp  = document.querySelector('meta[property="og:type"]');
  var twT    = document.querySelector('meta[name="twitter:title"]');
  var twD    = document.querySelector('meta[name="twitter:description"]');
  var twImg  = document.querySelector('meta[name="twitter:image"]');
  if (mDesc) mDesc.setAttribute('content', desc);
  if (ogT)   ogT.setAttribute('content', title);
  if (ogD)   ogD.setAttribute('content', desc);
  if (ogU)   ogU.setAttribute('content', url);
  if (twT)   twT.setAttribute('content', title);
  if (twD)   twD.setAttribute('content', desc);
  var _img = img || 'https://maxicompra.cl/og.png';
  if (ogImg) ogImg.setAttribute('content', _img);
  if (twImg) twImg.setAttribute('content', _img);
  if (ogTyp) ogTyp.setAttribute('content', img ? 'product' : 'website');
}

function applyCfg() {
  _setEl('s-name', gc('name'));
  _setEl('s-tag',  gc('tag'));
  _setEl('f-desc', gc('desc'));
  _setEl('f-brand', gc('name'));
  _setEl('f-copy', `© ${new Date().getFullYear()} ${gc('name')} — Todos los derechos reservados`);
  const rawPhone=(gc('phone')||'+56977462964').replace(/\D/g,'');
  const tEl=document.getElementById('t-phone');
  if(tEl){tEl.href='https://wa.me/'+rawPhone;tEl.innerHTML='<i class="fab fa-whatsapp"></i>'+gc('phone');}
  var _tag = gc('tag'); document.title = _tag ? gc('name') + ' — ' + _tag : gc('name');
  const c = gc('cuotas');
  document.getElementById('ben-cuotas').textContent = `${c} cuotas sin interés`;
  document.getElementById('promo-cuotas').textContent = `${c} cuotas sin interés`;
  const fs = gc('fship');
  document.getElementById('promo-ship').textContent = `En compras sobre ${fs} a todo Chile`;
  document.getElementById('ben-ship').textContent   = `Compras sobre ${fs}`;
  const bn = gc('banner');
  if (bn) { const pts=bn.split('|').map(s=>s.trim()).filter(Boolean); const tr=document.getElementById('annTrack'); tr.innerHTML=[...pts,...pts].map(p=>`<span>${p}</span>`).join(''); }
  const pi = gc('promoImg');
  const pw = document.getElementById('promoBannerWrap');
  const pi2 = document.getElementById('promoBannerImg');
  if (pw && pi2) { if(pi){pi2.src=pi;pw.style.display='block';}else{pw.style.display='none';pi2.src='';} }
  const addrEl = document.getElementById('info-addr');
  if (addrEl) addrEl.textContent = gc('addr');
}

/* ═════════════════════════════════════
   SCROLL REVEAL + COUNTERS
═════════════════════════════════════ */
(function(){
  function easeOut(t){return 1-Math.pow(1-t,3);}
  function animateNum(el){
    var target=parseFloat(el.dataset.count||0);
    var pfx=el.dataset.prefix||'';
    var sfx=el.dataset.suffix||'';
    var dec=parseInt(el.dataset.decimals||'0');
    var dur=1700;var t0=performance.now();
    (function tick(now){
      var p=Math.min((now-t0)/dur,1);
      var v=target*easeOut(p);
      el.textContent=pfx+(dec>0?v.toFixed(dec):Math.floor(v).toLocaleString('es-CL'))+sfx;
      if(p<1)requestAnimationFrame(tick);
    })(t0);
  }
  var io=new IntersectionObserver(function(entries){
    entries.forEach(function(e){
      if(!e.isIntersecting)return;
      e.target.classList.add('sr-v');
      e.target.querySelectorAll('[data-count]').forEach(animateNum);
      io.unobserve(e.target);
    });
  },{threshold:0.12});
  document.querySelectorAll('.sr').forEach(function(el){io.observe(el);});
  /* Parallax on hero product bubble */
  var heroImg=document.getElementById('heroProductImg');
  if(heroImg){
    window.addEventListener('scroll',function(){
      var s=window.scrollY;
      if(s<600)heroImg.style.transform='translateY('+Math.round(s*0.12)+'px)';
    },{passive:true});
  }
})();

/* ═════════════════════════════════════
   NEWSLETTER / MISC
═════════════════════════════════════ */
function subNl(){
  const v=document.getElementById('nlEmail').value.trim();
  if(!v||!v.includes('@')){showToast('Correo inválido','error');return;}
  fetch(API_BASE+'/api/newsletter',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:v})})
    .then(r=>r.json()).catch(()=>({ok:false}))
    .then(()=>{showToast('¡Suscrito con éxito! Te avisaremos de las mejores ofertas 🎉');document.getElementById('nlEmail').value='';});
}
window.addEventListener('scroll',()=>{
  document.getElementById('bTop').classList.toggle('visible',window.scrollY>400);
  document.querySelector('.site-header')?.classList.toggle('hdr-scrolled',window.scrollY>12);
},{passive:true});

/* ═════════════════════════════════════
   COOKIE CONSENT
═════════════════════════════════════ */
(function(){
  var b=document.getElementById('cookieBanner');
  if(!b) return;
  if(localStorage.getItem('cookieConsent')){b.classList.add('hidden');return;}
  setTimeout(function(){b.style.display='flex';},800);
})();
function acceptCookies(){
  localStorage.setItem('cookieConsent','all');
  var b=document.getElementById('cookieBanner');
  if(b) b.classList.add('hidden');
}
function declineCookies(){
  localStorage.setItem('cookieConsent','essential');
  var b=document.getElementById('cookieBanner');
  if(b) b.classList.add('hidden');
}

/* ═════════════════════════════════════
   TOAST
═════════════════════════════════════ */
let tTO;
function showToast(msg,type='success'){const t=document.getElementById('toast');document.getElementById('tMsg').textContent=msg;t.className='toast show'+(type==='error'?' error':type==='wish'?' wish':type==='info'?' info':'');clearTimeout(tTO);tTO=setTimeout(()=>t.classList.remove('show'),2800);}

// ─── Confirm Modal — reemplaza confirm() nativo (bloqueante) ─────────────────
// Uso: if(!await _confirmModal('mensaje','Título','Btn label', dangerBool)) return;
var _confirmModalResolve=null;
function _confirmModal(msg,title,btnLabel,danger){
  return new Promise(function(resolve){
    _confirmModalResolve=resolve;
    var el=document.getElementById('confirmModal');
    var titleEl=document.getElementById('confirmModalTitle');
    var msgEl=document.getElementById('confirmModalMsg');
    var btn=document.getElementById('confirmModalBtn');
    if(titleEl) titleEl.textContent=title||'¿Confirmar acción?';
    if(msgEl) msgEl.textContent=msg||'';
    if(btn){
      btn.textContent=btnLabel||'Confirmar';
      btn.className=danger?'btn-danger':'btn-grad';
      btn.style.cssText='padding:10px 20px;font-size:13px;cursor:pointer;';
    }
    if(el) el.classList.add('open');
  });
}
function _confirmModalOk(){
  var el=document.getElementById('confirmModal');
  if(el) el.classList.remove('open');
  if(_confirmModalResolve){_confirmModalResolve(true);_confirmModalResolve=null;}
}
function _confirmModalCancel(){
  var el=document.getElementById('confirmModal');
  if(el) el.classList.remove('open');
  if(_confirmModalResolve){_confirmModalResolve(false);_confirmModalResolve=null;}
}

/* ═════════════════════════════════════
   INIT
═════════════════════════════════════ */

/* ── MOBILE BOTTOM NAV JS ── */
function mobActive(id) {
  document.querySelectorAll('.mob-nav-item').forEach(b => b.classList.remove('active'));
  const el = document.getElementById(id);
  if(el) el.classList.add('active');
}
function updMobBadges() {
  const cc = (typeof cart!=='undefined' ? cart.reduce((s,i)=>s+(i.qty||1),0) : 0);
  const wc = (typeof wish!=='undefined' ? wish.length : 0);
  const mb = document.getElementById('mobCartBadge');
  const mw = document.getElementById('mobWishBadge');
  if(mb){ mb.textContent=cc; mb.classList.toggle('show', cc>0); }
  if(mw){ mw.textContent=wc; mw.classList.toggle('show', wc>0); }
}


/* ── MOBILE SEARCH OVERLAY JS ── */
function openMobSearch(){
  document.getElementById('mobSearchOverlay').classList.add('open');
  document.getElementById('mobSearchInp').value='';
  document.getElementById('mobSearchResults').innerHTML='<div class="mob-search-empty">🔍 Escribe para buscar productos</div>';
  setTimeout(()=>document.getElementById('mobSearchInp').focus(),80);
  document.body.style.overflow='hidden';
}
function closeMobSearch(){
  document.getElementById('mobSearchOverlay').classList.remove('open');
  document.body.style.overflow='';
}
/* ─── Desktop smart search autocomplete ─── */
function _norm(s){ return (s||'').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,''); }

/* ── FUZZY SEARCH ENGINE ── */
function _lev(a,b){
  // Levenshtein distance (optimized: single array, early exit)
  var la=a.length,lb=b.length;
  if(!la)return lb; if(!lb)return la;
  if(Math.abs(la-lb)>Math.ceil(Math.max(la,lb)*0.6))return la+lb; // early reject
  var row=Array.from({length:lb+1},function(_,i){return i;});
  for(var i=1;i<=la;i++){
    var prev=i;
    for(var j=1;j<=lb;j++){
      var val=a[i-1]===b[j-1]?row[j-1]:1+Math.min(row[j],prev,row[j-1]);
      row[j-1]=prev; prev=val;
    }
    row[lb]=prev;
  }
  return row[lb];
}
function _bigrams(s){
  var g=new Set();
  for(var i=0;i<s.length-1;i++)g.add(s.slice(i,i+2));
  return g;
}
function _bigramSim(a,b){
  var ga=_bigrams(a),gb=_bigrams(b);
  if(!ga.size||!gb.size)return 0;
  var shared=0; ga.forEach(function(g){if(gb.has(g))shared++;});
  return(2*shared)/(ga.size+gb.size);
}
function _tokSim(a,b){
  // Similarity between two individual tokens (0-1)
  if(a===b)return 1;
  if(!a||!b)return 0;
  if(b.startsWith(a)||a.startsWith(b))return 0.92;
  if(b.includes(a)||a.includes(b))return 0.86;
  var maxLen=Math.max(a.length,b.length);
  if(maxLen<3)return 0;
  var dist=_lev(a,b);
  // Tolerance: 1 error per 4 chars (min 1 for len≥3, max 3)
  var tol=Math.min(3,Math.max(1,Math.floor(maxLen/4)));
  if(dist<=tol)return Math.max(0.52,1-dist/maxLen);
  // Bigram fallback covers transpositions & longer scrambles
  return _bigramSim(a,b);
}
function _fuzzyScore(query,text){
  var nq=_norm(query),nt=_norm(text);
  if(nt.includes(nq))return 1; // exact substring = perfect
  var qToks=nq.split(/[\s\-\/]+/).filter(function(t){return t.length>=2;});
  var tToks=nt.split(/[\s\-\/]+/).filter(function(t){return t.length>=2;});
  if(!qToks.length||!tToks.length)return 0;
  var total=0;
  qToks.forEach(function(qt){
    var best=0;
    tToks.forEach(function(tt){best=Math.max(best,_tokSim(qt,tt));});
    total+=best;
  });
  return total/qToks.length;
}
var FUZZY_THR=0.60; // minimum score to show a fuzzy result
function _fuzzySearch(query,src){
  // Returns {exact:[], fuzzy:[]} product arrays sorted by relevance
  var nq=_norm(query.trim());
  if(!nq)return{exact:src,fuzzy:[]};
  var exact=[],fuzzy=[];
  src.forEach(function(p){
    var txt=_norm((p.name||'')+' '+(p.brand||'')+' '+(p.cat||''));
    if(txt.includes(nq)){
      exact.push({p:p,s:1+(1-txt.indexOf(nq)/txt.length)*0.1});
    } else if(query.trim().length>=3){
      var s=_fuzzyScore(query,p.name+' '+(p.brand||'')+' '+(p.cat||''));
      if(s>=FUZZY_THR)fuzzy.push({p:p,s:s});
    }
  });
  exact.sort(function(a,b){return b.s-a.s;});
  fuzzy.sort(function(a,b){return b.s-a.s;});
  return{exact:exact.map(function(x){return x.p;}),fuzzy:fuzzy.map(function(x){return x.p;})};
}

var _searchDebT = null;
function _escRe(s){ return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); }
function _hlText(text, q){
  if(!q) return esc(text);
  return esc(text).replace(new RegExp('('+_escRe(esc(q))+')','gi'),'<mark>$1</mark>');
}
function _handleDesktopSearch(v){
  clearTimeout(_searchDebT);
  _searchDebT = setTimeout(function(){
    if(currentView!=='home') showView('home');
    renderHomeProducts(v);
    _renderSuggest(v);
  }, 200);
}
function _commitSearch(){
  var v=(document.getElementById('searchInp')||{value:''}).value||(document.getElementById('mobSearchBarInp')||{value:''}).value;
  if(currentView!=='home') showView('home');
  renderHomeProducts(v);
  _hideSuggest();
  setTimeout(function(){
    var grid=document.getElementById('homeProductsGrid');
    if(grid){ var sec=grid.parentElement||grid; sec.scrollIntoView({behavior:'smooth',block:'start'}); }
  },80);
}
function _hideSuggest(){var b=document.getElementById('searchSuggest');if(b)b.style.display='none';}
function _renderSuggest(q){
  var box=document.getElementById('searchSuggest');
  if(!box)return;
  // Vive dentro de .search-bar (display:none en mobile) → sacarlo al body para que se vea en ambos
  if(box.parentElement!==document.body) document.body.appendChild(box);
  if(!q||q.trim().length<2){_hideSuggest();return;}
  var visible=products.filter(function(p){return p.visible!==false;});
  var res=_fuzzySearch(q,visible);
  var exactHits=res.exact.slice(0,8);
  var allHits=exactHits;
  var hasFuzzy=false;
  if(exactHits.length<5&&res.fuzzy.length){
    var need=Math.min(8-exactHits.length,res.fuzzy.length);
    allHits=exactHits.concat(res.fuzzy.slice(0,need));
    hasFuzzy=true;
  }
  if(!allHits.length){_hideSuggest();return;}
  var total=res.exact.length+res.fuzzy.length;
  var exactIds=new Set(exactHits.map(function(p){return p.id;}));
  box.innerHTML=allHits.map(function(p){
    var img=p.imgs&&p.imgs[0]?p.imgs[0]:(p.img||'');
    var imgEl=img
      ?'<img src="'+img+'" alt="" style="width:40px;height:40px;object-fit:contain;border-radius:6px;background:var(--bg-2);flex-shrink:0" loading="lazy">'
      :'<div style="width:40px;height:40px;background:var(--bg-2);border-radius:6px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:18px">📦</div>';
    var isFuzzy=!exactIds.has(p.id);
    var nameHL=_hlText(p.name,q.trim());
    var brandHL=p.brand?'<div class="ss-brand">'+_hlText(p.brand,q.trim())+'</div>':'';
    var fuzzyTag=isFuzzy?'<span style="font-size:10px;color:var(--muted);margin-left:4px">~similar</span>':'';
    return '<div class="ss-item'+(isFuzzy?' ss-item-fuzzy':'')+'" onclick="_hideSuggest();openPDP(\''+esc(p.id)+'\')" style="'+(isFuzzy?'opacity:.82':'')+'">'+imgEl+'<div style="flex:1;min-width:0"><div class="ss-name">'+nameHL+fuzzyTag+'</div>'+brandHL+'</div><div class="ss-price">'+fp(p.price)+'</div></div>';
  }).join('')+(hasFuzzy?'<div style="padding:6px 14px;font-size:11px;color:var(--muted);border-top:1px solid var(--border)">Mostrando resultados aproximados</div>':'')+'<div class="ss-see-all" onclick="_commitSearch()">Ver los '+total+' resultados →</div>';
  // En mobile #searchBarWrap está oculto (rect 0×0) → usar la fila de búsqueda mobile
  var wrap=document.getElementById('searchBarWrap');
  var wrapR=wrap?wrap.getBoundingClientRect():null;
  if(!wrapR||wrapR.width<40){
    wrap=document.getElementById('mobSearchRow');
    wrapR=wrap?wrap.getBoundingClientRect():null;
  }
  if(wrap&&wrapR&&wrapR.width>=40){
    var onMob=wrap.id==='mobSearchRow';
    var hdr=document.querySelector('.site-header');
    var topY=onMob?wrapR.bottom+2:(hdr?hdr.getBoundingClientRect().bottom+4:wrapR.bottom+6);
    var pad=onMob?12:0;
    box.style.top=topY+'px';
    box.style.left=(wrapR.left+pad)+'px';
    box.style.width=(wrapR.width-pad*2)+'px';
    box.style.maxHeight=Math.min(360,window.innerHeight-topY-16)+'px';
  }
  box.style.display='block';
}
// Global search listeners (Esc, /, outside-click)
(function(){
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape'){_hideSuggest();var si=document.getElementById('searchInp');if(si)si.blur();}
    if(e.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)){e.preventDefault();var si=document.getElementById('searchInp');if(si){si.focus();si.select();}}
  });
  document.addEventListener('mousedown',function(e){
    if(!e.target.closest('#searchBarWrap,#mobSearchRow,#searchSuggest'))_hideSuggest();
  });
})();
function mobSearchQuery(q){
  const res=document.getElementById('mobSearchResults');
  if(!q||q.trim().length<2){
    res.innerHTML='<div class="mob-search-empty">🔍 Escribe al menos 2 letras</div>';return;
  }
  const visible=products.filter(p=>p.visible!==false);
  const mobRes=_fuzzySearch(q,visible);
  var found=mobRes.exact;
  if(found.length<2&&q.trim().length>=3){
    const seen=new Set(found.map(p=>p.id));
    found=found.concat(mobRes.fuzzy.filter(p=>!seen.has(p.id)));
  }
  found=found.slice(0,14);
  if(!found.length){
    res.innerHTML='<div class="mob-search-empty">Sin resultados para "'+esc(q)+'"</div>';return;
  }
  res.innerHTML=found.map(function(p){
    var imgSrc=p.imgs&&p.imgs[0]?p.imgs[0]:(p.img||'');
    var img=imgSrc ? '<img src="'+imgSrc+'" alt="" loading="lazy" style="width:44px;height:44px;object-fit:contain;border-radius:7px;background:var(--card2);flex-shrink:0">' : '<div style="width:44px;height:44px;background:var(--card2);border-radius:7px;flex-shrink:0"></div>';
    return '<div class="mob-search-item" data-pid="'+p.id+'" onclick="closeMobSearch();openPDP(this.dataset.pid)">'+img+'<div class="mob-search-item-info"><div class="mob-search-item-name">'+esc(p.name)+'</div><div class="mob-search-item-price">'+fp(p.price)+'</div></div></div>';
  }).join('');
}

/* ─── Comparador de productos ─── */
var cmpList = [];
function cmpToggle(id) {
  var idx = cmpList.indexOf(id);
  if (idx !== -1) {
    cmpList.splice(idx, 1);
  } else {
    if (cmpList.length >= 3) { showToast('Máximo 3 productos para comparar','info'); return; }
    cmpList.push(id);
  }
  cmpRender();
}
function cmpRender() {
  var bar  = document.getElementById('cmpBar');
  var slots = document.getElementById('cmpSlots');
  var count = document.getElementById('cmpCount');
  var goBtn = document.getElementById('cmpGoBtn');
  // Update slots
  slots.innerHTML = cmpList.map(function(id) {
    var p = products.find(function(x){ return x.id===id; });
    if (!p) return '';
    var img = (p.imgs&&p.imgs[0])||p.img||'';
    var hasImg = !!img;
    return '<div class="cmp-slot'+(hasImg?' has-img':'')+'">' +
      (hasImg ? '<img src="'+img+'" alt="'+esc(p.name)+'">' : '<span style="font-size:22px">📦</span>') +
      '<button class="cmp-slot-rm" onclick="cmpToggle(\''+id+'\')" aria-label="Quitar '+esc(p.name)+' del comparador">×</button>' +
      '</div>';
  }).join('') +
  (cmpList.length < 3 ? '<div class="cmp-slot"><span style="opacity:.3;font-size:18px">+</span></div>' : '');
  // Update count + button
  count.textContent = cmpList.length;
  goBtn.disabled = cmpList.length < 2;
  // Toggle bar
  if (cmpList.length > 0) bar.classList.add('open'); else bar.classList.remove('open');
  // Update card buttons
  document.querySelectorAll('[id^="cmpbtn-"]').forEach(function(btn) {
    var pid = btn.id.replace('cmpbtn-','');
    btn.classList.toggle('on', cmpList.includes(pid));
    btn.setAttribute('aria-label', cmpList.includes(pid) ? 'Quitar de comparar' : 'Agregar a comparar');
  });
}
function cmpClear() { cmpList=[]; cmpRender(); }
function cmpOpen() {
  if (cmpList.length < 2) return;
  var prods = cmpList.map(function(id){ return products.find(function(x){ return x.id===id; }); }).filter(Boolean);
  var rows = [
    {label:'Imagen', fn:function(p){ var img=(p.imgs&&p.imgs[0])||p.img||''; return '<div class="cmp-prod-head">'+(img?'<img src="'+img+'" alt="'+esc(p.name)+'">':'<div style="width:80px;height:80px;background:var(--bg-2);border-radius:var(--radius);margin:0 auto 8px;display:flex;align-items:center;justify-content:center;font-size:32px">📦</div>')+'<div class="cmp-prod-name">'+esc(p.name)+'</div><div class="cmp-prod-price">'+fp(p.price)+'</div></div>'; }},
    {label:'Marca', fn:function(p){ return esc(p.brand||'—'); }},
    {label:'Categoría', fn:function(p){ return esc(p.cat||'—'); }},
    {label:'Calificación', fn:function(p){ return p.rat&&p.rat>0 ? '<span style="color:#F59E0B">★</span> '+parseFloat(p.rat).toFixed(1)+(p.rev?' ('+p.rev+' reseñas)':'') : '—'; }},
    {label:'Precio', fn:function(p){ return '<strong style="font-size:17px;font-weight:700;letter-spacing:-0.02em">'+fp(p.price)+'</strong>'+(p.orig?'<br><span style="font-size:11px;color:var(--mute);text-decoration:line-through">'+fp(p.orig)+'</span>':''); }},
    {label:'Envío', fn:function(p){ return p.envio ? '<span style="color:var(--accent)">✓ Gratis</span>' : 'Ver al comprar'; }},
    {label:'Acción', fn:function(p){ return '<button class="btn-grad" style="padding:8px 16px;font-size:12px" onclick="cmpClose();addToCart(\''+p.id+'\')"><i class="fas fa-shopping-cart"></i> Al carro</button>'; }}
  ];
  var html = '<table class="cmp-table"><thead><tr><th></th>'+prods.map(function(p){ return '<th>'+esc(p.name.substring(0,30))+'</th>'; }).join('')+'</tr></thead><tbody>';
  rows.forEach(function(r) {
    html += '<tr><td>'+r.label+'</td>'+prods.map(function(p){ return '<td>'+r.fn(p)+'</td>'; }).join('')+'</tr>';
  });
  html += '</tbody></table>';
  document.getElementById('cmpTableWrap').innerHTML = html;
  document.getElementById('cmpModal').classList.add('open');
  document.body.style.overflow = 'hidden';
}
function cmpClose() {
  document.getElementById('cmpModal').classList.remove('open');
  document.body.style.overflow = '';
}

/* ─── Fly-to-cart animation ─── */
function _flyToCart(btn) {
  var badge = document.getElementById('cartBdg');
  if (!badge || !btn) return;
  var from = btn.getBoundingClientRect();
  var to   = badge.getBoundingClientRect();
  var dot  = document.createElement('div');
  dot.className = 'fly-dot';
  dot.style.cssText = 'left:' + (from.left + from.width/2 - 7) + 'px;top:' + (from.top + from.height/2 - 7) + 'px;';
  document.body.appendChild(dot);
  var dx = (to.left + to.width/2) - (from.left + from.width/2);
  var dy = (to.top  + to.height/2) - (from.top  + from.height/2);
  var anim = dot.animate([
    {transform:'translate(0,0) scale(1)', opacity:1},
    {transform:'translate('+dx+'px,'+dy+'px) scale(0.2)', opacity:0}
  ], {duration:550, easing:'cubic-bezier(.4,0,.2,1)', fill:'forwards'});
  anim.onfinish = function(){ dot.remove(); };
}

/* ─── Skeleton loading for product grids ─── */
function _skelCards(n) {
  return Array.from({length:n}).map(function(){
    return '<div class="skel-card"><div class="skel skel-img"></div><div class="skel-body"><div class="skel skel-line w30"></div><div class="skel skel-line w80"></div><div class="skel skel-price"></div><div class="skel skel-line w60"></div></div><div class="skel skel-btn"></div></div>';
  }).join('');
}


/* Inicializar con aislamiento de errores — cada función independiente */
(function initApp() {
  function safe(fn, name) {
    try { fn(); } catch(e) { console.warn('[Maxicompra] ' + name + ':', e.message); }
  }
  safe(applyCfg,          'applyCfg');
  safe(renderHeroSlider,      'renderHeroSlider');
  safe(renderHomeBestsellers, 'renderHomeBestsellers');
  safe(renderHomeCats,        'renderHomeCats');
  // Update hero price tag with real minimum price from products
  safe(function(){
    if(products && products.length){
      var minP = products.reduce(function(m,p){ return p.price < m ? p.price : m; }, Infinity);
      var el = document.getElementById('heroPriceMin');
      if(el && minP !== Infinity) el.textContent = fp(minP);
    }
    // Set hero product image from first featured/offer product
    var heroImg = document.getElementById('heroProductImg');
    if(heroImg && products && products.length){
      var featured = products.find(function(p){ return p.hot || p.offer; }) || products[0];
      if(featured && (featured.imgs&&featured.imgs[0]||featured.img)){
        var src = (featured.imgs&&featured.imgs[0]) || featured.img;
        heroImg.innerHTML = '<img src="'+src+'" alt="'+featured.name+'" style="width:100%;height:100%;object-fit:contain;mix-blend-mode:multiply;" loading="eager" fetchpriority="high" decoding="async">';
      }
    }
  }, 'heroEdUpdate');
  safe(function(){ renderHomeProducts(''); }, 'renderHomeProducts');
  safe(renderRecent,      'renderRecent');
  safe(renderNavBar,      'renderNavBar');
  // Mostrar botón nativo de share solo en plataformas que lo soporten (mobile principalmente)
  safe(function(){
    var nativeBtn = document.getElementById('pdpNativeShare');
    if (nativeBtn && navigator.share) nativeBtn.style.display = 'flex';
  }, 'nativeShareBtn');
  safe(renderFooterCats,  'renderFooterCats');
  safe(updCartBadge,      'updCartBadge');
  safe(renderCart,        'renderCart');
  try { document.getElementById('wishCount').textContent = wish.length; } catch(e) {}
})();

/* ── HISTORY / BACK BUTTON FIX ── */
// ── Popstate: handles real URL navigation (browser back/forward + direct URL access) ──
if(window.location.hash !== '#__admin') history.replaceState({view:'home'}, '', window.location.pathname || '/');
window.addEventListener('popstate', function(e){
  var state = e.state || {};
  var path  = window.location.pathname;
  // Si el panel admin está abierto, el back button lo cierra (no navega a la tienda)
  var adminPnl = document.getElementById('adminPanel');
  if(adminPnl && adminPnl.classList.contains('open')){
    closeAdmin();
    return;
  }
  // Close overlays first
  var ckOv = document.getElementById('ckOverlay');
  if(ckOv && ckOv.classList.contains('open')){ closeCheckout(); return; }
  var cartOv = document.getElementById('cartOv');
  if(cartOv && cartOv.classList.contains('open')){ togCart(); return; }
  var mobSrch = document.getElementById('mobSearchOverlay');
  if(mobSrch && mobSrch.classList.contains('open')){ closeMobSearch(); return; }
  var qvOv = document.getElementById('qvOverlay');
  if(qvOv && qvOv.classList.contains('open')){ if(typeof closeQV==='function') closeQV(); return; }
  // Navigate based on state or path
  if(state.view === 'product' && state.id){
    var pp = products.find(function(x){ return x.id === state.id; });
    if(pp){ openPDP(pp.id); return; }
  }
  if(state.view === 'category' && state.cat){ openCatView(state.cat); return; }
  if(path.startsWith('/p/')){
    var _s = path.slice(3);
    var pp = products.find(function(x){ return x.slug === _s; });
    if(pp){ openPDP(pp.id); return; }
  }
  if(path.startsWith('/c/')){ openCatView(path.slice(3)); return; }
  goHome();
});

function show404(msg) {
  var el = document.getElementById('notFoundDesc');
  if (el) el.textContent = msg || 'El producto o categoría que buscas no existe o fue eliminado.';
  var _bc = document.getElementById('seo-breadcrumb');
  if (_bc) _bc.remove();
  var _cs = document.getElementById('seo-cat-schema');
  if (_cs) _cs.remove();
  showView('404');
  var _sn = gc('name') || 'Maxicompra';
  history.replaceState({view:'404'}, 'Página no encontrada | ' + _sn, window.location.pathname);
  _updateSeoMeta('Página no encontrada | ' + _sn, 'Lo sentimos, esta página no existe. Visita Maxicompra y encuentra miles de productos al mejor precio.', 'https://maxicompra.cl' + window.location.pathname);
}

// ── Handle direct URL access (e.g. Google lands on /p/iphone-15-pro-xxxx) ──
function _handleInitialUrl(){
  var path = window.location.pathname;
  if(path === '/' || path === '') return;
  if(path.startsWith('/p/')){
    var _slug = path.slice(3);
    var found = products.find(function(x){ return x.slug === _slug; });
    if(found){ openPDP(found.id); return; }
    // Products may not be merged yet — poll briefly
    var _tries = 0;
    var _poll = setInterval(function(){
      _tries++;
      var p2 = products.find(function(x){ return x.slug === _slug; });
      if(p2){ clearInterval(_poll); openPDP(p2.id); return; }
      if(_tries >= 20){ clearInterval(_poll); show404('No encontramos el producto que buscas. Puede haber sido eliminado o la URL cambió.'); }
    }, 150);
    return;
  }
  if(path.startsWith('/c/')){
    var catId = path.slice(3);
    var validCat = cats.find(function(c){ return c.id === catId; });
    if(validCat){ openCatView(catId); return; }
    show404('La categoría "' + catId + '" no existe en nuestra tienda.');
    return;
  }
  show404();
}
document.addEventListener('DOMContentLoaded', function(){ setTimeout(_handleInitialUrl, 0); });


/* ── Image lazy-load opacity ── */
document.addEventListener('load', function(e){
  if(e.target.tagName==='IMG' && e.target.closest('.pc-img-wrap')){
    e.target.classList.add('loaded');
  }
}, true);


/* ── MEJORAS PROFESIONALES JS ── */
(function(){

  // ── 1. Stock warning — desactivado por configuración del cliente ──
  window.showPdpStock = function(p){ /* desactivado */ };

  // ── 2. Sticky bar en PDP al hacer scroll ──
  var _stickyPdpActive = false;
  window.initStickyPdp = function(p){
    if(!p) return;
    _stickyPdpActive = true;
    var bar = document.getElementById('pdpStickyBar');
    var nameEl = document.getElementById('pdpStickyName');
    var priceEl = document.getElementById('pdpStickyPrice');
    if(!bar||!nameEl||!priceEl) return;
    nameEl.textContent = p.name;
    var seed2 = p.id?p.id.split('').reduce(function(a,c){return a+c.charCodeAt(0);},0):0;
    var ratBase = p.rat&&p.rat>0?Math.min(p.rat,4.9):4.5;
    var ratVar = ((seed2%9)-4)*0.1;
    var ratVal = Math.min(4.9,Math.max(3.7,ratBase+ratVar));
    priceEl.textContent = typeof fp==='function' ? fp(p.price) : '$'+p.price;
    function onScroll(){
      if(!_stickyPdpActive) return;
      var actionsRow = document.querySelector('#view-product .pdp-actions-row');
      if(!actionsRow){bar.classList.remove('show');return;}
      var rect = actionsRow.getBoundingClientRect();
      bar.classList.toggle('show', rect.bottom < 0);
    }
    window.removeEventListener('scroll', window._stickyPdpScroll);
    window._stickyPdpScroll = onScroll;
    window.addEventListener('scroll', onScroll, {passive:true});
    bar.classList.remove('show');
  };
  window.hideStickyPdp = function(){
    _stickyPdpActive = false;
    var bar = document.getElementById('pdpStickyBar');
    if(bar) bar.classList.remove('show');
  };

  window.getPcStockWarn = function(){ return ''; };

})();

/* ── WA SCROLL MINI ── */
(function(){
  var lastSY=0, waTimer=null;
  window.addEventListener('scroll',function(){
    var sy=window.scrollY;
    var wa=document.getElementById('waWrap');
    if(!wa) return;
    if(Math.abs(sy-lastSY)>30){
      wa.classList.add('wa-mini');
      clearTimeout(waTimer);
      waTimer=setTimeout(function(){wa.classList.remove('wa-mini');},1800);
    }
    lastSY=sy;
  },{passive:true});
})();


/* ── LEGAL MODAL JS ── */
function openLegal(tab){
  document.getElementById('legalOverlay').classList.add('open');
  document.body.style.overflow='hidden';
  if(tab) legalTab(tab);
}
function closeLegal(){
  document.getElementById('legalOverlay').classList.remove('open');
  document.body.style.overflow='';
}
function legalTab(name){
  document.querySelectorAll('.legal-tab').forEach(function(t,i){t.classList.toggle('active',['terms','privacy'][i]===name);});
  document.querySelectorAll('.legal-panel').forEach(function(p){p.classList.remove('active');});
  document.getElementById('lp-'+name).classList.add('active');
}


/* ── COUNTDOWN TIMER MERCADO PAGO ── */
(function(){
  function updateTimer(){
    var el=document.getElementById('mpTimer');
    if(!el) return;
    var now=new Date();
    var midnight=new Date(now);
    midnight.setHours(23,59,59,999);
    var diff=midnight-now;
    var h=Math.floor(diff/3600000);
    var m=Math.floor((diff%3600000)/60000);
    var s=Math.floor((diff%60000)/1000);
    el.textContent='Oferta termina en: '+String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
  }
  updateTimer();
  window._mpTimerInterval=setInterval(updateTimer,1000);
})();


/* ── PRICE FILTER JS ── */
var _pfMin=0, _pfMax=0, _pfActive=false;
function applyPriceFilter(){
  var mn=parseInt(document.getElementById('pfMin').value)||0;
  var mx=parseInt(document.getElementById('pfMax').value)||0;
  if(mn<=0&&mx<=0){clearPriceFilter();return;}
  _pfMin=mn; _pfMax=mx; _pfActive=true;
  var tag=document.getElementById('pfTag');
  var clear=document.getElementById('pfClear');
  tag.style.display=''; clear.style.display='';
  var txt=mn>0&&mx>0?fp(mn)+' – '+fp(mx):mn>0?'Desde '+fp(mn):'Hasta '+fp(mx);
  tag.textContent=txt;
  renderHomeProducts();
}
function clearPriceFilter(){
  _pfMin=0;_pfMax=0;_pfActive=false;
  document.getElementById('pfMin').value='';
  document.getElementById('pfMax').value='';
  document.getElementById('pfTag').style.display='none';
  document.getElementById('pfClear').style.display='none';
  renderHomeProducts();
}


/* ── VISTOS RECIENTEMENTE JS ── */
function trackRecent(id){
  var rec=JSON.parse(localStorage.getItem('mx_recent')||'[]');
  rec=rec.filter(function(x){return x!==id;});
  rec.unshift(id);
  if(rec.length>8) rec=rec.slice(0,8);
  localStorage.setItem('mx_recent',JSON.stringify(rec));
  renderRecent();
}
function clearRecent(){
  localStorage.removeItem('mx_recent');
  document.getElementById('recentSection').style.display='none';
}
function renderRecent(){
  var rec=JSON.parse(localStorage.getItem('mx_recent')||'[]');
  var sec=document.getElementById('recentSection');
  var grid=document.getElementById('recentGrid');
  if(!sec||!grid) return;
  var items=rec.map(function(id){
    var p=(typeof products!=='undefined'?products:[]).find(function(x){return x.id===id;});
    if(!p) return '';
    var img=p.imgs&&p.imgs[0]?p.imgs[0]:'';
    var pid=p.id;
    var imgHtml=img?'<img class="recent-card-img" src="'+img+'" alt="" loading="lazy">':'<div class="recent-card-img" style="display:flex;align-items:center;justify-content:center;font-size:28px">📦</div>';
    return '<div class="recent-card" data-pid="'+pid+'" onclick="openPDP(this.dataset.pid)">'+imgHtml+'<div class="recent-card-info"><div class="recent-card-name">'+esc(p.name)+'</div><div class="recent-card-price">'+fp(p.price)+'</div></div></div>';
  }).filter(Boolean);
  if(!items.length){sec.style.display='none';return;}
  grid.innerHTML=items.join('');
  sec.style.display='';
}

/* ═══ ADMIN: carga bajo demanda (assets/js/admin.js) ═══ */
var _admBundle = null;
function loadAdminBundle(){
  if(_admBundle) return _admBundle;
  _admBundle = new Promise(function(res, rej){
    var s = document.createElement('script');
    s.src = 'assets/js/admin.js?v=9adf9d59';
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

(function(){function _chkHash(){if(location.hash==='#__admin'){history.replaceState(null,'',location.pathname+location.search);openAdmin();}}window.addEventListener('hashchange',_chkHash);if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',_chkHash);}else{_chkHash();}})();

/* ═══════════ FAQ MODAL ═══════════ */
function openFAQ(section){
  document.getElementById('faqOverlay').classList.add('open');
  document.body.style.overflow='hidden';
  if(section) faqSection(section);
}
function closeFAQ(){
  document.getElementById('faqOverlay').classList.remove('open');
  document.body.style.overflow='';
}
function faqSection(name){
  document.querySelectorAll('.faq-tab').forEach(function(t){t.classList.remove('active');});
  document.querySelectorAll('.faq-section').forEach(function(s){s.classList.remove('active');});
  var tab = document.querySelector('.faq-tab[onclick*="\''+name+'\'"]');
  if(tab) tab.classList.add('active');
  var sec = document.getElementById('faq-'+name);
  if(sec) sec.classList.add('active');
}
function togFAQ(el){
  el.classList.toggle('open');
}

/* ═══════════ API CONFIG ═══════════ */
// Actualizar con URL real del worker después de: wrangler deploy
var API_BASE = 'https://maxicompra-api.elflaco0800.workers.dev';

/* ═══════════ KV PRODUCTS MERGE ═══════════ */
(function(){
  fetch(API_BASE + '/api/products')
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(!d.ok || !d.products || !d.products.length) return;
      var kvById = {};
      d.products.forEach(function(p){ kvById[p.id] = p; });
      var existingIds = new Set(products.map(function(p){ return p.id; }));
      // Merge KV into local — preservar imgs locales (pueden ser base64 recién subidas)
      products = products.map(function(p){
        var kv = kvById[p.id];
        if (!kv) return p;
        var localImgs = p.imgs && p.imgs.length ? p.imgs : null;
        var merged = Object.assign({}, kv);
        if (localImgs) merged.imgs = localImgs; // no pisar imágenes locales
        return merged;
      });
      // Agregar productos nuevos del KV que no están en el caché local
      d.products.forEach(function(p){
        if(!existingIds.has(p.id)) products.push(p);
      });
      saveP();
      // Re-render visible view
      try {
        var sv = document.getElementById('searchInp');
        var q = sv ? sv.value : '';
        if(currentView === 'home') renderHomeProducts(q);
        else if(currentView === 'category') renderCatProducts(currentCat);
      } catch(e){}
    })
    .catch(function(){});
})();

/* ═══════════ SPLASH SCREEN ═══════════ */
(function(){
  var bar=document.getElementById('splashBar');
  var splash=document.getElementById('splashScreen');
  if(!splash) return;
  var pct=10;
  var iv=setInterval(function(){pct=Math.min(pct+Math.random()*18+5,90);if(bar)bar.style.width=pct+'%';},200);
  window.addEventListener('load',function(){
    clearInterval(iv);
    if(bar) bar.style.width='100%';
    setTimeout(function(){
      splash.style.opacity='0';
      splash.style.visibility='hidden';
      setTimeout(function(){splash.style.display='none';},650);
    },300);
  });
  // Fallback por si window.load tarda demasiado
  setTimeout(function(){
    clearInterval(iv);
    if(splash&&splash.style.display!=='none'){
      splash.style.opacity='0'; splash.style.visibility='hidden';
      setTimeout(function(){splash.style.display='none';},650);
    }
  },4000);
})();

/* ═══════════ MERCADO PAGO — RETORNO DE PAGO ═══════════ */
(function(){
  var params = new URLSearchParams(window.location.search);
  var payment = params.get('payment');
  var orderId = params.get('order');
  if(!payment || !orderId) return;
  // Limpiar URL sin recargar
  var cleanUrl = window.location.pathname;
  history.replaceState(null,'',cleanUrl);
  // Esperar a que el DOM esté listo
  window.addEventListener('load', function(){
    if(payment==='success' || payment==='pending'){
      // Vaciar carrito
      cart=[]; saveC(); updCartBadge(); renderCart();
      try { sessionStorage.removeItem('mx_mp_pending'); } catch(e){}
      document.getElementById('ckOrderNum').textContent = '#'+orderId;
      document.getElementById('ckForm').style.display='none';
      document.getElementById('ckSummary').style.display='none';
      document.getElementById('ckSuccess').style.display='block';
      document.getElementById('ckOverlay').classList.add('open');
      var cdEl=document.getElementById('ck-wa-countdown');
      if(!cdEl){
        cdEl=document.createElement('div');
        cdEl.id='ck-wa-countdown';
        cdEl.style.cssText='margin-top:14px;font-size:13px;color:var(--muted);display:flex;align-items:center;justify-content:center;gap:6px;';
        document.getElementById('ckSuccess').appendChild(cdEl);
      }
      // Mensaje inicial y luego polling para confirmar estado real
      cdEl.innerHTML='<i class="fas fa-spinner fa-spin" style="color:var(--pink);font-size:16px"></i> <span>Verificando pago con Mercado Pago…</span>';
      // Polling del estado real del pedido (hasta 30 seg, cada 4 seg)
      var _mpPolls=0;
      var _mpPoller=setInterval(function(){
        _mpPolls++;
        fetch(API_BASE+'/api/order/'+encodeURIComponent(orderId))
          .then(function(r){return r.json();})
          .then(function(d){
            var st = d.order && d.order.status;
            if(st==='paid'||st==='shipped'||st==='delivered'){
              clearInterval(_mpPoller);
              cdEl.innerHTML='<i class="fas fa-check-circle" style="color:var(--green);font-size:16px"></i> <strong style="color:var(--green)">¡Pago confirmado con Mercado Pago!</strong>';
              showToast('¡Pago exitoso! Tu pedido está confirmado.','ok');
            } else if(st==='payment_failed'||st==='cancelled'){
              clearInterval(_mpPoller);
              cdEl.innerHTML='<i class="fas fa-exclamation-circle" style="color:var(--red);font-size:16px"></i> <span style="color:var(--red)">Pago no procesado. Contacta a soporte.</span>';
            } else if(_mpPolls>=8){
              clearInterval(_mpPoller);
              cdEl.innerHTML='<i class="fas fa-clock" style="color:var(--yellow);font-size:16px"></i> <span style="color:var(--yellow)">Tu pago está siendo procesado. Te notificaremos por email.</span>';
            }
          }).catch(function(){if(_mpPolls>=8) clearInterval(_mpPoller);});
      }, 4000);

    } else if(payment==='failure' || payment==='cancel'){
      // Si orderId no existe (URL manipulada), advertir y no abrir checkout
      if(!orderId){
        showToast && showToast('URL inválida. No se pudo verificar el estado del pago.','warn');
        return;
      }
      // Extraer lógica de reapertura en función local para no duplicarla
      function _abrirCheckoutPorFalla(){
        try {
          var saved = JSON.parse(sessionStorage.getItem('mx_mp_pending')||'null');
          if(saved){
            var f = function(id,v){ var el=document.getElementById(id); if(el&&v) el.value=v; };
            f('ck-fname', saved.name); f('ck-email', saved.email);
            f('ck-phone', saved.phone); f('ck-addr',  saved.addr);
            f('ck-city',  saved.city);
            var reg=document.getElementById('ck-region');
            if(reg && saved.region) reg.value=saved.region;
          }
        } catch(e){}
        setTimeout(function(){
          var existing = document.getElementById('mp-retry-banner');
          if(!existing){
            var banner = document.createElement('div');
            banner.id = 'mp-retry-banner';
            banner.style.cssText='background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);border-radius:10px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#f87171;display:flex;align-items:center;gap:10px;';
            banner.innerHTML='<i class="fas fa-exclamation-circle" style="font-size:16px;flex-shrink:0"></i><span><strong>Pago cancelado o rechazado.</strong> Puedes reintentar con Mercado Pago o elegir otro método de pago.</span>';
            var form = document.getElementById('ckForm');
            if(form) form.insertBefore(banner, form.firstChild);
          }
          if(cart && cart.length > 0){
            document.getElementById('ckForm').style.display='';
            document.getElementById('ckSummary').style.display='';
            document.getElementById('ckSuccess').style.display='none';
            document.getElementById('ckOverlay').classList.add('open');
          } else {
            showToast('Pago cancelado. Agrega productos al carrito para reintentar.','error');
          }
        }, 400);
      }
      // Verificar estado real de la orden antes de reabrir checkout
      // MP a veces redirige a failure aunque el cobro fue exitoso (Khipu, transferencias, race conditions)
      fetch(API_BASE + '/api/order/' + encodeURIComponent(orderId))
        .then(function(r){ return r.ok ? r.json() : Promise.reject(r.status); })
        .then(function(d){
          var st = d.order && d.order.status;
          var yaPagado = st==='paid'||st==='payment_pending'||st==='shipped'||st==='delivered';
          if(yaPagado){
            // Cobrado aunque MP dijo failure → tratar como éxito
            cart=[]; saveC(); updCartBadge(); renderCart();
            try{ sessionStorage.removeItem('mx_mp_pending'); }catch(e){}
            var el=document.getElementById('ckOrderNum');
            if(el) el.textContent='#'+orderId;
            ['ckForm','ckSummary'].forEach(function(id){
              var e=document.getElementById(id); if(e) e.style.display='none';
            });
            var sc=document.getElementById('ckSuccess');
            if(sc) sc.style.display='block';
            var ov=document.getElementById('ckOverlay');
            if(ov) ov.classList.add('open');
            showToast && showToast('Tu pago fue procesado. ¡Gracias!','ok');
          } else {
            // Genuinamente fallido → ejecutar reapertura original
            _abrirCheckoutPorFalla();
          }
        })
        .catch(function(){
          showToast && showToast('Verifica tu tarjeta antes de reintentar. Es posible que el pago ya haya sido procesado.','warn');
          _abrirCheckoutPorFalla();
        });

      // pending se trata igual que success: carrito vacío + polling IPN
      // auto_return:'all' solo redirige aquí cuando el movimiento de dinero ya inició
    }
  });
})();

/* ═══════════ CART ABANDONMENT TOAST ═══════════ */
(function(){
  var abTimer=null, abShown=false;
  function resetAbTimer(){
    clearTimeout(abTimer);
    if(abShown||!cart||cart.length===0) return;
    abTimer=setTimeout(function(){
      if(cart&&cart.length>0&&!abShown){
        abShown=true;
        showToast('🛒 Tu carro te espera — ¡no olvides completar tu compra!','info');
      }
    },90000); // 90 segundos de inactividad
  }
  document.addEventListener('mousemove',resetAbTimer,{passive:true});
  document.addEventListener('keypress',resetAbTimer,{passive:true});
  document.addEventListener('touchstart',resetAbTimer,{passive:true});
  document.addEventListener('scroll',resetAbTimer,{passive:true});
  // Re-arm when cart changes
  window._cartAbanInterval=setInterval(function(){
    if(cart&&cart.length>0&&!abShown) resetAbTimer();
    if(!cart||cart.length===0){abShown=false;clearTimeout(abTimer);}
  },5000);
})();
