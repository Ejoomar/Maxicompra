/* ═════════════════════════════════════
   BANNER EDITOR
═════════════════════════════════════ */
function loadBannerEditor() {
  const list = document.getElementById('bannerEditorList');
  list.innerHTML = banners.map((s, i) => `
    <div class="banner-slide-editor">
      <div class="slide-num"><i class="fas fa-image"></i>Slide ${i+1}</div>
      <div class="form-grid">
        <div class="form-group span2">
          <label class="form-label">Imagen de fondo <span style="color:var(--muted);font-weight:400">(se muestra como fondo del banner)</span></label>
          <div class="img-uploader" ondragover="event.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')" ondrop="dropBannerImg(event,${i})">
            <input type="file" accept="image/*" onchange="setBannerImg(this,${i})">
            <i class="fas fa-panorama"></i>
            <p><span>Haz clic o arrastra</span> una imagen de fondo aquí</p>
            <p style="font-size:11px;margin-top:4px">Recomendado: 1400×450px · JPG, PNG, WEBP · Máx 5MB</p>
          </div>
          <div id="banner-prev-${i}" style="margin-top:8px">
            ${s.bg ? `<div style="position:relative;width:100%;height:90px;border-radius:8px;overflow:hidden;border:1px solid var(--border)"><div style="position:absolute;inset:0;background-image:url(${s.bg});background-size:cover;background-position:center;opacity:.6"></div><button style="position:absolute;top:6px;right:6px;width:24px;height:24px;background:var(--red);border:none;border-radius:50%;color:#fff;font-size:11px;cursor:pointer" onclick="removeBannerImg(${i})"><i class="fas fa-times"></i></button><span style="position:absolute;bottom:8px;left:10px;font-size:11px;color:#fff;font-weight:600">Imagen actual</span></div>` : `<span style="font-size:12px;color:var(--muted)">Sin imagen · Se mostrará el fondo por defecto</span>`}
          </div>
        </div>
        <div class="form-group"><label class="form-label">Badge / Etiqueta</label><input class="form-input" placeholder="Ej: 🔥 Más Vendido" value="${esc(s.badge||'')}" oninput="banners[${i}].badge=this.value"></div>
        <div class="form-group"><label class="form-label">Texto del precio / subtítulo destacado</label><input class="form-input" placeholder="Ej: $29.780 ó Ver productos ↓" value="${esc(s.price||'')}" oninput="banners[${i}].price=this.value"></div>
        <div class="form-group span2"><label class="form-label">Título principal</label><input class="form-input" placeholder="Título del slide" value="${esc(s.title||'')}" oninput="banners[${i}].title=this.value"></div>
        <div class="form-group span2"><label class="form-label">Subtítulo / descripción</label><input class="form-input" placeholder="Descripción corta" value="${esc(s.sub||'')}" oninput="banners[${i}].sub=this.value"></div>
        <div class="form-group"><label class="form-label">Texto extra (cuotas, envío...)</label><input class="form-input" placeholder="Ej: 6 cuotas sin interés · Envío gratis" value="${esc(s.detail||'')}" oninput="banners[${i}].detail=this.value"></div>
        <div class="form-group"><label class="form-label">Texto del botón</label><input class="form-input" placeholder="Ver productos" value="${esc(s.btnText||'')}" oninput="banners[${i}].btnText=this.value"></div>
      </div>
    </div>`).join('');
}

function setBannerImg(input, i) {
  const file = input.files[0]; if(!file) return;
  if(file.size>10*1024*1024){showToast('La imagen debe pesar menos de 10MB','error');return;}
  showToast('Comprimiendo imagen…');
  _compressImg(file, 1400, 0.78, data => {
    if(!data){showToast('Error al procesar la imagen','error');return;}
    banners[i].bg = data;
    const prev = document.getElementById(`banner-prev-${i}`);
    if(prev) prev.innerHTML =
      `<div style="position:relative;width:100%;height:90px;border-radius:8px;overflow:hidden;border:1px solid var(--border)"><div style="position:absolute;inset:0;background-image:url(${data});background-size:cover;background-position:center;opacity:.6"></div><button style="position:absolute;top:6px;right:6px;width:24px;height:24px;background:var(--red);border:none;border-radius:50%;color:#fff;font-size:11px;cursor:pointer" onclick="removeBannerImg(${i})"><i class="fas fa-times"></i></button><span style="position:absolute;bottom:8px;left:10px;font-size:11px;color:#fff;font-weight:600">Imagen cargada ✓</span></div>`;
  });
}
function dropBannerImg(e, i) {
  e.preventDefault(); e.currentTarget.classList.remove('drag');
  const file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) { const fakeInput={files:[file]}; setBannerImg({files:[file]},i); }
}
function removeBannerImg(i) { banners[i].bg=''; loadBannerEditor(); }
function saveBanners() { saveBan(); renderHeroSlider(); showToast('Banners actualizados — el slider ya refleja los cambios ✓'); }

/* ═════════════════════════════════════
   CATEGORY EDITOR
═════════════════════════════════════ */
function loadCatEditor() {
  const grid = document.getElementById('catEditorGrid');
  grid.innerHTML = cats.map((c, i) => {
    const cnt = products.filter(p=>p.visible!==false&&p.cat===c.name).length;
    return `<div class="cat-edit-card">
      <div class="cat-head">
        <span class="cat-emoji-big" id="cat-emo-${i}">${c.emoji}</span>
        <div><div class="cat-name-edit">${c.name}</div><div style="font-size:12px;color:var(--muted)">${cnt} producto${cnt!==1?'s':''}</div></div>
      </div>
      <div class="form-group" style="margin-bottom:10px">
        <label class="form-label" style="font-size:12px">Ícono / Emoji</label>
        <input class="form-input" style="font-size:18px" value="${c.emoji}" oninput="cats[${i}].emoji=this.value;document.getElementById('cat-emo-${i}').textContent=this.value">
      </div>
      <div class="form-group" style="margin-bottom:10px">
        <label class="form-label" style="font-size:12px">Imagen de portada de categoría</label>
        <div class="img-uploader" style="padding:14px" ondragover="event.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')" ondrop="dropCatImg(event,${i})">
          <input type="file" accept="image/*" onchange="setCatImg(this,${i})">
          <p style="font-size:12px"><span>Haz clic o arrastra</span> imagen de portada</p>
        </div>
        ${c.bg ? `<div style="margin-top:6px;display:flex;align-items:center;gap:8px"><img src="${c.bg}" style="width:60px;height:40px;object-fit:cover;border-radius:6px;border:1px solid var(--border)"><span style="font-size:12px;color:var(--green)">✓ Imagen cargada</span><button style="background:var(--red);border:none;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;cursor:pointer" onclick="cats[${i}].bg='';loadCatEditor()">Quitar</button></div>` : `<div style="margin-top:4px;font-size:11px;color:var(--muted)">Sin imagen de portada</div>`}
      </div>
    </div>`;
  }).join('');
}
function setCatImg(input, i) {
  const file = input.files[0]; if(!file)return;
  if(file.size>10*1024*1024){showToast('Imagen máximo 10MB','error');return;}
  _compressImg(file, 800, 0.80, data => {
    if(!data){showToast('Error al procesar la imagen','error');return;}
    cats[i].bg=data; loadCatEditor();
  });
}
function dropCatImg(e, i) { e.preventDefault();e.currentTarget.classList.remove('drag');const f=e.dataTransfer.files[0];if(f&&f.type.startsWith('image/')){const inp={files:[f]};setCatImg(inp,i);} }
function saveCategories() { saveCats(); renderHomeCats(); renderNavBar(); renderFooterCats(); showToast('Categorías guardadas y actualizadas en la tienda ✓'); }

/* ═════════════════════════════════════
   PRODUCT MODAL
═════════════════════════════════════ */
function openProductModal(id=null) {
  editId=id; clearProdForm();
  // Populate category select
  const sel=document.getElementById('prod-cat');
  sel.innerHTML='<option value="">Selecciona categoría</option>'+cats.map(c=>`<option value="${c.name}" ${id&&products.find(p=>p.id===id)?.cat===c.name?'selected':''}>${c.emoji} ${c.name}</option>`).join('');
  if (id) {
    const p=products.find(x=>x.id===id); if(!p)return;
    document.getElementById('modal-title').textContent='Editar Producto';
    document.getElementById('prod-id').value=p.id;
    ['name','brand','cat','sku','seller','price','orig','cuotas','stock','rat','rev','desc','video'].forEach(k=>{const el=document.getElementById('prod-'+k);if(el)el.value=p[k]||'';});
    document.getElementById('prod-cat').value=p.cat||'';
    ['hot','sale','newp','featured'].forEach((k,i)=>{ const el=document.getElementById(['b-hot','b-sale','b-new','b-feat'][i]);if(el)el.checked=!!p[k]; });
    if(p.envio)document.getElementById('tog-ship').classList.add('on');
    if(p.visible!==false)document.getElementById('tog-vis').classList.add('on');
    formImgs=[...(p.imgs||[])]; renderFormImgs();
    specData=[...(p.specs||[])]; renderSpecRows();
    featData=[...(p.feats||[])]; renderFeatRows();
    var _ta=document.getElementById('prod-desc'); if(_ta)updateDescChar(_ta);
  } else {
    document.getElementById('modal-title').textContent='Agregar Producto';
    document.getElementById('tog-vis').classList.add('on');
  }
  document.getElementById('prodModal').classList.add('open');
}
function closeProdModal(){ document.getElementById('prodModal').classList.remove('open'); clearProdForm(); editId=null; }
function clearProdForm(){
  ['prod-id','prod-name','prod-brand','prod-cat','prod-sku','prod-seller','prod-price','prod-orig','prod-cuotas','prod-stock','prod-rat','prod-rev','prod-desc','prod-video'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  ['b-hot','b-sale','b-new','b-feat'].forEach(id=>{const e=document.getElementById(id);if(e)e.checked=false;});
  ['tog-ship','tog-vis'].forEach(id=>{const e=document.getElementById(id);if(e)e.classList.remove('on');});
  formImgs=[]; specData=[]; featData=[]; _dragImgIdx=null;
  renderFormImgs(); renderSpecRows(); renderFeatRows();
  var ta=document.getElementById('prod-desc'); if(ta)updateDescChar(ta);
}
function addProductImgs(input){
  var token=''; try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  [...input.files].forEach(function(f){
    if(formImgs.length>=6){showToast('Máximo 6 imágenes','error');return;}
    if(f.size>5*1024*1024){showToast('Máx 5MB por imagen','error');return;}
    // Reservar posición con placeholder de carga
    var idx=formImgs.length;
    formImgs.push('__uploading__');
    renderFormImgs();
    // Comprimir antes de subir (~1200px, 82% calidad)
    _compressImg(f, 1200, 0.82, function(dataUrl){
      if(!dataUrl){
        formImgs.splice(idx,1); renderFormImgs();
        showToast('Error al procesar la imagen','error'); return;
      }
      if(!token){
        // Sin sesión admin: guardar local como fallback (no persistirá en otros dispositivos)
        formImgs[idx]=dataUrl; renderFormImgs();
        showToast('Inicia sesión como admin para guardar imágenes en el servidor','warn'); return;
      }
      var base64=dataUrl.split(',')[1];
      var mimeType=dataUrl.split(';')[0].split(':')[1]||'image/jpeg';
      fetch(API_BASE+'/api/admin/image',{
        method:'POST',
        headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
        body:JSON.stringify({base64:base64,mimeType:mimeType})
      })
      .then(function(r){return r.json();})
      .then(function(d){
        if(d.ok&&d.url){ formImgs[idx]=d.url; renderFormImgs(); }
        else{ formImgs.splice(idx,1); renderFormImgs(); showToast(d.error||'Error al subir imagen','error'); }
      })
      .catch(function(){ formImgs.splice(idx,1); renderFormImgs(); showToast('Sin conexión — no se pudo subir la imagen','error'); });
    });
  });
  input.value='';
}
function dropImgs(e){
  e.preventDefault();
  document.getElementById('imgUpArea').classList.remove('drag');
  var files=[...e.dataTransfer.files].filter(f=>f.type.startsWith('image/'));
  if(!files.length) return;
  // Reusar el mismo flujo de addProductImgs (comprime + sube al Worker)
  var fakeInput={files:files,value:''};
  addProductImgs(fakeInput);
}
function removeImg(i){ formImgs.splice(i,1); renderFormImgs(); }
var _dragImgIdx = null;
function renderFormImgs(){
  var row = document.getElementById('imgPreviewRow');
  row.innerHTML = formImgs.map((img,i)=>{
    if(img==='__uploading__') return `<div class="img-thumb-edit" style="display:flex;align-items:center;justify-content:center;background:var(--bg-2);"><i class="fas fa-spinner fa-spin" style="color:var(--muted);font-size:20px;"></i></div>`;
    return `<div class="img-thumb-edit" draggable="true" data-idx="${i}" ondragstart="_dragImgIdx=parseInt(this.dataset.idx)" ondragover="event.preventDefault();this.style.opacity='.5'" ondragleave="this.style.opacity=''" ondrop="_dropReorder(parseInt(this.dataset.idx));this.style.opacity=''"><img src="${img}" alt="img-${i}"><button class="img-del-btn" onclick="removeImg(${i})"><i class="fas fa-times"></i></button>${i===0?'<div class="img-main-badge">PRINCIPAL</div>':''}</div>`;
  }).join('');
}
function _dropReorder(toIdx){
  if(_dragImgIdx===null||_dragImgIdx===toIdx) return;
  const moved = formImgs.splice(_dragImgIdx,1)[0];
  formImgs.splice(toIdx,0,moved);
  _dragImgIdx=null;
  renderFormImgs();
}

/* ── Toolbar de descripción ── */
function updateDescChar(ta){
  var n = ta.value.length;
  var el = document.getElementById('descCharCount');
  var bar = document.getElementById('descCharBar');
  if(el) el.textContent = n;
  if(bar){ bar.classList.toggle('warn', n>600&&n<=750); bar.classList.toggle('limit', n>750); }
}
function dtbWrap(pre, post){
  var ta = document.getElementById('prod-desc');
  if(!ta) return;
  var s=ta.selectionStart, e=ta.selectionEnd;
  var sel = ta.value.substring(s,e) || 'texto';
  ta.value = ta.value.substring(0,s)+pre+sel+post+ta.value.substring(e);
  ta.focus(); ta.selectionStart=s+pre.length; ta.selectionEnd=s+pre.length+sel.length;
  updateDescChar(ta);
}
function dtbLine(prefix){
  var ta = document.getElementById('prod-desc');
  if(!ta) return;
  var cur = ta.selectionStart;
  var before = ta.value.substring(0,cur);
  var lineStart = before.lastIndexOf('\n')+1;
  ta.value = ta.value.substring(0,lineStart)+prefix+ta.value.substring(lineStart);
  ta.focus(); ta.selectionStart = ta.selectionEnd = cur+prefix.length;
  updateDescChar(ta);
}
function dtbNewline(){
  var ta = document.getElementById('prod-desc');
  if(!ta) return;
  var s = ta.selectionStart;
  ta.value = ta.value.substring(0,s)+'\n'+ta.value.substring(s);
  ta.focus(); ta.selectionStart = ta.selectionEnd = s+1;
  updateDescChar(ta);
}

function addSpecRow(k='',v=''){ specData.push({k,v}); renderSpecRows(); }
function removeSpec(i){ specData.splice(i,1); renderSpecRows(); }
function renderSpecRows(){ document.getElementById('specRowsWrap').innerHTML=specData.map((s,i)=>`<div class="spec-row-item"><input class="form-input" placeholder="Ej: Potencia" value="${esc(s.k)}" oninput="specData[${i}].k=this.value"><input class="form-input" placeholder="Ej: 20W" value="${esc(s.v)}" oninput="specData[${i}].v=this.value"><button class="row-del-btn" onclick="removeSpec(${i})"><i class="fas fa-times"></i></button></div>`).join(''); }
function addFeatRow(v=''){ featData.push(v); renderFeatRows(); }
function removeFeat(i){ featData.splice(i,1); renderFeatRows(); }
function renderFeatRows(){ document.getElementById('featRowsWrap').innerHTML=featData.map((f,i)=>`<div class="feat-row-item"><input class="form-input" placeholder="Ej: Resistente al agua IP67" value="${esc(f)}" oninput="featData[${i}]=this.value"><button class="row-del-btn" onclick="removeFeat(${i})"><i class="fas fa-times"></i></button></div>`).join(''); }
function saveProd(){
  const name=document.getElementById('prod-name').value.trim();
  const price=parseFloat(document.getElementById('prod-price').value);
  if(!name){showToast('El nombre es obligatorio','error');return;}
  if(!price||price<=0){showToast('Precio inválido','error');return;}
  const orig=parseFloat(document.getElementById('prod-orig').value)||null;
  const off=(orig&&orig>price)?Math.round((1-price/orig)*100):null;
  var _pid = editId || uid();
  var _existSlug = editId ? (products.find(p=>p.id===editId)||{}).slug : null;
  var _slug = _existSlug || (_toSlug(name) + '-' + _pid.slice(-4));
  const prod={
    id:_pid, name, brand:document.getElementById('prod-brand').value.trim(),
    cat:document.getElementById('prod-cat').value, sku:document.getElementById('prod-sku').value.trim(),
    seller:document.getElementById('prod-seller').value.trim()||gc('name'),
    price, orig, off, cuotas:document.getElementById('prod-cuotas').value.trim(),
    stock:parseInt(document.getElementById('prod-stock').value)||null,
    rat:parseFloat(document.getElementById('prod-rat').value)||4.5,
    rev:parseInt(document.getElementById('prod-rev').value)||0,
    desc:document.getElementById('prod-desc').value.trim(),
    video:document.getElementById('prod-video').value.trim(),
    imgs:[...formImgs], specs:specData.filter(s=>s.k), feats:featData.filter(f=>f.trim()),
    hot:document.getElementById('b-hot').checked, sale:document.getElementById('b-sale').checked,
    newp:document.getElementById('b-new').checked, featured:document.getElementById('b-feat').checked,
    envio:document.getElementById('tog-ship').classList.contains('on'),
    visible:document.getElementById('tog-vis').classList.contains('on'),
    slug:_slug,
  };
  if(editId){ const idx=products.findIndex(p=>p.id===editId); if(idx!==-1)products[idx]=prod; }
  else products.unshift(prod);
  saveP(); renderAll(); closeProdModal(); updStats(); showToast(editId?'Producto actualizado ✓':'Producto agregado ✓');
  // Sync to Worker KV (fire-and-forget) — strip base64 imgs antes de enviar
  (function(p){
    var token=''; try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
    if(!token) return;
    var prodKV = Object.assign({}, p, {
      imgs: (p.imgs||[]).filter(function(u){ return typeof u==='string' && u.startsWith('http'); })
    });
    fetch(API_BASE+'/api/admin/product',{
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
      body:JSON.stringify(prodKV)
    }).catch(function(){});
  })(prod);
}
async function deleteProd(id){
  if(!await _confirmModal('¿Eliminar este producto? Esta acción no se puede deshacer.','Eliminar producto','Eliminar',true))return;
  products=products.filter(p=>p.id!==id);
  saveP(); renderAll(); renderProdTable(); updStats(); showToast('Producto eliminado del catálogo');
  // Sync delete to Worker KV (fire-and-forget)
  var token=''; try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  if(token) fetch(API_BASE+'/api/admin/product/'+encodeURIComponent(id),{
    method:'DELETE',
    headers:{'Authorization':'Bearer '+token}
  }).catch(function(){});
}
function dupProd(id){ const p=products.find(x=>x.id===id);if(!p)return; products.unshift({...p,id:uid(),name:p.name+' (copia)'}); saveP(); renderAll(); renderProdTable(); updStats(); showToast('Producto duplicado — aparece al inicio de la tabla ✓'); }
function renderAll(){
  renderHomeProducts(document.getElementById('searchInp').value||'');
  renderHomeCats(); renderNavBar(); renderFooterCats();
  var inp=document.getElementById('mobSearchInp');
  if(inp) inp.placeholder='Buscar en '+products.filter(function(p){return p.visible!==false;}).length+' productos...';
}

/* ═════════════════════════════════════
   PRODUCT TABLE (ADMIN)
═════════════════════════════════════ */
var selectedProdIds=new Set();

function _syncProdToKV(p){
  var token='';try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  if(!token)return;
  var prodKV=Object.assign({},p,{
    imgs:(p.imgs||[]).filter(function(u){return typeof u==='string'&&u.startsWith('http');})
  });
  fetch(API_BASE+'/api/admin/product',{
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify(prodKV)
  }).catch(function(){});
}

function renderProdTable(){
  const rawQ=(document.getElementById('pt-search')?.value||'');
  const cat=document.getElementById('pt-cat')?.value||'';
  const bdg=document.getElementById('pt-bdg')?.value||'';

  // Pre-filter by category and badge (exact)
  let pool=products.filter(p=>
    (!cat||p.cat===cat)
    &&(!bdg||(bdg==='hot'&&p.hot)||(bdg==='sale'&&p.sale)||(bdg==='new'&&p.newp))
  );

  // Apply fuzzy search over the filtered pool
  let list=pool;
  if(rawQ.trim()){
    const r=_fuzzySearch(rawQ,pool);
    list=r.exact;
    if(list.length<3&&rawQ.trim().length>=3){
      const seen=new Set(list.map(p=>p.id));
      list=list.concat(r.fuzzy.filter(p=>!seen.has(p.id)));
    }
  }
  const tb=document.getElementById('prodTableBody');

  // Inject bulk bar once into wrapper
  const wrap=document.getElementById('prodTableWrap');
  if(wrap&&!document.getElementById('bulkBar')){
    const bar=document.createElement('div');
    bar.id='bulkBar';bar.className='bulk-bar';
    bar.innerHTML=
      '<span class="bulk-count"><strong id="bulkCount">0</strong> producto(s) seleccionado(s)</span>'+
      '<div class="bulk-acts">'+
        '<button class="bulk-btn bulk-btn-show" onclick="bulkSetVisible(true)"><i class="fas fa-eye"></i> Mostrar</button>'+
        '<button class="bulk-btn bulk-btn-hide" onclick="bulkSetVisible(false)"><i class="fas fa-eye-slash"></i> Ocultar</button>'+
        '<button class="bulk-btn bulk-btn-del" onclick="bulkDelete()"><i class="fas fa-trash"></i> Eliminar</button>'+
        '<button class="bulk-btn bulk-btn-cancel" onclick="clearSelection()">Cancelar</button>'+
      '</div>';
    wrap.insertBefore(bar,wrap.firstChild);
  }

  if(!list.length){
    tb.innerHTML='<tr><td colspan="10"><div class="empty-table"><i class="fas fa-box-open"></i><p>Ningún producto coincide con el filtro activo</p><p style="font-size:12px;margin-top:6px;opacity:.6">Prueba cambiando la búsqueda o limpia los filtros</p></div></td></tr>';
    return;
  }

  tb.innerHTML=list.map(p=>{
    const img=p.imgs&&p.imgs[0];
    const bdgs=[
      p.hot?'<span class="pc-badge pcb-hot" style="font-size:10px;padding:2px 6px">🔥</span>':'',
      p.sale?'<span class="pc-badge pcb-sale" style="font-size:10px;padding:2px 6px">Oferta</span>':'',
      p.newp?'<span class="pc-badge pcb-new" style="font-size:10px;padding:2px 6px">Nuevo</span>':''
    ].filter(Boolean).join(' ');
    const isVis=p.visible!==false;
    const stk=p.stock!=null?p.stock:0;
    const isSel=selectedProdIds.has(p.id);
    return `<tr data-id="${p.id}">
      <td class="pt-th-cb"><input type="checkbox" class="pt-cb pt-row-cb" ${isSel?'checked':''} onchange="toggleRowSelect('${p.id}',this)"></td>
      <td>${img?`<img class="pt-thumb" src="${esc(img)}" alt="">`:'<div class="pt-no-img">📦</div>'}</td>
      <td style="max-width:220px"><div class="pt-name">${esc(p.name)}</div><div class="pt-brand">${esc(p.brand||'')}${p.sku?` · SKU: ${esc(p.sku)}`:''}</div></td>
      <td><span class="pt-cat-tag">${esc(p.cat||'Sin cat.')}</span></td>
      <td><span class="pt-price">${fp(p.price)}</span>${p.off?`<span style="color:var(--accent);font-size:11px;font-weight:700"> -${p.off}%</span>`:''}</td>
      <td><div style="display:flex;flex-wrap:wrap;gap:4px">${bdgs||'<span style="color:var(--muted);font-size:12px">–</span>'}</div></td>
      <td><span style="color:${p.envio?'var(--accent)':'var(--muted)'};font-size:13px">${p.envio?'✓ Gratis':'✗ No'}</span></td>
      <td class="pt-col-x"><label class="vis-toggle" title="${isVis?'Visible — click para ocultar':'Oculto — click para mostrar'}"><input type="checkbox" ${isVis?'checked':''} onchange="toggleVisible('${p.id}',this.checked)"><span class="vis-slider"></span><span class="vis-lbl">${isVis?'Visible':'Oculto'}</span></label></td>
      <td class="pt-col-x"><div class="stock-cell"><span class="stock-val${stk===0?' zero':''}" onclick="editStockInline('${p.id}',this)">${stk}</span>${stk===0?'<span class="badge-nostock">Sin stock</span>':''}</div></td>
      <td><div class="pt-actions"><button class="pt-act edit" onclick="openProductModal('${p.id}')" title="Editar"><i class="fas fa-pencil-alt"></i></button><button class="pt-act dup" onclick="dupProd('${p.id}')" title="Duplicar"><i class="fas fa-copy"></i></button><button class="pt-act del" onclick="deleteProd('${p.id}')" title="Eliminar"><i class="fas fa-trash"></i></button></div></td>
    </tr>`;
  }).join('');

  _syncSelectAllState();
}
function updCatFilter(){
  const cs=[...new Set(products.map(p=>p.cat).filter(Boolean))];
  const sel=document.getElementById('pt-cat'); const cur=sel?.value||'';
  if(sel)sel.innerHTML='<option value="">Todas las categorías</option>'+cs.map(c=>`<option ${c===cur?'selected':''}>${c}</option>`).join('');
}

/* ── VISIBLE / STOCK inline ── */
function toggleVisible(id,checked){
  var idx=products.findIndex(function(p){return p.id===id;});
  if(idx===-1)return;
  products[idx]=Object.assign({},products[idx],{visible:checked});
  saveP();renderProdTable();_syncProdToKV(products[idx]);
  showToast(checked?'Producto publicado en la tienda ✓':'Producto ocultado — no aparece en la tienda');
}
function editStockInline(id,el){
  var p=products.find(function(x){return x.id===id;});
  if(!p)return;
  var current=p.stock!=null?p.stock:0;
  var inp=document.createElement('input');
  inp.className='stock-inp';inp.type='number';inp.min='0';inp.value=current;
  el.parentNode.replaceChild(inp,el);
  inp.focus();inp.select();
  var done=false;
  function commit(){
    if(done)return;done=true;
    var val=parseInt(inp.value);
    if(isNaN(val)||val<0)val=current;
    updateStock(id,val);
  }
  inp.addEventListener('blur',commit);
  inp.addEventListener('keydown',function(e){
    if(e.key==='Enter'){inp.blur();}
    else if(e.key==='Escape'){done=true;renderProdTable();}
  });
}
function updateStock(id,val){
  var n=parseInt(val);if(isNaN(n)||n<0)return;
  var idx=products.findIndex(function(p){return p.id===id;});
  if(idx===-1)return;
  products[idx]=Object.assign({},products[idx],{stock:n});
  saveP();renderProdTable();_syncProdToKV(products[idx]);
}
function toggleExtraCols(){
  var cols=document.querySelectorAll('.pt-col-x');
  var show=!Array.from(cols)[0]?.classList.contains('show');
  cols.forEach(function(el){el.classList.toggle('show',show);});
  var btn=document.getElementById('ptColToggleBtn');
  if(btn)btn.innerHTML=show
    ?'<i class="fas fa-columns"></i> Menos columnas'
    :'<i class="fas fa-columns"></i> Más columnas';
}

/* ── BULK ACTIONS ── */
function toggleRowSelect(id,cb){
  if(cb.checked){selectedProdIds.add(id);}else{selectedProdIds.delete(id);}
  _updateBulkBar();_syncSelectAllState();
}
function toggleSelectAll(cb){
  document.querySelectorAll('#prodTableBody tr[data-id]').forEach(function(row){
    var id=row.dataset.id;
    var rowCb=row.querySelector('.pt-row-cb');
    if(cb.checked){selectedProdIds.add(id);if(rowCb)rowCb.checked=true;}
    else{selectedProdIds.delete(id);if(rowCb)rowCb.checked=false;}
  });
  _updateBulkBar();
}
function _updateBulkBar(){
  var bar=document.getElementById('bulkBar');
  var cnt=document.getElementById('bulkCount');
  if(!bar)return;
  var n=selectedProdIds.size;
  if(cnt)cnt.textContent=n;
  bar.classList.toggle('active',n>0);
}
function _syncSelectAllState(){
  var allCb=document.getElementById('pt-sel-all');
  if(!allCb)return;
  var rows=document.querySelectorAll('#prodTableBody tr[data-id]');
  var total=rows.length;
  var sel=Array.from(rows).filter(function(r){return selectedProdIds.has(r.dataset.id);}).length;
  allCb.checked=total>0&&sel===total;
  allCb.indeterminate=sel>0&&sel<total;
}
function clearSelection(){
  selectedProdIds.clear();
  document.querySelectorAll('.pt-row-cb').forEach(function(cb){cb.checked=false;});
  var allCb=document.getElementById('pt-sel-all');
  if(allCb){allCb.checked=false;allCb.indeterminate=false;}
  _updateBulkBar();
}
async function bulkDelete(){
  var n=selectedProdIds.size;if(!n)return;
  if(!await _confirmModal('¿Eliminar '+n+' producto'+(n!==1?'s':'')+' seleccionado'+(n!==1?'s':'')+' del catálogo? Esta acción no se puede deshacer.','Eliminar productos','Eliminar',true))return;
  var token='';try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  Array.from(selectedProdIds).forEach(function(id){
    products=products.filter(function(p){return p.id!==id;});
    if(token)fetch(API_BASE+'/api/admin/product/'+encodeURIComponent(id),{
      method:'DELETE',headers:{'Authorization':'Bearer '+token}
    }).catch(function(){});
  });
  saveP();renderAll();renderProdTable();updStats();
  selectedProdIds.clear();_updateBulkBar();
  showToast(n+' producto'+(n!==1?'s':'')+' eliminado'+(n!==1?'s':''));
}
function bulkSetVisible(visible){
  var n=selectedProdIds.size;if(!n)return;
  Array.from(selectedProdIds).forEach(function(id){
    var idx=products.findIndex(function(p){return p.id===id;});
    if(idx===-1)return;
    products[idx]=Object.assign({},products[idx],{visible:visible});
    _syncProdToKV(products[idx]);
  });
  saveP();renderProdTable();
  selectedProdIds.clear();_updateBulkBar();
  showToast(n+' producto'+(n!==1?'s':'')+' '+(visible?'mostrado'+(n!==1?'s':''):'ocultado'+(n!==1?'s':''))+' ✓');
}

function updStats(){
  document.getElementById('st-prod').textContent=products.length;
  document.getElementById('st-cat').textContent=[...new Set(products.map(p=>p.cat).filter(Boolean))].length;
  document.getElementById('st-hot').textContent=products.filter(p=>p.hot).length;
  document.getElementById('st-img').textContent=products.filter(p=>p.imgs&&p.imgs.length>0).length;
  document.getElementById('prodBadge').textContent=products.length;
}

/* ═════════════════════════════════════
   ADMIN AUTH & TABS
═════════════════════════════════════ */
function openAdmin(){
  document.getElementById('pwMsg').textContent='Ingresa la contraseña para acceder';
  document.getElementById('pwSubmitBtn').innerHTML='<i class="fas fa-unlock-alt"></i> Acceder al Panel';
  document.getElementById('pwScreen').classList.add('open');
  document.getElementById('pwInput').value='';
  document.getElementById('pwError').classList.remove('show');
  setTimeout(()=>document.getElementById('pwInput').focus(),100);
}
function closePw(){document.getElementById('pwScreen').classList.remove('open');}
function _openAdminPanel(){
  closePw();
  document.getElementById('adminPanel').classList.add('open');
  document.body.classList.add('admin-open');
  // Empujar estado al historial para que el back-button cierre el panel
  history.pushState({view:'admin',tab:'dashboard'}, '', window.location.pathname);
  swTab('dashboard');
  updStats();renderProdTable();updCatFilter();loadConfig();loadBannerEditor();loadCatEditor();
}
function chkPw(){
  var v=document.getElementById('pwInput').value;
  if(!v){document.getElementById('pwError').textContent='Ingresa una contraseña';document.getElementById('pwError').classList.add('show');return;}
  var btn=document.getElementById('pwSubmitBtn');
  btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Verificando...';
  fetch(API_BASE+'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:v})})
  .then(function(r){return r.json();})
  .then(function(d){
    btn.disabled=false;btn.innerHTML='<i class="fas fa-unlock-alt"></i> Acceder al Panel';
    if(d.ok){try{sessionStorage.setItem('mx_admin_token',d.token);}catch(e){}  _openAdminPanel();}
    else{document.getElementById('pwError').textContent='Contraseña incorrecta';document.getElementById('pwError').classList.add('show');document.getElementById('pwInput').value='';}
  })
  .catch(function(){
    btn.disabled=false;btn.innerHTML='<i class="fas fa-unlock-alt"></i> Acceder al Panel';
    document.getElementById('pwError').textContent='Error de conexión — intenta de nuevo';document.getElementById('pwError').classList.add('show');
  });
}
function closeAdmin(){document.getElementById('adminPanel').classList.remove('open');document.body.classList.remove('admin-open');closeAdmSidebar();}
function toggleAdmSidebar(){
  const s=document.getElementById('admSidebar');
  const o=document.getElementById('admMobOverlay');
  const open=s&&s.classList.toggle('adm-open');
  if(o){o.classList.toggle('open',open);o.style.pointerEvents=open?'auto':'none';}
}
function closeAdmSidebar(){
  const s=document.getElementById('admSidebar');
  const o=document.getElementById('admMobOverlay');
  if(s)s.classList.remove('adm-open');
  if(o){o.classList.remove('open');o.style.pointerEvents='none';}
}
function swTab(t){
  document.querySelectorAll('.adm-tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.adm-menu-item').forEach(x=>x.classList.remove('active'));
  document.getElementById('tab-'+t).classList.add('active');
  const labels={dashboard:'dashboard',products:'producto',banners:'banner',categories:'categor',store:'tienda',settings:'ajuste',orders:'pedido'};
  document.querySelectorAll('.adm-menu-item').forEach(m=>{if(m.textContent.toLowerCase().includes(labels[t]))m.classList.add('active');});
  if(t==='products'){renderProdTable();updCatFilter();}
  if(t==='banners')loadBannerEditor();
  if(t==='categories')loadCatEditor();
  if(t==='store')loadConfig();
  if(t==='orders')loadOrders();
  if(window.innerWidth<=768)closeAdmSidebar();
  // Scroll al inicio del contenido al cambiar tab (especialmente en mobile)
  var main=document.querySelector('.adm-main');
  if(main) main.scrollTo(0,0);
  // Actualizar estado del historial para que el back button sepa que estamos en admin
  if(document.getElementById('adminPanel').classList.contains('open')){
    history.replaceState({view:'admin',tab:t}, '', window.location.pathname);
  }
}
function changePw(){
  var np=document.getElementById('npw').value,cp=document.getElementById('cpw').value;
  if(!np||np.length<4){showToast('Mínimo 4 caracteres','error');return;}
  if(np!==cp){showToast('Las contraseñas no coinciden','error');return;}
  var token=sessionStorage.getItem('mx_admin_token');
  if(!token){showToast('Sesión expirada — vuelve a ingresar','error');return;}
  fetch(API_BASE+'/api/admin/change-password',{
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify({password:np})
  })
  .then(function(r){return r.json();})
  .then(function(d){
    if(d&&d.ok){
      document.getElementById('npw').value='';
      document.getElementById('cpw').value='';
      showToast('Contraseña cambiada correctamente ✓ — úsala en el próximo inicio de sesión');
    } else {
      showToast(d&&d.error||'No se pudo cambiar la contraseña','error');
    }
  })
  .catch(function(){showToast('Error de conexión','error');});
}
function exportAll(){const blob=new Blob([JSON.stringify({products,config,banners,cats,exported:new Date().toISOString()},null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`maxicompra-backup-${Date.now()}.json`;a.click();showToast('Backup guardado en tu carpeta de descargas ✓');}
function importAll(e){
  const f=e.target.files[0];if(!f)return;
  const r=new FileReader();
  r.onload=async ev=>{
    try{
      const d=JSON.parse(ev.target.result);
      if(d.products&&Array.isArray(d.products)){
        if(!await _confirmModal(`¿Importar ${d.products.length} productos? Esto actualizará el catálogo con los datos del archivo.`,'Importar backup','Importar',false))return;
        // Ensure all imported products have slugs
        products=d.products.map(function(p){
          if(!p.slug) p.slug=_toSlug(p.name||'')+'-'+(p.id||'').slice(-4);
          return p;
        });
        saveP();
        if(d.config){config=d.config;saveCfg();applyCfg();}
        if(d.banners&&Array.isArray(d.banners)){banners=d.banners;saveBan();renderHeroSlider();}
        if(d.cats&&Array.isArray(d.cats)){cats=d.cats;saveCats();}
        renderAll();renderProdTable();updStats();
        showToast(`${d.products.length} productos importados ✓`);
        // Sync all to Worker KV in one bulk request
        var token='';try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(ex){}
        if(token){
          fetch(API_BASE+'/api/admin/products/bulk',{
            method:'POST',
            headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
            body:JSON.stringify({products:products})
          }).catch(function(){});
        }
      } else showToast('Archivo inválido','error');
    }catch{showToast('Error al leer el archivo','error');}
  };
  r.readAsText(f);e.target.value='';
}
async function clearProds(){
  if(!await _confirmModal('¿Eliminar TODOS los productos del catálogo? Esta acción no se puede deshacer.','Vaciar catálogo','Eliminar todo',true))return;
  products=[];saveP();renderAll();renderProdTable();updStats();showToast('Catálogo vaciado — recuerda hacer una copia de respaldo la próxima vez');
}
/* ══════════════════════════════════════════════
   AUTO-IMG: busca imágenes en ML via Worker proxy
══════════════════════════════════════════════ */
var _aiRunning = false;
var _aiStop    = false;

function openAutoImgModal() {
  var sinImg = products.filter(function(p){ return !p.imgs || !p.imgs[0] || !String(p.imgs[0]).startsWith('http'); });
  document.getElementById('aiSubtitle').textContent = sinImg.length + ' productos sin imagen de ' + products.length + ' total';
  document.getElementById('aiCountLeft').textContent = sinImg.length;
  document.getElementById('aiCountDone').textContent = '0';
  document.getElementById('aiCountSkip').textContent = '0';
  document.getElementById('aiProgressBar').style.width = '0%';
  document.getElementById('aiProdName').textContent = 'Listo para iniciar';
  document.getElementById('aiStatus').textContent = sinImg.length + ' productos pendientes';
  document.getElementById('aiThumb').innerHTML = '📦';
  document.getElementById('aiBtnStart').style.display = '';
  document.getElementById('aiBtnStop').style.display = 'none';
  document.getElementById('aiNote').textContent = 'Las imágenes se guardan automáticamente y se sincronizan al terminar.';
  document.getElementById('autoImgModal').style.display = 'flex';
}

function closeAutoImgModal() {
  document.getElementById('autoImgModal').style.display = 'none';
}

async function startAutoImg() {
  var token = ''; try{ token = sessionStorage.getItem('mx_admin_token') || ''; }catch(e){}
  if (!token) { showToast('Debes iniciar sesión como admin primero', 'error'); return; }

  var queue = products.filter(function(p){ return !p.imgs || !p.imgs[0] || !String(p.imgs[0]).startsWith('http'); });
  if (!queue.length) { showToast('Todos los productos ya tienen imagen asignada ✓', 'ok'); return; }

  _aiRunning = true;
  _aiStop    = false;
  var done   = 0, skip = 0, total = queue.length;

  document.getElementById('aiBtnStart').style.display = 'none';
  document.getElementById('aiBtnStop').style.display  = '';
  document.getElementById('aiNote').textContent = 'Buscando imágenes... no cierres esta ventana.';

  for (var i = 0; i < queue.length; i++) {
    if (_aiStop) break;
    var p = queue[i];

    // UI: mostrar producto actual
    document.getElementById('aiProdName').textContent = p.name;
    document.getElementById('aiStatus').textContent   = 'Buscando en MercadoLibre...';
    document.getElementById('aiThumb').innerHTML      = '<div style="width:100%;height:100%;background:var(--card2);display:flex;align-items:center;justify-content:center;font-size:20px;">⏳</div>';
    document.getElementById('aiCountLeft').textContent = (total - i);
    document.getElementById('aiProgressBar').style.width = Math.round((i / total) * 100) + '%';

    try {
      var resp = await fetch(API_BASE + '/api/search-image?q=' + encodeURIComponent(p.name));
      var data = await resp.json();

      if (data.ok && data.img) {
        // Guardar imagen en el producto
        var idx = products.findIndex(function(x){ return x.id === p.id; });
        if (idx >= 0) {
          products[idx] = Object.assign({}, products[idx], { imgs: [data.img] });
        }
        done++;
        document.getElementById('aiCountDone').textContent = done;
        document.getElementById('aiStatus').textContent    = '✓ ' + (data.title || 'Encontrada').slice(0, 60);
        document.getElementById('aiThumb').innerHTML       = '<img src="' + data.img + '" style="width:100%;height:100%;object-fit:contain;border-radius:6px;" onerror="this.parentNode.innerHTML=\'📷\'">';
      } else {
        skip++;
        document.getElementById('aiCountSkip').textContent = skip;
        document.getElementById('aiStatus').textContent    = '— Sin resultado';
        document.getElementById('aiThumb').innerHTML       = '❌';
      }
    } catch(e) {
      skip++;
      document.getElementById('aiCountSkip').textContent = skip;
      document.getElementById('aiStatus').textContent    = 'Error de red';
      document.getElementById('aiThumb').innerHTML       = '⚠️';
    }

    // Guardar en localStorage cada 20 productos
    if ((i + 1) % 20 === 0) { saveP(); }

    // Pausa entre requests para no saturar la API
    await new Promise(function(r){ setTimeout(r, 350); });
  }

  // Guardar todo y sincronizar
  saveP();
  renderProdTable();
  renderAll();
  _aiRunning = false;

  var finalMsg = _aiStop
    ? 'Detenido. ' + done + ' imágenes encontradas.'
    : '¡Listo! ' + done + ' imágenes encontradas, ' + skip + ' sin resultado.';

  document.getElementById('aiProgressBar').style.width = '100%';
  document.getElementById('aiStatus').textContent = finalMsg;
  document.getElementById('aiNote').textContent   = done > 0 ? 'Sincronizando con el servidor...' : '';
  document.getElementById('aiBtnStop').style.display  = 'none';
  document.getElementById('aiBtnStart').style.display = '';
  document.getElementById('aiBtnStart').innerHTML     = '<i class="fas fa-check"></i> Listo';

  if (done > 0) {
    showToast(done + ' imágenes guardadas. Sincronizando...', 'ok');
    syncAllProductsToKV();
  }
}

function stopAutoImg() {
  _aiStop = true;
  document.getElementById('aiStatus').textContent = 'Deteniendo...';
}

/* ══════════════════════════════════════════════
   BACKFILL IMGS: obtiene TODAS las fotos desde ML
   (productos con < 3 imágenes)
══════════════════════════════════════════════ */
var _bfRunning = false;
var _bfStop    = false;

function openBackfillModal() {
  var queue = products.filter(function(p){ return !p.imgs || p.imgs.filter(function(u){ return u && String(u).startsWith('http'); }).length < 3; });
  document.getElementById('bfSubtitle').textContent = queue.length + ' productos con menos de 3 imágenes de ' + products.length + ' total';
  document.getElementById('bfCountLeft').textContent = queue.length;
  document.getElementById('bfCountDone').textContent = '0';
  document.getElementById('bfCountSkip').textContent = '0';
  document.getElementById('bfProgressBar').style.width = '0%';
  document.getElementById('bfProdName').textContent = 'Listo para iniciar';
  document.getElementById('bfStatus').textContent = queue.length + ' productos pendientes';
  document.getElementById('bfThumb').innerHTML = '📦';
  document.getElementById('bfBtnStart').style.display = '';
  document.getElementById('bfBtnStart').innerHTML = '<i class="fas fa-play"></i> Iniciar backfill';
  document.getElementById('bfBtnStop').style.display = 'none';
  document.getElementById('bfNote').textContent = 'Busca múltiples imágenes por producto en MercadoLibre (productos con menos de 3 fotos).';
  document.getElementById('backfillModal').style.display = 'flex';
}

function closeBackfillModal() {
  document.getElementById('backfillModal').style.display = 'none';
}

async function startBackfillImgs() {
  var token = ''; try{ token = sessionStorage.getItem('mx_admin_token') || ''; }catch(e){}
  if (!token) { showToast('Debes iniciar sesión como admin primero', 'error'); return; }

  var queue = products.filter(function(p){
    return !p.imgs || p.imgs.filter(function(u){ return u && String(u).startsWith('http'); }).length < 3;
  });
  if (!queue.length) { showToast('Todos los productos ya tienen galería completa ✓', 'ok'); return; }

  _bfRunning = true;
  _bfStop    = false;
  var done   = 0, skip = 0, total = queue.length;

  document.getElementById('bfBtnStart').style.display = 'none';
  document.getElementById('bfBtnStop').style.display  = '';
  document.getElementById('bfNote').textContent = 'Obteniendo imágenes... no cierres esta ventana.';

  for (var i = 0; i < queue.length; i++) {
    if (_bfStop) break;
    var p = queue[i];

    document.getElementById('bfProdName').textContent = p.name;
    document.getElementById('bfStatus').textContent   = 'Buscando en MercadoLibre...';
    document.getElementById('bfThumb').innerHTML      = '<div style="width:100%;height:100%;background:var(--card2);display:flex;align-items:center;justify-content:center;font-size:20px;">⏳</div>';
    document.getElementById('bfCountLeft').textContent = (total - i);
    document.getElementById('bfProgressBar').style.width = Math.round((i / total) * 100) + '%';

    try {
      var resp = await fetch(API_BASE + '/api/search-images-multi?q=' + encodeURIComponent(p.name));
      var data = await resp.json();

      if (data.ok && data.imgs && data.imgs.length) {
        var idx = products.findIndex(function(x){ return x.id === p.id; });
        if (idx >= 0) {
          // Combinar imágenes existentes (http) con las nuevas, sin duplicados
          var existing = (products[idx].imgs || []).filter(function(u){ return u && String(u).startsWith('http'); });
          var merged = existing.slice();
          data.imgs.forEach(function(u) {
            if (u && !merged.includes(u)) merged.push(u);
          });
          products[idx] = Object.assign({}, products[idx], { imgs: merged });
        }
        done++;
        document.getElementById('bfCountDone').textContent = done;
        document.getElementById('bfStatus').textContent    = '✓ ' + data.imgs.length + ' fotos — ' + (data.title || '').slice(0, 50);
        document.getElementById('bfThumb').innerHTML       = '<img src="' + data.imgs[0] + '" style="width:100%;height:100%;object-fit:contain;border-radius:6px;" onerror="this.parentNode.innerHTML=\'📷\'">';
      } else {
        skip++;
        document.getElementById('bfCountSkip').textContent = skip;
        document.getElementById('bfStatus').textContent    = '— Sin resultado';
        document.getElementById('bfThumb').innerHTML       = '❌';
      }
    } catch(e) {
      skip++;
      document.getElementById('bfCountSkip').textContent = skip;
      document.getElementById('bfStatus').textContent    = 'Error de red';
      document.getElementById('bfThumb').innerHTML       = '⚠️';
    }

    if ((i + 1) % 20 === 0) { saveP(); }
    await new Promise(function(r){ setTimeout(r, 400); });
  }

  saveP();
  renderProdTable();
  renderAll();
  _bfRunning = false;

  var finalMsg = _bfStop
    ? 'Detenido. ' + done + ' productos actualizados.'
    : '¡Listo! ' + done + ' productos actualizados, ' + skip + ' sin resultado.';

  document.getElementById('bfProgressBar').style.width = '100%';
  document.getElementById('bfStatus').textContent = finalMsg;
  document.getElementById('bfNote').textContent   = done > 0 ? 'Sincronizando con el servidor...' : '';
  document.getElementById('bfBtnStop').style.display  = 'none';
  document.getElementById('bfBtnStart').style.display = '';
  document.getElementById('bfBtnStart').innerHTML     = '<i class="fas fa-check"></i> Listo';

  if (done > 0) {
    showToast(done + ' productos con imágenes actualizadas. Sincronizando...', 'ok');
    syncAllProductsToKV();
  }
}

function stopBackfillImgs() {
  _bfStop = true;
  document.getElementById('bfStatus').textContent = 'Deteniendo...';
}

/* ─── Importar imágenes desde mx_matches.json ─────────────────── */
function importMLImages(event) {
  var file = event.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {
    try {
      var matches = JSON.parse(e.target.result);
      if (!Array.isArray(matches)) throw new Error('Formato inválido');

      // Índice por ID para lookup O(1)
      var byId = {};
      matches.forEach(function(m) { if (m.id) byId[m.id] = m.img; });

      var updated = 0;
      products = products.map(function(p) {
        var img = byId[p.id];
        if (img && (!p.imgs || !p.imgs[0] || !String(p.imgs[0]).startsWith('http'))) {
          updated++;
          return Object.assign({}, p, { imgs: [img] });
        }
        return p;
      });

      saveP();
      renderAll();
      renderProdTable();
      updStats();
      showToast(updated + ' productos actualizados con imágenes. Sincronizando...', 'ok');
      if (updated > 0) syncAllProductsToKV();
    } catch(err) {
      showToast('Error leyendo el archivo: ' + err.message, 'error');
    }
  };
  reader.readAsText(file);
  event.target.value = ''; // reset input
}

/* ─── Cargar todos los productos desde KV ────────────────────── */
async function loadProdsFromKV() {
  showToast('Sincronizando catálogo desde el servidor...', 'info');
  try {
    var resp = await fetch(API_BASE + '/api/products');
    var data = await resp.json();
    var list  = data.products || data;
    if (!Array.isArray(list) || !list.length) { showToast('El servidor no devolvió productos — verifica que el KV tenga datos', 'error'); return; }
    products = list;
    saveP();
    renderAll();
    renderProdTable();
    updStats();
    showToast(list.length + ' productos cargados desde el servidor ✓', 'ok');
  } catch(err) {
    showToast('Error al cargar: ' + err.message, 'error');
  }
}

// Comprime un dataUrl base64 existente (imágenes viejas sin comprimir pueden ser >5MB)
function _compressBase64(dataUrl, maxPx, quality, cb){
  var img=new Image();
  img.onload=function(){
    var w=img.width,h=img.height;
    if(w>maxPx||h>maxPx){ if(w>h){h=Math.round(h*maxPx/w);w=maxPx;}else{w=Math.round(w*maxPx/h);h=maxPx;} }
    var c=document.createElement('canvas'); c.width=w; c.height=h;
    c.getContext('2d').drawImage(img,0,0,w,h);
    cb(c.toDataURL('image/jpeg',quality));
  };
  img.onerror=function(){ cb(dataUrl); }; // fallback sin comprimir
  img.src=dataUrl;
}

// Sincroniza KV silenciosamente (sin confirm modal) — para uso interno post-migración
async function _syncToKVSilent(){
  var token=''; try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  if(!token) return;
  var list=products.map(function(p){
    if(!p.slug) p.slug=_toSlug(p.name||'')+'-'+(p.id||'').slice(-4);
    return p;
  });
  saveP();
  try{
    var r=await fetch(API_BASE+'/api/admin/products/bulk',{
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
      body:JSON.stringify({products:list})
    });
    var d=await r.json();
    if(d.ok) showToast('Servidor actualizado con las nuevas imágenes ✓','success');
    else showToast('Imágenes migradas localmente. Sincroniza manualmente para actualizar el servidor.','warn');
  }catch(e){
    showToast('Imágenes migradas localmente. Sincroniza manualmente para actualizar el servidor.','warn');
  }
}

// Migra imágenes base64 del localStorage al Worker KV y actualiza los productos con URLs reales
async function _migrateLocalImages(){
  var token=''; try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  if(!token){showToast('Debes iniciar sesión como admin primero','error');return;}

  // Detectar todos los productos con imágenes base64 (data:...)
  var toMigrate=[];
  products.forEach(function(p){
    if(!Array.isArray(p.imgs)) return;
    var localImgs=p.imgs.filter(function(u){return typeof u==='string'&&u.startsWith('data:');});
    if(localImgs.length) toMigrate.push({p:p,count:localImgs.length});
  });

  if(!toMigrate.length){
    showToast('No hay imágenes locales pendientes de migrar ✓','success'); return;
  }

  var totalImgs=toMigrate.reduce(function(s,x){return s+x.count;},0);
  var ok=await _confirmModal(
    'Se encontraron '+totalImgs+' imagen'+(totalImgs!==1?'es':'')+' en '+toMigrate.length+' producto'+(toMigrate.length!==1?'s':'')+' guardadas solo en este dispositivo. ¿Subirlas al servidor ahora?',
    'Migrar imágenes','Migrar',false
  );
  if(!ok) return;

  var descEl=document.getElementById('migrateImgsDesc');
  var done=0, failed=0, failedProds=[];

  for(var i=0;i<toMigrate.length;i++){
    var prod=toMigrate[i].p;
    var newImgs=[];
    var prodFailed=false;
    for(var j=0;j<prod.imgs.length;j++){
      var imgUrl=prod.imgs[j];
      // Si ya es URL http, no tocar
      if(typeof imgUrl==='string'&&(imgUrl.startsWith('http://')||imgUrl.startsWith('https://'))){
        newImgs.push(imgUrl); continue;
      }
      if(typeof imgUrl!=='string'||!imgUrl.startsWith('data:')){continue;}
      if(descEl) descEl.textContent='Subiendo imagen '+(done+failed+1)+' de '+totalImgs+' (comprimiendo…)';
      // Comprimir primero — imágenes viejas pueden ser 5-10MB sin comprimir
      var compressed=await new Promise(function(res){_compressBase64(imgUrl,1200,0.82,res);});
      if(descEl) descEl.textContent='Subiendo imagen '+(done+failed+1)+' de '+totalImgs+'…';
      try{
        var base64=compressed.split(',')[1];
        var mimeType='image/jpeg';
        var r=await fetch(API_BASE+'/api/admin/image',{
          method:'POST',
          headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
          body:JSON.stringify({base64:base64,mimeType:mimeType})
        });
        var d=await r.json();
        if(d.ok&&d.url){newImgs.push(d.url);done++;}
        else{newImgs.push(imgUrl);failed++;prodFailed=true;}
      }catch(e){newImgs.push(imgUrl);failed++;prodFailed=true;}
    }
    if(prodFailed) failedProds.push(prod.name||prod.id);
    // Actualizar producto con las URLs nuevas
    var idx=products.findIndex(function(x){return x.id===prod.id;});
    if(idx!==-1) products[idx]=Object.assign({},products[idx],{imgs:newImgs});
  }

  saveP();
  if(descEl) descEl.textContent='Detecta imágenes guardadas solo en este dispositivo y las sube al servidor para que sean visibles en todos lados';

  if(failed===0){
    showToast('✅ '+done+' imagen'+(done!==1?'es':'')+' migrada'+(done!==1?'s':'')+' correctamente','success');
    // Sincronizar KV silenciosamente (sin segundo modal de confirmación)
    await _syncToKVSilent();
  } else {
    showToast(done+' migradas, '+failed+' fallaron en: '+failedProds.slice(0,3).join(', ')+(failedProds.length>3?'…':''),'warn');
  }
}

async function syncAllProductsToKV(){
  var token=''; try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  if(!token){showToast('Debes iniciar sesión como admin primero','error');return;}
  if(!await _confirmModal('¿Sincronizar '+products.length+' productos con el servidor KV? Esto sobreescribirá los datos actuales en el servidor.','Sincronizar con servidor','Sincronizar',false))return;
  // Ensure all products have slugs before syncing
  var list=products.map(function(p){
    if(!p.slug) p.slug=_toSlug(p.name||'')+'-'+(p.id||'').slice(-4);
    return p;
  });
  saveP();
  showToast('Sincronizando '+list.length+' productos...');
  // Strip base64/blob images before sending — reduces payload from ~50MB to ~1MB
  var listClean=list.map(function(p){
    var imgs=(p.imgs||[]).filter(function(u){ return typeof u==='string'&&(u.startsWith('http://')||u.startsWith('https://')); });
    return Object.assign({},p,{imgs:imgs});
  });
  fetch(API_BASE+'/api/admin/products/bulk',{
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify({products:listClean})
  })
  .then(function(r){ return r.json(); })
  .then(function(d){
    if(d.ok) showToast('Sincronización completa ✓ ('+d.count+' productos)');
    else showToast('Error: '+(d.error||'desconocido'),'error');
  })
  .catch(function(){ showToast('Error de conexión al sincronizar','error'); });
}

/* ═════════════════════════════════════
   ADMIN — PEDIDOS
═════════════════════════════════════ */
var _ordStatusLabels = {pending:'⏳ Pendiente',payment_pending:'🔄 Pago en proceso',payment_failed:'❌ Pago fallido',paid:'✅ Pagado',shipped:'🚚 Enviado',delivered:'🎉 Entregado',cancelled:'❌ Cancelado'};
var _ordPayLabels    = {mp:'Mercado Pago',transfer:'Transferencia',cash:'Efectivo',webpay:'Webpay'};
var _ordPayIcons     = {mp:'💙',transfer:'🏦',cash:'💵',webpay:'💳'};

var _ordDataCache = [];

function loadOrders(){
  var di = document.getElementById('ordDate');
  if(!di) return;
  if(!di.value) di.value = new Date().toISOString().slice(0,10);
  var token = '';
  try { token = sessionStorage.getItem('mx_admin_token')||''; } catch(e){}
  if(!token){ document.getElementById('ordList').innerHTML='<div class="ord-empty"><i class="fas fa-lock"></i><p>Sesión expirada — vuelve a iniciar sesión</p></div>'; return; }
  var container = document.getElementById('ordList');
  container.innerHTML='<div class="ord-empty"><i class="fas fa-spinner fa-spin"></i><p>Cargando pedidos…</p></div>';
  var sf=document.getElementById('ordStatusFilter');
  if(sf) sf.value=''; // reset filter on new date load
  fetch(API_BASE+'/api/admin/orders?date='+di.value, {headers:{'Authorization':'Bearer '+token}})
  .then(function(r){return r.json();})
  .then(function(d){
    if(!d.ok){container.innerHTML='<div class="ord-empty"><i class="fas fa-exclamation-circle"></i><p>Error al cargar: '+(d.error||'desconocido')+'</p></div>';return;}
    _ordDataCache = d.orders||[];
    renderOrdersTable(_ordDataCache, container);
    var badge=document.getElementById('ordersBadge');
    if(badge){badge.textContent=d.total;badge.style.display=d.total>0?'':'none';}
  })
  .catch(function(){container.innerHTML='<div class="ord-empty"><i class="fas fa-wifi-slash"></i><p>Sin conexión con el servidor</p></div>';});
}

function filterOrders(){
  var sf=document.getElementById('ordStatusFilter');
  var status=sf?sf.value:'';
  var list=status?_ordDataCache.filter(function(o){return (o.status||'pending')===status;}):_ordDataCache;
  var container=document.getElementById('ordList');
  if(!container)return;
  renderOrdersTable(list, container, !!status); // skipSummary when filtering
}

function searchOrders(){
  var q=(document.getElementById('ordSearch')||{}).value||'';
  q=q.trim();
  if(!q){loadOrders();return;}
  if(q.length<2){showToast('Mínimo 2 caracteres','error');return;}
  var token='';try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  if(!token)return;
  var container=document.getElementById('ordList');
  container.innerHTML='<div class="ord-empty"><i class="fas fa-spinner fa-spin"></i><p>Buscando en últimos 90 días…</p></div>';
  fetch(API_BASE+'/api/admin/orders/search?q='+encodeURIComponent(q),{headers:{'Authorization':'Bearer '+token}})
  .then(function(r){return r.json();})
  .then(function(d){
    if(!d.ok){container.innerHTML='<div class="ord-empty"><i class="fas fa-search"></i><p>Sin resultados</p></div>';return;}
    _ordDataCache=d.orders||[];
    renderOrdersTable(_ordDataCache,container,true); // no daily summary in global search
    if(d.total>0) showToast(d.total+' resultado(s) encontrado(s)');
  })
  .catch(function(){container.innerHTML='<div class="ord-empty"><i class="fas fa-wifi-slash"></i><p>Error de conexión</p></div>';});
}

function changeOrdDate(delta){
  var di=document.getElementById('ordDate');
  if(!di)return;
  var d=new Date((di.value||new Date().toISOString().slice(0,10))+'T12:00:00');
  d.setDate(d.getDate()+delta);
  di.value=d.toISOString().slice(0,10);
  loadOrders();
}

function _renderOrdSummary(orders){
  var INCOME_ST={paid:1,shipped:1,delivered:1};
  var income=0,pending=0,cancelled=0,total=orders.length;
  var payTotals={};
  orders.forEach(function(o){
    var st=o.status||'pending';
    var amt=Math.round(o.total||0);
    if(INCOME_ST[st]){
      income+=amt;
      var pm=o.payment||'other';
      payTotals[pm]=(payTotals[pm]||0)+amt;
    }
    if(st==='pending'||st==='payment_pending') pending++;
    if(st==='cancelled'||st==='payment_failed') cancelled++;
  });
  var payPills=Object.keys(payTotals).map(function(pm){
    return '<span class="ord-pay-pill">'+(_ordPayIcons[pm]||'💳')+' $'+payTotals[pm].toLocaleString('es-CL')+'</span>';
  }).join('');
  return '<div class="ord-summary">'+
    '<div class="ord-sum-card">'+
      '<div class="ord-sum-icon green"><i class="fas fa-dollar-sign"></i></div>'+
      '<div class="ord-sum-body">'+
        '<div class="ord-sum-val income">$'+income.toLocaleString('es-CL')+'</div>'+
        '<div class="ord-sum-label">Ingresos del día</div>'+
        (payPills?'<div class="ord-pay-pills">'+payPills+'</div>':'')+
      '</div>'+
    '</div>'+
    '<div class="ord-sum-card">'+
      '<div class="ord-sum-icon blue"><i class="fas fa-shopping-bag"></i></div>'+
      '<div class="ord-sum-body">'+
        '<div class="ord-sum-val">'+total+'</div>'+
        '<div class="ord-sum-label">Pedidos totales</div>'+
      '</div>'+
    '</div>'+
    '<div class="ord-sum-card">'+
      '<div class="ord-sum-icon amber"><i class="fas fa-clock"></i></div>'+
      '<div class="ord-sum-body">'+
        '<div class="ord-sum-val">'+pending+'</div>'+
        '<div class="ord-sum-label">Pendientes / En proceso</div>'+
      '</div>'+
    '</div>'+
    '<div class="ord-sum-card">'+
      '<div class="ord-sum-icon red"><i class="fas fa-times-circle"></i></div>'+
      '<div class="ord-sum-body">'+
        '<div class="ord-sum-val">'+cancelled+'</div>'+
        '<div class="ord-sum-label">Cancelados / Fallidos</div>'+
      '</div>'+
    '</div>'+
  '</div>';
}

function renderOrdersTable(orders,container,skipSummary){
  if(!orders||!orders.length){
    var summaryHtml=(!skipSummary&&_ordDataCache.length)?_renderOrdSummary(_ordDataCache):'';
    container.innerHTML=summaryHtml+'<div class="ord-empty"><i class="fas fa-inbox"></i><p>No hay pedidos'+(skipSummary?'':' para esta fecha')+'</p></div>';
    return;
  }
  orders.sort(function(a,b){return new Date(b.createdAt)-new Date(a.createdAt);});
  var rows=orders.map(function(o){
    var st=o.status||'pending';
    var time=o.createdAt?new Date(o.createdAt).toLocaleTimeString('es-CL',{hour:'2-digit',minute:'2-digit'}):'—';
    var total='$'+Math.round(o.total||0).toLocaleString('es-CL');
    var payIcon=_ordPayIcons[o.payment]||'💳';
    var payLabel=_ordPayLabels[o.payment]||o.payment||'—';
    return '<tr>'+
      '<td><strong style="font-family:monospace;font-size:12px">#'+esc(o.id)+'</strong></td>'+
      '<td>'+esc(o.customer&&o.customer.name||'—')+'<br><span style="font-size:11px;color:var(--muted)">'+esc(o.customer&&o.customer.phone||'')+'</span></td>'+
      '<td><strong>'+total+'</strong></td>'+
      '<td>'+payIcon+' <span style="font-size:12px">'+esc(payLabel)+'</span></td>'+
      '<td><span class="ord-status '+st+'">'+esc(_ordStatusLabels[st]||st)+'</span></td>'+
      '<td style="color:var(--muted);font-size:12px;white-space:nowrap">'+time+'</td>'+
      '<td><button class="btn-outline" style="padding:5px 12px;font-size:12px;white-space:nowrap" onclick="openOrdDetail(\''+esc(o.id)+'\')"><i class="fas fa-eye"></i> Ver</button></td>'+
    '</tr>';
  }).join('');
  var summaryHtml=skipSummary?'':_renderOrdSummary(_ordDataCache.length?_ordDataCache:orders);
  container.innerHTML=summaryHtml+
    '<div class="ord-table-wrap"><table class="ord-table">'+
    '<thead><tr><th>#Pedido</th><th>Cliente</th><th>Total</th><th>Pago</th><th>Estado</th><th>Hora</th><th></th></tr></thead>'+
    '<tbody>'+rows+'</tbody>'+
  '</table></div>';
}

function openOrdDetail(orderId){
  var modal=document.getElementById('ordModal');
  var box=document.getElementById('ordModalContent');
  if(!modal||!box)return;
  modal.classList.add('open');
  box.innerHTML='<div style="padding:48px;text-align:center"><i class="fas fa-spinner fa-spin" style="font-size:28px;color:var(--muted)"></i></div>';
  var token='';try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  fetch(API_BASE+'/api/order/'+encodeURIComponent(orderId),{headers:token?{'Authorization':'Bearer '+token}:{}})
  .then(function(r){return r.json();})
  .then(function(d){
    if(!d.ok||!d.order){box.innerHTML='<div style="padding:24px;color:var(--red)">Error al cargar el pedido.</div>';return;}
    renderOrdDetail(d.order,box);
  })
  .catch(function(){box.innerHTML='<div style="padding:24px;color:var(--red)">Sin conexión con el servidor.</div>';});
}

function closeOrdModal(){
  var m=document.getElementById('ordModal');
  if(m)m.classList.remove('open');
}

var _ST_TRANSITIONS={pending:['paid','payment_pending','payment_failed','cancelled'],payment_pending:['paid','payment_failed','cancelled','pending'],payment_failed:['payment_pending','cancelled'],paid:['shipped','cancelled'],shipped:['delivered','cancelled'],delivered:[],cancelled:[]};
var _ST_LABELS={pending:'Pendiente',payment_pending:'Pago en proceso',payment_failed:'Pago fallido',paid:'Pagado',shipped:'Enviado',delivered:'Entregado',cancelled:'Cancelado'};
var _ST_COLORS={pending:'#f59e0b',payment_pending:'#3b82f6',payment_failed:'#ef4444',paid:'#10b981',shipped:'#6366f1',delivered:'#059669',cancelled:'#6b7280'};

function _ordStatusBtns(o){
  var transitions=_ST_TRANSITIONS[o.status]||[];
  if(!transitions.length) return '';
  var btns=transitions.map(function(s){
    var bg=_ST_COLORS[s]||'#888';
    return '<button onclick="changeOrdStatus(\''+esc(o.id)+'\',\''+s+'\')" style="background:'+bg+';color:#fff;border:none;padding:8px 16px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;display:inline-flex;align-items:center;gap:6px">'+esc(_ST_LABELS[s]||s)+'</button>';
  }).join('');
  return '<div style="padding:16px 24px;border-top:1px solid var(--line);background:var(--surface)"><div style="font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:10px">Cambiar estado del pedido</div><div style="display:flex;flex-wrap:wrap;gap:8px">'+btns+'</div></div>';
}

function changeOrdStatus(orderId, newStatus){
  var token=''; try{token=sessionStorage.getItem('mx_admin_token')||'';}catch(e){}
  if(!token){showToast('Sesión expirada','error');return;}
  fetch(API_BASE+'/api/admin/order/'+encodeURIComponent(orderId)+'/status',{
    method:'PATCH',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify({status:newStatus})
  }).then(function(r){return r.json();}).then(function(d){
    if(d.ok){
      showToast('Estado actualizado: '+(_ST_LABELS[newStatus]||newStatus)+' ✓');
      closeOrdModal();
      loadOrders();
    } else {
      showToast(d.error||'Error al actualizar estado','error');
    }
  }).catch(function(){showToast('Error de conexión','error');});
}

function renderOrdDetail(o,box){
  var st=o.status||'pending';
  var payLabel=_ordPayLabels[o.payment]||o.payment||'—';
  var payIcon=_ordPayIcons[o.payment]||'💳';
  var createdAt=o.createdAt?new Date(o.createdAt).toLocaleString('es-CL',{dateStyle:'medium',timeStyle:'short'}):'—';
  var total='$'+Math.round(o.total||0).toLocaleString('es-CL');
  var storeWa=(gc('phone')||'+56977462964').replace(/\D/g,'');
  var custPhone=(o.customer&&o.customer.phone||'').replace(/\D/g,'');
  if(custPhone&&custPhone.length===9)custPhone='56'+custPhone; // añade prefijo CL si falta
  var contactWa=custPhone||storeWa; // usa teléfono del cliente; fallback a la tienda
  var itemsHtml=(o.items||[]).map(function(i){
    return '<div class="ord-item-row">'+
      (i.img?'<img class="ord-item-img" src="'+esc(i.img)+'" onerror="this.style.display=\'none\'" alt="">':'')+
      '<div style="flex:1;min-width:0"><div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(i.name||'—')+'</div>'+
      '<div style="color:var(--muted);font-size:11.5px;margin-top:2px">Cant: '+i.qty+' · $'+Math.round(i.price||0).toLocaleString('es-CL')+' c/u</div></div>'+
      '<div style="font-weight:700;white-space:nowrap">$'+Math.round((i.price||0)*(i.qty||1)).toLocaleString('es-CL')+'</div>'+
    '</div>';
  }).join('');
  var waMsg=encodeURIComponent('Hola! Te contactamos sobre tu pedido #'+o.id+' en Maxicompra. ');
  box.innerHTML=
    '<div class="ord-modal-head">'+
      '<div><div style="font-family:monospace;font-size:11px;color:var(--muted);margin-bottom:2px">Pedido #'+esc(o.id)+'</div>'+
      '<h3 style="margin:0;font-size:18px">Detalle del pedido</h3></div>'+
      '<button onclick="closeOrdModal()" style="background:none;border:none;font-size:22px;color:var(--muted);cursor:pointer;padding:0 4px;line-height:1"><i class="fas fa-times"></i></button>'+
    '</div>'+
    '<div class="ord-detail-grid">'+
      '<div class="ord-detail-cell"><div class="ord-dc-label">Cliente</div><div class="ord-dc-value">'+esc(o.customer&&o.customer.name||'—')+'</div></div>'+
      '<div class="ord-detail-cell"><div class="ord-dc-label">Teléfono</div><div class="ord-dc-value">'+esc(o.customer&&o.customer.phone||'—')+'</div></div>'+
      '<div class="ord-detail-cell" style="grid-column:span 2"><div class="ord-dc-label">Dirección</div><div class="ord-dc-value" style="font-size:13px">'+esc(o.customer&&o.customer.address||'—')+'</div></div>'+
      '<div class="ord-detail-cell"><div class="ord-dc-label">Método de pago</div><div class="ord-dc-value">'+payIcon+' '+esc(payLabel)+'</div></div>'+
      '<div class="ord-detail-cell"><div class="ord-dc-label">Estado</div><div class="ord-dc-value"><span class="ord-status '+st+'">'+esc(_ordStatusLabels[st]||st)+'</span></div></div>'+
      '<div class="ord-detail-cell"><div class="ord-dc-label">Fecha</div><div class="ord-dc-value" style="font-size:12.5px">'+createdAt+'</div></div>'+
      '<div class="ord-detail-cell"><div class="ord-dc-label">Total</div><div class="ord-dc-value" style="font-size:20px;color:var(--accent)">'+total+'</div></div>'+
    '</div>'+
    '<div style="padding:0 24px;font-weight:700;font-size:13px;margin-bottom:10px">Productos ('+(o.items||[]).length+')</div>'+
    '<div class="ord-items-list">'+itemsHtml+'</div>'+
    _ordStatusBtns(o)+
    '<div class="ord-modal-foot">'+
      '<a href="https://wa.me/'+contactWa+'?text='+waMsg+'" target="_blank" rel="noopener" class="btn-grad" style="padding:10px 20px;font-size:13px;text-decoration:none;border-radius:8px"><i class="fab fa-whatsapp"></i> Contactar cliente</a>'+
      '<button onclick="closeOrdModal()" class="btn-outline" style="padding:10px 20px;font-size:13px">Cerrar</button>'+
    '</div>';
}
