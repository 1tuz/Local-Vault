'use strict';
const $ = id => document.getElementById(id);
const state = { entries: [], filter: 'all', search: '', selected: null, edit: null, versions: [], revealed: false, isNew: false };
const kinds = {
  all: ['Все записи','grid'], secret: ['Пароли и секреты','key'], ssh: ['SSH-ключи','terminal'],
  kubeconfig: ['Kubeconfig','box'], api: ['API-ключи','nodes'], env: ['Переменные .env','sliders'], file: ['Файлы','file']
};
let toastTimer = null;

function h(value) { return String(value ?? '').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function icon(name) {
  const paths={
    grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    key:'<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9m-3 3 3 3m-6 0 3 3"/>',
    terminal:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    box:'<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 8 9 5 9-5m-18 0v9l9 5 9-5V8m-9 5v9"/>',
    nodes:'<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="m8.2 10.8 7.5-3.6m-7.5 6 7.5 3.6"/>',
    sliders:'<path d="M4 6h9m4 0h3M4 12h3m4 0h9M4 18h9m4 0h3"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="15" cy="18" r="2"/>',
    file:'<path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10Z"/><path d="M13 3v7h7m-11 4h6m-6 4h6"/>',
    vault:'<rect x="3" y="3" width="18" height="18" rx="4"/><circle cx="12" cy="12" r="5"/><path d="M12 7v2m5 3h-2m-3 5v-2m-5-3h2"/>',
    search:'<circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/>',
    import:'<path d="M12 15V3m-5 5 5-5 5 5M4 14v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5"/>',
    export:'<path d="M12 9v12m-5-5 5 5 5-5M4 10V5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v5"/>',
    audit:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    lock:'<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3m-4 4v3"/>',
    theme:'<circle cx="12" cy="12" r="9"/><path d="M12 3v18a9 9 0 0 0 0-18Z"/>',
    sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/>',
    moon:'<path d="M20.9 13A9 9 0 0 1 11 3.1 9 9 0 1 0 20.9 13Z"/>',
    'arrow-right':'<path d="M5 12h14m-6-6 6 6-6 6"/>',
    eye:'<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    'eye-off':'<path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a15 15 0 0 1-3.1 3.8M6.2 6.2C3.5 8 2 12 2 12s3.6 7 10 7a10.8 10.8 0 0 0 4-.8"/>',
    copy:'<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>'
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name]}</svg>`;
}
function applyStaticIcons() { document.querySelectorAll('[data-icon]').forEach(el=>{el.innerHTML=icon(el.dataset.icon);}); }
function toast(message, isError=false) {
  const el=$('toast'); el.textContent=message; el.style.background=isError?'#a84e54':'';el.classList.remove('hidden');
  clearTimeout(toastTimer); toastTimer=setTimeout(()=>{el.classList.add('hidden');el.style.background='';},3600);
}
async function api(url, options={}) {
  const payload=options.body?JSON.parse(options.body):undefined;
  let data;
  try {
    data=await window.__TAURI__.core.invoke('api_request',{
      path:url,method:options.method||'GET',payload
    });
  } catch(error) {
    if(typeof error==='string' && error==='Vault is locked' && !url.includes('unlock') && !url.includes('setup')) showAuth(false);
    throw new Error(typeof error==='string'?error:'Операция не выполнена');
  }
  if(options.binary) return new Blob([data.content],{type:'application/octet-stream'});
  return data;
}
function setTheme(theme) {document.documentElement.dataset.theme=theme;localStorage.setItem('lv-theme',theme);const label=theme==='dark'?'Светлая тема':'Тёмная тема';const action=theme==='dark'?'светлую тему':'тёмную тему';for(const id of ['themeBtn','authThemeBtn']){const button=$(id);if(button){button.title=`Включить ${action}`;button.setAttribute('aria-label',`Включить ${action}`);}}const authIcon=$('authThemeBtn')?.querySelector('[data-icon]');if(authIcon){authIcon.innerHTML=icon(theme==='dark'?'sun':'moon');$('authThemeLabel').textContent=label;}}
function showAuth(setup) {
  $('authScreen').classList.remove('hidden');$('vaultScreen').classList.add('hidden');
  $('confirmRow').classList.toggle('hidden',!setup); $('masterPassword').value='';$('confirmPassword').value='';
  $('masterPassword').autocomplete=setup?'new-password':'current-password';
  $('authSubmit').innerHTML=setup?'Создать хранилище <span data-icon="arrow-right"></span>':'Открыть хранилище <span data-icon="arrow-right"></span>';
  applyStaticIcons();
  setTheme(document.documentElement.dataset.theme||'light');
  $('authHint').textContent=setup?'Пароль не восстанавливается. Минимум 12 символов.':'Все данные остаются в зашифрованном файле на устройстве.';
  $('authError').classList.add('hidden');state.authMode=setup?'setup':'unlock';
}
async function bootstrap() {
  setTheme(localStorage.getItem('lv-theme')||'light');
  try {const s=await api('/api/status');
    if(s.unlocked) {try {await openApp();return;} catch{ /* another browser without session */ }}
    showAuth(!s.exists);
  }catch(e){showAuth(false);$('authError').textContent=e.message;$('authError').classList.remove('hidden');}
}
async function openApp() {
  $('authScreen').classList.add('hidden');$('vaultScreen').classList.remove('hidden');
  await refresh();
}
function renderNav(){
  const nav=$('navCategories');nav.replaceChildren();
  for(const [k,[label,iconName]] of Object.entries(kinds)) {
    const count=k==='all'?state.entries.length:state.entries.filter(e=>e.kind===k).length;
    const btn=document.createElement('button');btn.type='button';btn.className='nav-link'+(state.filter===k?' active':'');
    const ic=document.createElement('span');ic.className='nav-icon';ic.innerHTML=icon(iconName);
    const text=document.createElement('span');text.textContent=label;
    const amount=document.createElement('span');amount.className='count';amount.textContent=String(count);
    btn.append(ic,text,amount);btn.addEventListener('click',()=>{state.filter=k;renderNav();renderList();});nav.append(btn);
  }
}
function renderList(){
  const display=(kinds[state.filter]||kinds.all)[0];$('sectionName').textContent=display;$('pageTitle').textContent=display;
  const query=state.search.toLocaleLowerCase('ru');
  const entries=state.entries.filter(e=>(state.filter==='all'||e.kind===state.filter)&&
    (`${e.name} ${e.folder}`.toLocaleLowerCase('ru').includes(query)));
  $('countLabel').textContent=`ЗАПИСИ · ${entries.length}`;
  const list=$('entryList');list.replaceChildren();
  if(!entries.length){const empty=document.createElement('div');empty.className='empty-list';empty.textContent='Записей пока нет';list.append(empty);}
  for(const e of entries) {
    const b=document.createElement('button');b.className='entry-card'+(e.id===state.selected?' selected':'');b.type='button';
    const kindIcon=document.createElement('span');kindIcon.className='kind-icon '+e.kind;kindIcon.innerHTML=icon(kinds[e.kind]?.[1]||'box');
    const summary=document.createElement('span');summary.className='entry-summary';
    const title=document.createElement('b');title.textContent=e.name;
    const small=document.createElement('small');small.textContent=(e.folder?e.folder+' · ':'')+(kinds[e.kind]?.[0]||e.kind);summary.append(title,small);
    const v=document.createElement('span');v.className='entry-version';v.textContent='v'+e.current_version;
    b.append(kindIcon,summary,v);b.addEventListener('click',()=>selectEntry(e.id));list.append(b);
  }
}
async function refresh(){const data=await api('/api/entries');state.entries=data.entries;renderNav();renderList();}
function clearDetail(){state.selected=null;state.edit=null;state.versions=[];state.isNew=false;state.revealed=false;
  $('detailPane').innerHTML=`<div class="blank-state"><div class="blank-symbol">${icon('vault')}</div><h2>Выберите запись</h2><p>Содержимое доступно только после открытия записи в этой панели.</p></div>`;renderList();}
async function selectEntry(id){
  try{const [entry,versions]=await Promise.all([api('/api/entries/'+encodeURIComponent(id)),api('/api/entries/'+encodeURIComponent(id)+'/versions')]);
    state.selected=id;state.edit=entry;state.versions=versions.versions;state.isNew=false;state.revealed=false;renderDetail();renderList();}
  catch(e){toast(e.message,true);}
}
function newEntry(){state.selected=null;state.isNew=true;state.revealed=true;state.versions=[];
  state.edit={name:'',folder:'',kind:'secret',encoding:'utf-8',content:'',agent_allowed:false,metadata:{}};
  renderDetail();renderList();$('input[name="name"]')?.focus();}
function visibleFor(k){$('sshFields').classList.toggle('hidden',k!=='ssh');$('apiFields').classList.toggle('hidden',k!=='api');
$('fileRow').classList.toggle('hidden',k!=='file');
}
function renderDetail(){
  const e=state.edit;if(!e)return clearDetail();const isNew=state.isNew;
  const panel=$('detailPane');
  panel.innerHTML=`<form id="entryForm" class="detail-content">
    <div class="detail-head"><div><span class="label-chip">${isNew?'НОВАЯ ЗАПИСЬ':'ЗАЩИЩЁННАЯ ЗАПИСЬ'}</span>
      <h2>${isNew?'Создать секрет':h(e.name)}</h2><p class="muted">${isNew?'Добавление в локальную зашифрованную базу':`Последняя версия · v${e.current_version}`}</p></div>
      ${isNew?'':'<span class="entry-version">ИСТОРИЯ ВЕРСИЙ</span>'}
    </div>
    <h3 class="section-heading">ОСНОВНАЯ ИНФОРМАЦИЯ</h3>
    <div class="editor-grid">
      <div class="field wide"><label for="entryName">Название</label><input id="entryName" name="name" maxlength="120" required /></div>
      <div class="field"><label for="entryKind">Тип секрета</label><select id="entryKind" name="kind">
        ${Object.entries(kinds).filter(([k])=>k!=='all').map(([k,v])=>`<option value="${k}">${h(v[0])}</option>`).join('')}</select></div>
      <div class="field"><label for="entryFolder">Папка / группа</label><input id="entryFolder" name="folder" maxlength="160" placeholder="Личное / Работа" /></div>
    </div>
    <div id="sshFields" class="editor-grid hidden"><div class="field wide"><h3 class="section-heading">SSH-ПОДКЛЮЧЕНИЕ</h3></div>
      <div class="field"><label for="sshHost">Хост</label><input id="sshHost" placeholder="example.org" /></div>
      <div class="field"><label for="sshUser">Пользователь</label><input id="sshUser" placeholder="deploy" /></div>
      <div class="field"><label for="sshPort">Порт</label><input id="sshPort" type="number" min="1" max="65535" value="22" /></div>
      <div class="field"><label for="sshPassphrase">Пароль ключа (необязательно)</label><input id="sshPassphrase" type="password" autocomplete="off" /></div></div>
    <div id="apiFields" class="editor-grid hidden"><div class="field wide"><h3 class="section-heading">ПАРАМЕТРЫ API</h3></div>
      <div class="field wide"><label for="apiBase">Адрес HTTPS API</label><input id="apiBase" placeholder="https://api.example.org/v1" /></div>
      <div class="field"><label for="apiMethods">Разрешённые методы</label><input id="apiMethods" placeholder="GET" /></div>
      <div class="field"><label for="apiHeader">Заголовок</label><select id="apiHeader"><option>Authorization</option><option>X-API-Key</option><option>X-Auth-Token</option></select></div>
      <div class="field wide"><label for="apiPrefix">Префикс ключа в заголовке</label><input id="apiPrefix" placeholder="Bearer " /></div></div>
    <h3 class="section-heading">ЗАШИФРОВАННОЕ ЗНАЧЕНИЕ</h3>
    <div class="field wide"><div class="secret-field-heading"><label for="entryContent">Содержимое ${e.encoding==='base64'?'(Base64)':''}</label>
      <div class="secret-actions">
        ${e.encoding==='base64'?'':'<button type="button" class="secret-icon-button" id="copyBtn" aria-label="Скопировать значение" title="Скопировать значение">'+icon('copy')+'</button>'}
        <button type="button" class="secret-icon-button" id="revealBtn" aria-label="${state.revealed?'Скрыть':'Показать'} значение" title="${state.revealed?'Скрыть':'Показать'} значение" aria-pressed="${state.revealed}">${icon(state.revealed?'eye-off':'eye')}</button>
      </div></div>
      <textarea id="entryContent" spellcheck="false" autocomplete="off" ${state.revealed?'':'disabled'}></textarea>
      <span class="hint">При сохранении создаётся следующая версия. Значение не попадает в список записей.</span></div>
    <div id="fileRow" class="hidden"><p class="hint">Файлы хранятся как двоичные данные. Выберите файл, затем сохраните запись.</p>
      <input id="attachmentInput" type="file" /><span id="fileName" class="hint"></span></div>
    <div class="action-row"><button class="btn primary" type="submit">Сохранить ${isNew?'запись':'новую версию'}</button>
      ${isNew?'':'<button class="btn danger" type="button" id="deleteBtn">Удалить</button>'}<span class="spacer"></span></div>
    ${isNew?'':`<h3 class="section-heading">ИСТОРИЯ ИЗМЕНЕНИЙ</h3><div id="versionList" class="versions-table"></div>
      <div class="soft-alert">Откат создаёт новую версию с выбранным содержимым. Предыдущие версии сохраняются.</div>`}
  </form>`;
  $('entryName').value=e.name;$('entryFolder').value=e.folder;$('entryKind').value=e.kind;
  $('entryContent').value=state.revealed?e.content:'••••••••••••••••';
  const meta=e.metadata||{};
  $('sshHost').value=meta.host||'';$('sshUser').value=meta.user||'';$('sshPort').value=meta.port||22;$('sshPassphrase').value=meta.passphrase||'';
  $('apiBase').value=meta.base_url||'';$('apiMethods').value=meta.methods||'GET';$('apiHeader').value=meta.header_name||'Authorization';
  $('apiPrefix').value=meta.header_prefix===undefined?'Bearer ':meta.header_prefix;
  visibleFor(e.kind);
  $('entryKind').addEventListener('change',ev=>visibleFor(ev.target.value));
  $('revealBtn').addEventListener('click',()=>{
    if(state.revealed){state.edit.content=$('entryContent').value;state.revealed=false;$('entryContent').value='••••••••••••••••';$('entryContent').disabled=true;}
    else{state.revealed=true;$('entryContent').disabled=false;$('entryContent').value=state.edit.content;}
    const button=$('revealBtn');
    button.setAttribute('aria-label',(state.revealed?'Скрыть':'Показать')+' значение');
    button.title=(state.revealed?'Скрыть':'Показать')+' значение';
    button.setAttribute('aria-pressed',String(state.revealed));
    button.innerHTML=icon(state.revealed?'eye-off':'eye');
  });
  $('copyBtn')?.addEventListener('click',async()=>{
    try {
      const value=state.revealed?$('entryContent').value:state.edit.content;
      await navigator.clipboard.writeText(value);
      toast('Значение скопировано');
    } catch { toast('Не удалось скопировать. Проверьте разрешение на буфер обмена.',true); }
  });
  $('entryForm').addEventListener('submit',saveForm);
  $('attachmentInput').addEventListener('change',async ev=>{
    const f=ev.target.files[0];if(!f)return;if(f.size>1024*1024){toast('Размер файла ограничен 1 МиБ',true);return;}
    const bytes=new Uint8Array(await f.arrayBuffer());let raw='';for(let i=0;i<bytes.length;i+=8192)raw+=String.fromCharCode(...bytes.subarray(i,i+8192));
    state.edit.content=btoa(raw);state.edit.encoding='base64';state.edit.metadata.filename=f.name;
    $('copyBtn')?.remove();$('entryContent').labels[0].textContent='Содержимое (Base64)';
    if(!state.revealed)$('revealBtn').click();
    else $('entryContent').value=state.edit.content;
    $('fileName').textContent=f.name+' · '+f.size+' байт';
  });
  if(!isNew){$('deleteBtn').addEventListener('click',deleteEntry);renderVersions();}
}
function getValues(){
  const kind=$('entryKind').value;
  const meta={...(state.edit.metadata||{})};
  if(kind==='ssh'){meta.host=$('sshHost').value.trim();meta.user=$('sshUser').value.trim();meta.port=Number($('sshPort').value)||22;
    meta.passphrase=$('sshPassphrase').value;}
  else if(kind==='api'){meta.base_url=$('apiBase').value.trim();meta.methods=$('apiMethods').value.trim().toUpperCase();
    meta.header_name=$('apiHeader').value;meta.header_prefix=$('apiPrefix').value;}
  else{delete meta.host;delete meta.user;delete meta.port;delete meta.passphrase;delete meta.base_url;
       delete meta.methods;delete meta.header_name;delete meta.header_prefix;}
  const content=state.revealed?$('entryContent').value:state.edit.content;
  return {name:$('entryName').value.trim(),folder:$('entryFolder').value.trim(),kind,content,
    encoding:state.edit.encoding,metadata:meta,agent_allowed:false};
}
async function saveForm(event){event.preventDefault();try{
  const val=getValues();if(!val.name){toast('Укажите название',true);return;}
  if(val.kind==='ssh' && (!val.metadata.host||!val.metadata.user)){toast('Укажите SSH-хост и пользователя',true);return;}
  if(val.kind==='api' && !val.metadata.base_url){toast('Укажите HTTPS API',true);return;}
  const id=state.selected;
  const result=await api(id?'/api/entries/'+encodeURIComponent(id):'/api/entries',
                         {method:id?'PUT':'POST',body:JSON.stringify(val)});
  toast(id?'Создана новая версия':'Запись сохранена');await refresh();await selectEntry(result.id);
}catch(e){toast(e.message,true);}}
async function deleteEntry(){if(!confirm('Удалить эту запись и всю историю без возможности отката?'))return;
  try{await api('/api/entries/'+encodeURIComponent(state.selected),{method:'DELETE'});clearDetail();await refresh();toast('Запись удалена');}
  catch(e){toast(e.message,true);}}
function renderVersions(){
  const div=$('versionList');if(!div)return;div.replaceChildren();
  for(const v of state.versions){
    const row=document.createElement('div');row.className='version-line';
    const text=document.createElement('div');const b=document.createElement('b');b.textContent='Версия '+v.version+(v.version===state.edit.current_version?' · текущая':'');
    const small=document.createElement('small');small.textContent=v.created_at+(v.note?' · '+v.note:'')+' · '+v.bytes+' байт';text.append(b,small);
    const actions=document.createElement('div');const view=document.createElement('button');view.className='btn small';view.type='button';view.textContent='Открыть';
    view.addEventListener('click',async()=>{try{const data=await api('/api/entries/'+state.selected+'/versions/'+v.version);
      const old=row.querySelector('pre');if(old){old.remove();return;}const pre=document.createElement('pre');pre.className='version-preview';
      pre.style.cssText='width:100%;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px;padding:12px;background:var(--panel2);border-radius:7px';
      pre.textContent=data.content;row.style.flexWrap='wrap';row.append(pre);
    }catch(e){toast(e.message,true);}});actions.append(view);
    if(v.version!==state.edit.current_version){const revert=document.createElement('button');revert.className='btn small';revert.type='button';revert.textContent='Откат';
      revert.addEventListener('click',async()=>{if(!confirm(`Создать новую версию из версии ${v.version}?`))return;
        try{await api('/api/entries/'+state.selected+'/rollback',{method:'POST',body:JSON.stringify({version:v.version})});
          toast('Версия восстановлена');await refresh();await selectEntry(state.selected);}
        catch(e){toast(e.message,true);}});actions.append(revert);}
    row.append(text,actions);div.append(row);
  }
}
async function exportVault(){if(!confirm('Экспорт создаст НЕЗАШИФРОВАННЫЙ файл со всеми секретами. Продолжить?'))return;
  const fmt=prompt('Формат экспорта: yaml или json','yaml');if(!fmt)return;if(!['yaml','json'].includes(fmt)){toast('Доступны YAML и JSON',true);return;}
  try{const saved=await window.__TAURI__.core.invoke('export_file',{format:fmt});
    if(saved)toast('Экспорт сохранён в открытом виде');}
  catch(e){toast(e.message,true);}}
async function importVault(ev){const f=ev.target.files[0];ev.target.value='';if(!f)return;if(f.size>4*1024*1024){toast('Файл импорта превышает 4 МиБ',true);return;}
  if(!confirm('Импорт добавит записи из файла. Существующие записи не будут заменены. Продолжить?'))return;
  try{const fmt=f.name.toLowerCase().endsWith('.json')?'json':'yaml';
    const result=await api('/api/import',{method:'POST',body:JSON.stringify({format:fmt,data:await f.text()})});
    await refresh();toast('Импортировано записей: '+result.imported);
  }catch(e){toast(e.message,true);}}
async function showAudit(){
  try{const audit=await api('/api/audit');state.selected=null;state.edit=null;renderList();
    $('detailPane').innerHTML=`<div class="detail-content"><div class="eyebrow">ИСТОРИЯ ОПЕРАЦИЙ</div><h2>Журнал действий</h2>
      <p class="muted">Содержимое секретов никогда не пишется в журнал.</p><div id="auditLog"></div></div>`;
    const log=$('auditLog');for(const item of audit.events){const line=document.createElement('div');line.className='audit-line';
      const name=document.createElement('span');name.textContent=({save:'Сохранение',delete:'Удаление',import:'Импорт'})[item.event]||item.event;
      const date=document.createElement('small');date.textContent=item.at;line.append(name,date);log.append(line);}
  }catch(e){toast(e.message,true);}}

applyStaticIcons();
$('authForm').addEventListener('submit',async ev=>{ev.preventDefault();const pass=$('masterPassword').value;
  if(state.authMode==='setup'&&pass!==$('confirmPassword').value){$('authError').textContent='Пароли не совпадают';$('authError').classList.remove('hidden');return;}
  $('authSubmit').disabled=true;
  try{await api(state.authMode==='setup'?'/api/setup':'/api/unlock',{method:'POST',body:JSON.stringify({password:pass})});
    $('masterPassword').value='';$('confirmPassword').value='';await openApp();}
  catch(e){$('authError').textContent=e.message;$('authError').classList.remove('hidden');}
  finally{$('authSubmit').disabled=false;}
});
$('newBtn').addEventListener('click',newEntry);
$('searchInput').addEventListener('input',e=>{state.search=e.target.value;renderList();});
for(const id of ['themeBtn','authThemeBtn'])$(id).addEventListener('click',()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));
$('lockBtn').addEventListener('click',async()=>{try{await api('/api/lock',{method:'POST'});state.entries=[];clearDetail();showAuth(false);}catch(e){toast(e.message,true);}});
$('exportBtn').addEventListener('click',exportVault);
$('importBtn').addEventListener('click',()=>$('importInput').click());
$('importInput').addEventListener('change',importVault);
$('auditBtn').addEventListener('click',showAudit);
bootstrap();
