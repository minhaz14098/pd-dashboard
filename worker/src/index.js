const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,PUT,OPTIONS","Access-Control-Allow-Headers":"Content-Type,Authorization","Cache-Control":"no-store"};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{...cors,"Content-Type":"application/json; charset=utf-8"}});
const enc=s=>new TextEncoder().encode(s), b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const norm=e=>String(e||"").trim().toLowerCase(), now=()=>new Date().toISOString();
async function digest(s){return b64(await crypto.subtle.digest("SHA-256",enc(s)))}
async function passHash(p,s){const k=await crypto.subtle.importKey("raw",enc(p),"PBKDF2",false,["deriveBits"]);return b64(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:enc(s),iterations:210000},k,256))}
async function sign(payload,secret){const body=b64(enc(JSON.stringify(payload))),key=await crypto.subtle.importKey("raw",enc(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return body+"."+b64(await crypto.subtle.sign("HMAC",key,enc(body)))}
async function verify(token,secret){try{const [body]=token.split("."),payload=JSON.parse(atob(body.replace(/-/g,"+").replace(/_/g,"/")));return await sign(payload,secret)===token&&payload.exp>Date.now()?payload:null}catch{return null}}
async function sendCode(env,email,code){if(!env.RESEND_API_KEY||!env.MAIL_FROM)throw Error("Email sender is not configured");const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.MAIL_FROM,to:[email],subject:"PD Dashboard verification code",text:"Your code is "+code+". It expires in 10 minutes."})});if(!r.ok)throw Error("Email delivery failed")}
async function issueCode(env,user,purpose,email){const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,"0");await env.BD.prepare("INSERT INTO otp_codes (user_id,otp_hash,purpose,expires_at,attempts,used,created_at) VALUES (?,?,?,?,0,0,?)").bind(user.user_id,await digest(code),purpose,new Date(Date.now()+600000).toISOString(),now()).run();await sendCode(env,email,code)}
async function auth(request,env,path){if(!env.BD||!env.AUTH_SECRET)return json({error:"Authentication is not configured"},503);if(path==="/api/auth/logout"){const token=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");if(token)await env.BD.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();return json({ok:true})}let d;try{d=await request.json()}catch{return json({error:"Invalid JSON"},400)}const email=norm(d.email);if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json({error:"Enter a valid email"},400);
if(path==="/api/auth/setup"){if(!env.SETUP_KEY||d.setupKey!==env.SETUP_KEY)return json({error:"Setup key is incorrect"},403);if(String(d.password||"").length<12)return json({error:"Use at least 12 characters"},400);const count=await env.BD.prepare("SELECT COUNT(*) AS n FROM users").first();if(count?.n>0)return json({error:"Initial account already created"},409);const salt=b64(crypto.getRandomValues(new Uint8Array(16))),hash=await passHash(d.password,salt);await env.BD.prepare("INSERT INTO users (user_id,email,password_hash,is_active,two_factor_enabled,created_at) VALUES (?,?,?,?,?,?)").bind(email,email,salt+"."+hash,0,1,now()).run();const user={user_id:email};await issueCode(env,user,"setup",email);return json({ok:true,requiresOtp:true})}
if(path==="/api/auth/login"){const u=await env.BD.prepare("SELECT * FROM users WHERE email=? AND is_active=1").bind(email).first();const [salt,hash]=String(u?.password_hash||".").split(".");if(!u||await passHash(String(d.password||""),salt)!==hash)return json({error:"Email or password is incorrect"},401);await issueCode(env,u,"login",email);return json({ok:true,requiresOtp:true})}
if(path==="/api/auth/forgot"){const u=await env.BD.prepare("SELECT * FROM users WHERE email=? AND is_active=1").bind(email).first();if(u)await issueCode(env,u,"reset",email);return json({ok:true})}
if(path==="/api/auth/verify"||path==="/api/auth/reset"){const purpose=path.endsWith("/reset")?"reset":"login";const u=await env.BD.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!u)return json({error:"Code is invalid or expired"},400);let otp;if(path.endsWith("/verify")){otp=await env.BD.prepare("SELECT id,otp_hash,purpose FROM otp_codes WHERE user_id=? AND purpose IN ('setup','login') AND used=0 AND attempts<5 AND expires_at>? ORDER BY id DESC LIMIT 1").bind(u.user_id,now()).first()}else{otp=await env.BD.prepare("SELECT id,otp_hash,purpose FROM otp_codes WHERE user_id=? AND purpose='reset' AND used=0 AND attempts<5 AND expires_at>? ORDER BY id DESC LIMIT 1").bind(u.user_id,now()).first()}if(!otp)return json({error:"Code is invalid or expired"},400);const match=otp.otp_hash===await digest(String(d.code||""));await env.BD.prepare("UPDATE otp_codes SET attempts=attempts+1,used=? WHERE id=?").bind(match?1:0,otp.id).run();if(!match)return json({error:"Code is invalid or expired"},400);if(purpose==="reset"){if(String(d.password||"").length<12)return json({error:"Use at least 12 characters"},400);const salt=b64(crypto.getRandomValues(new Uint8Array(16))),hash=await passHash(d.password,salt);await env.BD.prepare("UPDATE users SET password_hash=? WHERE user_id=?").bind(salt+"."+hash,u.user_id).run();return json({ok:true})}if(otp.purpose==="setup")await env.BD.prepare("UPDATE users SET is_active=1 WHERE user_id=?").bind(u.user_id).run();if(!u.is_active&&otp.purpose!=="setup")return json({error:"Account is not active"},403);const token=await sign({sub:u.user_id,exp:Date.now()+28800000},env.AUTH_SECRET);await env.BD.prepare("INSERT INTO sessions (user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?)").bind(u.user_id,await digest(token),new Date(Date.now()+28800000).toISOString(),now()).run();return json({ok:true,token})}
if(path==="/api/auth/logout"){const token=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");if(token)await env.BD.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();return json({ok:true})}
return json({error:"Not found"},404)}
async function authenticated(request,env){const token=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");if(!token||!env.AUTH_SECRET||!env.BD)return null;const claims=await verify(token,env.AUTH_SECRET);if(!claims)return null;const row=await env.BD.prepare("SELECT user_id FROM sessions WHERE token_hash=? AND expires_at>?").bind(await digest(token),now()).first();return row?claims:null}
async function readCsv(url,label){if(!url)throw Error(label+" sheet URL missing");const r=await fetch(url,{headers:{Accept:"text/csv,text/plain,*/*"},cf:{cacheTtl:0,cacheEverything:false}});if(!r.ok)throw Error(label+" sheet returned HTTP "+r.status);const t=await r.text();if(!t.trim()||/^\s*<(?:!doctype|html)/i.test(t))throw Error(label+" sheet returned empty data or a sign-in page");retur…248151 tokens truncated…h>Handover</th></tr></thead><tbody>${c.months.map(m=>`<tr><td class="l"><b>${m.label}</b></td><td><b>${m.tp}</b></td><td>${m.ih}</td><td>${m.ho}</td></tr>`).join('')}</tbody></table></div>${c.peak?`<div class="peak">Peak month: ${c.peak.label} with ${c.peak.tp} TP received</div>`:''}</div>`);
  panels.push(`<div class="pn"><div class="kl">Lead time distribution</div>${vbar(c.buckets.map(b=>b.label),[{color:C1(),values:c.buckets.map(b=>b.n)}])}<table><thead><tr><th class="l">Range</th><th># Styles</th><th>Share</th></tr></thead><tbody>${c.buckets.map(b=>`<tr><td class="l">${b.label}</td><td><b>${b.n}</b></td><td>${(b.n/bt*100).toFixed(0)}%</td></tr>`).join('')}</tbody></table></div>`);
  panels.push(`<div class="pn"><div class="kl">Received vs on process</div><div style="text-align:center">${donut(c.received,c.onProcess)}</div></div>`);
  h+=`<div class="grid2">${panels.join('')}</div>`;
  const mk=state.month!==null&&c.months.some(m=>m.key===state.month)?state.month:(c.months.length?c.months[c.months.length-1].key:null);
  if(mk!==null){
    const w=weekly(c.recs,mk), tot=w.reduce((a,r)=>({tp:a.tp+r.tp,ih:a.ih+r.ih,ho:a.ho+r.ho}),{tp:0,ih:0,ho:0});
    h+=`<div class="kl" style="margin-top:18px">Weekly breakdown</div>
      <div class="noprint" style="margin-bottom:8px">Month <select id="wkMonth">${c.months.map(m=>`<option value="${m.key}" ${m.key===mk?'selected':''}>${m.label}</option>`).join('')}</select></div>
      <table><thead><tr><th class="l">Week</th><th>Date range</th><th>TP recv</th><th>In hand</th><th>Handover</th></tr></thead><tbody>
      ${w.map(r=>`<tr><td class="l"><b>${r.w}</b></td><td>${r.range}</td><td>${r.tp}</td><td>${r.ih}</td><td>${r.ho}</td></tr>`).join('')}
      <tr class="tot"><td class="l">TOTAL</td><td></td><td>${tot.tp}</td><td>${tot.ih}</td><td>${tot.ho}</td></tr></tbody></table>
      <div class="note">W1 is days 1 to 7, W2 is 8 to 14, W3 is 15 to 21, W4 is 22 to 28, W5 is 29 to month end.</div>`;
  }
  h+=`<div class="note">Source: ${esc(state.tracks.map(s=>s.name).join(', '))}. ${st.used} of ${st.read} rows used. Rows where In hand is earlier than TP received (${st.negative}) are left out of lead time figures. Unreadable dates ignored: ${st.badDates}.</div>`;
  dash.innerHTML=h; bindCost();
  const wm=$('#wkMonth'); if(wm) wm.onchange=e=>{ state.month=+e.target.value; render(); };
}

// ----- profiles -----
const LS_P='pd_dash_profiles_v1';
let profiles={list:[],active:''}, edit=null;
const uid=()=>'p'+Date.now().toString(36)+Math.floor(Math.random()*46656).toString(36);
const newProfile=()=>({id:'',name:'',designation:'',photo:'',adj:{x:0,y:0,z:100,r:0},view:'both',match:''});
const VIEW_LABEL={both:'Tracker and costing',tracker:'Tracker only',costing:'Costing only'};
function activeProfile(){ return profiles.list.find(p=>p.id===profiles.active)||profiles.list[0]||null; }
function saveProfiles(){ lsSet(LS_P,profiles); }
function initials(n){ const w=String(n||'').trim().split(/\s+/).filter(Boolean); if(!w.length) return '?'; return (w[0][0]+(w.length>1?w[w.length-1][0]:'')).toUpperCase(); }
const showT=()=>{ const p=activeProfile(); return !p||p.view!=='costing'; };
const showC=()=>{ const p=activeProfile(); return !p||p.view!=='tracker'; };
const matchOf=()=>{ const p=activeProfile(); return p&&p.match?p.match.trim().toLowerCase():''; };
function scopedRecs(){ const recs=state.built?state.built.records:[], m=matchOf(); if(!m||!recs.some(r=>r.owner)) return recs; return recs.filter(r=>(r.owner||'').toLowerCase().includes(m)); }
function scopedCostRecs(){ const recs=state.costBuilt?state.costBuilt.records:[], m=matchOf(); return m?recs.filter(r=>(r.owner||'').toLowerCase().includes(m)):recs; }
function avatarHTML(p,px,cls){
  const sz='width:'+px+'px;height:'+px+'px';
  if(p.photo){ const a=p.adj||{x:0,y:0,z:100,r:0}; return `<div class="av ${cls||''}" style="${sz}"><img src="${p.photo}" style="transform:translate(${a.x}%,${a.y}%) rotate(${a.r}deg) scale(${a.z/100})" alt=""></div>`; }
  return `<div class="av ${cls||''}" style="${sz};font-size:${Math.round(px*0.38)}px">${esc(initials(p.name))}</div>`;
}
function renderProfile(){
  const p=activeProfile(), el=$('#profileCard');
  if(!p){ el.innerHTML=''; return; }
  const tags=[`<span class="ptag">${VIEW_LABEL[p.view]||VIEW_LABEL.both}</span>`];
  if(p.match) tags.push(`<span class="ptag">Rows for: ${esc(p.match)}</span>`);
  if(p.match && showT() && state.built && !state.built.records.some(r=>r.owner)) tags.push(`<span class="ptag w">Tracker has no Owner / PD column, so tracker rows are not split by person</span>`);
  el.innerHTML=`<div class="cover"></div><div class="pbody">${avatarHTML(p,104,'big')}<div class="pinfo"><div class="pname">${esc(p.name)}</div><div class="pdesig">${esc(p.designation||'')}</div><div class="ptags">${tags.join('')}</div></div><div class="pbtns"><button class="btn" id="pbEdit">Edit profile</button><button class="btn" id="pbAdd">Add profile</button></div></div>`
    + (profiles.list.length>1?`<div class="pswitch"><span class="bl">Profiles</span>${profiles.list.map(x=>`<button class="chip ${x.id===p.id?'on':''}" data-id="${esc(x.id)}">${avatarHTML(x,28)}${esc(x.name)}</button>`).join('')}</div>`:'');
  $('#pbEdit').onclick=()=>openEditor(p.id); $('#pbAdd').onclick=()=>openEditor(null);
  el.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{ profiles.active=b.dataset.id; saveProfiles(); state.buyer='All'; state.owner='All'; state.year='All'; state.month=null; refreshAll(false); });
}
function paintPreview(){ $('#pePreview').innerHTML=''; const tmp=avatarHTML(edit,190,''); const d=document.createElement('div'); d.innerHTML=tmp; const inner=d.firstChild; $('#pePreview').innerHTML=inner.innerHTML; $('#pePreview').style.fontSize=Math.round(190*0.38)+'px'; }
function syncAdjInputs(){
  const a=edit.adj;
  [['X','x'],['Y','y'],['Z','z'],['R','r']].forEach(([k,f])=>{ $('#pe'+k).value=a[f]; $('#pe'+k+'n').value=a[f]; });
  [['X','x'],['Y','y'],['Z','z'],['R','r']].forEach(([k,f])=>{ $('#pe'+k).disabled=!edit.photo; $('#pe'+k+'n').disabled=!edit.photo; });
}
function openEditor(id){
  const p=id?profiles.list.find(x=>x.id===id):null;
  edit=p?JSON.parse(JSON.stringify(p)):newProfile();
  if(!edit.adj) edit.adj={x:0,y:0,z:100,r:0};
  $('#peTitle').textContent=p?'EDIT PROFILE':'ADD PROFILE';
  $('#peName').value=edit.name; $('#peDesig').value=edit.designation; $('#peView').value=edit.view; $('#peMatch').value=edit.match;
  $('#peDelete').style.display=(p&&profiles.list.length>1)?'':'none';
  syncAdjInputs(); paintPreview(); $('#profileEditor').hidden=false; if($('#profileEditor').scrollIntoView) $('#profileEditor').scrollIntoView({block:'nearest'}); $('#peName').focus();
}
function closeEditor(){ $('#profileEditor').hidden=true; edit=null; }
function fileToDataURL(file,maxPx){
  return new Promise((resolve,reject)=>{
    const url=URL.createObjectURL(file), img=new Image();
    img.onload=()=>{ const k=Math.min(1,maxPx/Math.max(img.width,img.height)), c=document.createElement('canvas'); c.width=Math.max(1,Math.round(img.width*k)); c.height=Math.max(1,Math.round(img.height*k)); const g=c.getContext('2d'); g.fillStyle='#fff'; g.fillRect(0,0,c.width,c.height); g.drawImage(img,0,0,c.width,c.height); URL.revokeObjectURL(url); resolve(c.toDataURL('image/jpeg',0.88)); };
    img.onerror=()=>{ URL.revokeObjectURL(url); reject(new Error('This file is not an image the browser can open.')); };
    img.src=url;
  });
}
function wireEditor(){
  $('#peChoose').onclick=()=>$('#peFile').click();
  $('#peFile').onchange=async e=>{ const f=e.target.files[0]; e.target.value=''; if(!f||!edit) return; try{ edit.photo=await fileToDataURL(f,520); edit.adj={x:0,y:0,z:100,r:0}; syncAdjInputs(); paintPreview(); }catch(err){ alert(err.message); } };
  $('#peRemove').onclick=()=>{ if(!edit) return; edit.photo=''; edit.adj={x:0,y:0,z:100,r:0}; syncAdjInputs(); paintPreview(); };
  const clamp=(v,a,b)=>Math.min(b,Math.max(a,v));
  const lim={x:[-100,100],y:[-100,100],z:[50,300],r:[-180,180]};
  [['X','x'],['Y','y'],['Z','z'],['R','r']].forEach(([k,f])=>{
    const set=v=>{ if(!edit) return; v=parseFloat(v); if(!isFinite(v)) return; edit.adj[f]=clamp(Math.round(v),lim[f][0],lim[f][1]); $('#pe'+k).value=edit.adj[f]; $('#pe'+k+'n').value=edit.adj[f]; paintPreview(); };
    $('#pe'+k).oninput=e=>set(e.target.value); $('#pe'+k+'n').oninput=e=>set(e.target.value);
  });
  $('#peRotL').onclick=()=>{ if(!edit||!edit.photo) return; let r=edit.adj.r-90; if(r<-180) r+=360; edit.adj.r=r; syncAdjInputs(); paintPreview(); };
  $('#peRotR').onclick=()=>{ if(!edit||!edit.photo) return; let r=edit.adj.r+90; if(r>180) r-=360; edit.adj.r=r; syncAdjInputs(); paintPreview(); };
  $('#peReset').onclick=()=>{ if(!edit) return; edit.adj={x:0,y:0,z:100,r:0}; syncAdjInputs(); paintPreview(); };
  const pv=$('#pePreview'); let drag=null;
  pv.addEventListener('pointerdown',e=>{ if(!edit||!edit.photo) return; drag={x:e.clientX,y:e.clientY,ax:edit.adj.x,ay:edit.adj.y}; try{ pv.setPointerCapture(e.pointerId); }catch(_){} pv.style.cursor='grabbing'; });
  pv.addEventListener('pointermove',e=>{ if(!drag||!edit) return; const w=pv.clientWidth||190; edit.adj.x=clamp(Math.round(drag.ax+(e.clientX-drag.x)/w*100),-100,100); edit.adj.y=clamp(Math.round(drag.ay+(e.clientY-drag.y)/w*100),-100,100); syncAdjInputs(); paintPreview(); });
  const end=()=>{ drag=null; pv.style.cursor='grab'; }; pv.addEventListener('pointerup',end); pv.addEventListener('pointercancel',end);
  $('#peName').oninput=e=>{ if(edit){ edit.name=e.target.value; if(!edit.photo) paintPreview(); } };
  $('#peDesig').oninput=e=>{ if(edit) edit.designation=e.target.value; };
  $('#peView').onchange=e=>{ if(edit) edit.view=e.target.value; };
  $('#peMatch').oninput=e=>{ if(edit) edit.match=e.target.value; };
  $('#peCancel').onclick=closeEditor;
  $('#peSave').onclick=()=>{
    if(!edit) return;
    edit.name=$('#peName').value.trim(); edit.designation=$('#peDesig').value.trim(); edit.view=$('#peView').value; edit.match=$('#peMatch').value.trim();
    if(!edit.name){ alert('Enter a name for the profile.'); $('#peName').focus(); return; }
    if(edit.id){ const i=profiles.list.findIndex(x=>x.id===edit.id); if(i>=0) profiles.list[i]=edit; else profiles.list.push(edit); }
    else { edit.id=uid(); profiles.list.push(edit); }
    profiles.active=edit.id; saveProfiles(); closeEditor();
    state.buyer='All'; state.owner='All'; state.year='All'; state.month=null; refreshAll(false);
  };
  $('#peDelete').onclick=()=>{
    if(!edit||!edit.id||profiles.list.length<2) return;
    if(!confirm('Delete the profile '+edit.name+'?')) return;
    profiles.list=profiles.list.filter(x=>x.id!==edit.id); profiles.active=profiles.list[0].id; saveProfiles(); closeEditor();
    state.buyer='All'; state.owner='All'; refreshAll(false);
  };
}

// ----- Google Sheets -----
const lines=s=>String(s||'').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
async function fetchSheetText(link){
  const cands=sheetCandidates(link);
  if(!cands.length) throw new Error('this is not a Google Sheets link');
  let last='';
  for(const u of cands){
    try{
      const r=await fetch(u,{credentials:'omit'});
      if(!r.ok){ last='Google answered with status '+r.status+(r.status===404?' (check the link)':(r.status===401||r.status===403?' (the sheet is not shared with Anyone with the link)':'')); continue; }
      const txt=await r.text();
      if(/^\s*<(!doctype|html)/i.test(txt)){ last='Google returned a sign-in page, so the sheet is not shared with Anyone with the link'; continue; }
      if(!txt.trim()){ last='the sheet returned no rows'; continue; }
      return txt;
    }catch(e){ last='the browser could not reach Google ('+(e&&e.message?e.message:'network error')+'). Check the internet connection and that the sheet is shared with Anyone with the link'; }
  }
  throw new Error(last||'no data returned');
}
function sameHeader(old, rows){ try{ return JSON.stringify((old.sheets[old.sheetName]||[])[old.headerRow])===JSON.stringify(rows[old.headerRow]); }catch(e){ return false; } }
let syncTimer=null, syncing=false;
function setStatus(t){ const el=$('#syncStatus'); if(el) el.textContent=t; }
const hhmm=()=>new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
const fmtSec=n=>n<60?n+' seconds':(n%60===0?(n/60)+' minute'+(n/60>1?'s':''):n+' seconds');
function paintSub(){
  let s=state.subBase||'';
  if(state.lastCheck){
    const n=+settings.syncSec;
    s+=(s?'  |  ':'')+'Google Sheets: data changed '+(state.lastSync||'not yet')+', last checked '+state.lastCheck+(n>0?', auto sync every '+fmtSec(n):', auto sync off');
  }
  $('#sub').textContent=s;
}
function hashStr(s){ let h=5381; for(let i=0;i<s.length;i++) h=((h<<5)+h+s.charCodeAt(i))|0; return (h>>>0).toString(36)+':'+s.length; }
function toast(msg){ const el=$('#toast'); el.textContent=msg; el.classList.add('on'); clearTimeout(toast.t); toast.t=setTimeout(()=>el.classList.remove('on'),4000); }

const GOOGLE_SHEETS_API = window.PD_API_URL || 'https://pd-dashboard-api.kaziminhaz14.workers.dev/';
let workerSyncing = false;
async function appendSheetsRows(kind){
  const sources=(kind==='tracker'?state.tracks:state.costs).filter(x=>!x.sample);
  const rows=sources.flatMap(src=>{const data=src.sheets&&src.sheets[src.sheetName];return Array.isArray(data)?data:[];});
  if(!rows.length){toast('Load '+kind+' rows before syncing');return;}
  if(!confirm('Append '+rows.length+' '+kind+' rows to Google Sheets? Existing rows will stay unchanged. Repeating this action may create duplicates.'))return;
  try{const response=await fetch(GOOGLE_SHEETS_API,{method:'PUT',headers:{'Content-Type':'application/json',Authorization:'Bearer '+(localStorage.getItem('pd_auth_token')||'')},body:JSON.stringify({sheet:kind,rows})});const result=await response.json();if(!response.ok)throw new Error(result.error||'Write failed');setStatus('Appended '+rows.length+' '+kind+' rows to Google Sheets.');toast('Rows appended successfully');}catch(error){setStatus('Sheets write failed: '+error.message);toast('Sheets write failed: '+error.message);}
}
async function syncWorkerSheets(silent){
  if(workerSyncing) return;
  workerSyncing=true;
  const status=$('#workerStatus');
  if(status) status.textContent='Syncing live Google Sheets…';
  try{
    const response=await fetch(GOOGLE_SHEETS_API,{method:'GET',cache:'no-store',headers:{Authorization:'Bearer '+(localStorage.getItem('pd_auth_token')||'')}});
    if(!response.ok) throw new Error('Worker returned HTTP '+response.status);
    const payload=await response.json();
    if(!payload || typeof payload.tracker!=='string' || typeof payload.costing!=='string'){
      throw new Error('Unexpected response from the Sheets API');
    }
    const trackerRows=parseCSV(payload.tracker);
    const costingRows=parseCSV(payload.costing);
    if(!trackerRows.length && !costingRows.length) throw new Error('No rows were returned by Google Sheets');

    const oldT=state.tracks.find(x=>x.kind==='worker');
    const oldC=state.costs.find(x=>x.kind==='worker');
    const nextT=trackerRows.length?makeTrack('Google Sheets · Tracker',{'Tracker':trackerRows},false):null;
    const nextC=costingRows.length?makeCost('Google Sheets · Costing',{'Costing':costingRows}):null;
    if(nextT){
      nextT.kind='worker';
      if(oldT && sameHeader(oldT,trackerRows)){ nextT.headerRow=oldT.headerRow; nextT.map=oldT.map; }
    }
    if(nextC){
      nextC.kind='worker';
      if(oldC && sameHeader(oldC,costingRows)){ nextC.headerRow=oldC.headerRow; nextC.map=oldC.map; }
    }
    const signature=hashStr(payload.tracker+'\\n--COSTING--\\n'+payload.costing);
    const changed=signature!==state.workerSig;
    state.tracks=state.tracks.filter(x=>x.kind!=='worker').concat(nextT?[nextT]:[]);
    state.costs=state.costs.filter(x=>x.kind!=='worker').concat(nextC?[nextC]:[]);
    state.workerSig=signature;
    state.lastCheck=hhmm();
    if(changed) state.lastSync=state.lastCheck;
    state.syncErrors=[];
    if(status) status.textContent=(changed?'Updated':'Up to date')+' · '+state.lastCheck;
    setStatus((changed?'Updated':'Checked')+' '+state.lastCheck+': '+(nextT?'Tracker':'No tracker')+' and '+(nextC?'Costing':'No costing')+'.');
    if(changed || !silent) refreshAll(true);
    else paintSub();
    if(changed && !silent) toast('Google Sheets synced successfully');
  }catch(e){
    if(status) status.textContent='Sync failed · '+e.message;
    setStatus('Google Sheets sync failed: '+e.message);
    if(!silent) toast('Sync failed. Showing the last saved data.');
  }finally{
    workerSyncing=false;
  }
}

async function loadFromSheets(silent){
  const tl=lines(settings.trackerLinks), cl=lines(settings.costLinks);
  if(!tl.length&&!cl.length){ if(!silent){ $('#srcPanel').hidden=false; setStatus('Paste at least one sheet link first.'); } return; }
  if(syncing) return; syncing=true;
  if(!silent) setStatus('Loading from Google Sheets...');
  const job=async(link,i,kind)=>{
    const label=(kind==='t'?'Tracker':'Costing')+' sheet '+(i+1);
    try{
      const text=await fetchSheetText(link), rows=parseCSV(text);
      if(!rows.length) throw new Error('the sheet is empty');
      const sheets={'Google Sheet':rows}, type=classify(sheets);
      if(kind==='t'&&type==='cost') throw new Error('this looks like a costing sheet, paste it in the costing box');
      if(kind==='c'&&type==='tracker') throw new Error('this looks like a tracker sheet, paste it in the tracker box');
      const src=kind==='t'?makeTrack(label,sheets,false):makeCost(label,sheets);
      src.kind='sheet'; src.link=link;
      const old=(kind==='t'?state.tracks:state.costs).find(s=>s.kind==='sheet'&&s.link===link);
      if(old&&sameHeader(old,rows)){ src.headerRow=old.headerRow; src.map=old.map; }
      return {src,kind,sig:kind+'|'+link+'|'+hashStr(text)};
    }catch(e){ return {err:label+': '+e.message}; }
  };
  const res=await Promise.all([...tl.map((l,i)=>job(l,i,'t')),...cl.map((l,i)=>job(l,i,'c'))]);
  syncing=false;
  const errs=res.filter(r=>r.err).map(r=>r.err), okT=res.filter(r=>r.src&&r.kind==='t').map(r=>r.src), okC=res.filter(r=>r.src&&r.kind==='c').map(r=>r.src);
  const sig=res.map(r=>r.sig||('E|'+r.err)).join(';');
  state.lastCheck=hhmm();
  if(silent && sig===state.sig){ setStatus('Checked '+state.lastCheck+'. No changes in the sheets.'); paintSub(); return; }
  const firstLoad=!state.sig; state.sig=sig;
  if(okT.length) state.tracks=state.tracks.filter(s=>s.kind!=='sheet'&&!s.sample).concat(okT);
  if(okC.length) state.costs=state.costs.filter(s=>s.kind!=='sheet').concat(okC);
  state.syncErrors=errs;
  if(okT.length||okC.length){ state.lastSync=state.lastCheck; setStatus('Updated '+state.lastSync+': '+okT.length+' tracker and '+okC.length+' costing sheet(s).'+(errs.length?' '+errs.length+' failed.':'')); }
  else setStatus('Nothing loaded. '+(errs[0]||''));
  const sy=window.scrollY, cs=$('#costSearch')?$('#costSearch').value:'';
  refreshAll(true);
  const cs2=$('#costSearch'); if(cs2&&cs){ cs2.value=cs; cs2.dispatchEvent(new Event('input')); }
  if(silent&&!firstLoad) window.scrollTo(0,sy);
  if((okT.length||okC.length)&&!firstLoad){ const sb=$('#sub'); sb.classList.remove('flash'); void sb.offsetWidth; sb.classList.add('flash'); toast('Sheet changed. Dashboard updated at '+state.lastSync); }
}
let syncHooks=false;
function setupAutoRefresh(){
  if(syncTimer){ clearInterval(syncTimer); syncTimer=null; }
  const n=+settings.syncSec;
  if(n>0) syncTimer=setInterval(()=>{ if(!document.hidden) syncWorkerSheets(true); }, Math.max(5,n)*1000);
  if(!syncHooks){
    syncHooks=true;
    document.addEventListener('visibilitychange',()=>{ if(!document.hidden && +settings.syncSec>0) syncWorkerSheets(true); });
    window.addEventListener('online',()=>{ if(+settings.syncSec>0) syncWorkerSheets(true); });
    window.addEventListener('focus',()=>{ if(+settings.syncSec>0) syncWorkerSheets(true); });
  }
}
function syncBox(){
  return state.syncErrors.length ? `<div class="warnbox"><b>Google Sheets could not be read for ${state.syncErrors.length} link(s).</b>${state.tracks.length||state.costs.length?' The last saved data is shown.':''}<br>${state.syncErrors.map(esc).join('<br>')}</div>` : '';
}

// ----- wiring -----
$('#btnSelect').onclick=()=>$('#file').click();
$('#drop').onclick=()=>{ $('#srcPanel').hidden=false; };

$('#btnRefresh').onclick=()=>syncWorkerSheets(false);
$('#btnWriteTracker').onclick=()=>appendSheetsRows('tracker'); $('#btnWriteCosting').onclick=()=>appendSheetsRows('costing');
$('#btnSaveLoad').onclick=()=>{ readSettings(); applySettingsToUI(); setupAutoRefresh(); loadFromSheets(false); };
$('#file').onchange=e=>{ if(e.target.files.length) addToQueue(e.target.files); e.target.value=''; };
$('#btnUpload').onclick=uploadQueue; $('#btnQUpload').onclick=uploadQueue;
$('#btnQClear').onclick=()=>{ state.queue=[]; renderQueue(); render(); };
$('#btnSample').onclick=()=>{ state.tracks=[makeTrack('Sample data',{'Sample':sampleRows()},true)]; state.buyer='All'; state.year='All'; state.month=null; refreshAll(false); };


$('#btnPrint').onclick=()=>window.print();
$('#btnClear').onclick=()=>{ if(!confirm('Remove the tracker data from this browser?')) return; state.tracks=[]; state.buyer='All'; state.year='All'; state.month=null; refreshAll(true); };
$('#btnClearCost').onclick=()=>{ if(!confirm('Remove the costing data from this browser?')) return; state.costs=[]; state.owner='All'; refreshAll(true); };
$('#fYear').onchange=e=>{ state.year=e.target.value; render(); };
$('#fOwner').onchange=e=>{ state.owner=e.target.value; render(); };
['sTitle','sFy','sLow','sTop','sAcc','sDec','sRules','sPL','sBands'].forEach(id=>{
  $('#'+id).addEventListener('change',()=>{ readSettings(); applySettingsToUI(); if(id==='sRules') refreshAll(false); else render(); });
});
['dragenter','dragover'].forEach(ev=>document.addEventListener(ev,e=>{ e.preventDefault(); $('#drop').classList.add('over'); }));
['dragleave','drop'].forEach(ev=>document.addEventListener(ev,e=>{ e.preventDefault(); $('#drop').classList.remove('over'); }));
document.addEventListener('drop',e=>{ const f=e.dataTransfer&&e.dataTransfer.files; if(f&&f.length) addToQueue(f); });

(function init(){
  const s2=lsGet(LS_S), s1=lsGet(LS_S1);
  if(s2) settings=Object.assign({},DEFAULTS,s2);
  else if(s1){ const o=Object.assign({},s1); delete o.accent; delete o.title; settings=Object.assign({},DEFAULTS,o); }
  applySettingsToUI();
  const pr=lsGet(LS_P);
  if(pr&&pr.list&&pr.list.length) profiles=pr; else { const p0=newProfile(); p0.id=uid(); p0.name=settings.owner||'My profile'; p0.designation='Product Developer'; profiles={list:[p0],active:p0.id}; saveProfiles(); }
  wireEditor();
  let d=lsGet(LS_D); if(!d){ const o=lsGet(LS_D1); if(o&&o.rows&&!o.isSample) d={tracks:[{name:o.fileName,sheetName:o.sheetName,rows:o.rows,headerRow:o.headerRow,map:o.map}]}; }
  if(d&&d.tracks) state.tracks=d.tracks.map(x=>({name:x.name,sheets:{[x.sheetName]:x.rows},sheetName:x.sheetName,headerRow:x.headerRow,map:x.map,sample:false,kind:x.kind||'',link:x.link||''}));
  let c=lsGet(LS_C); if(!c){ const o=lsGet(LS_C1); if(o&&o.rows) c={costs:[{name:o.fileName,sheetName:o.sheetName,rows:o.rows,headerRow:o.headerRow,map:o.map}]}; }
  if(c&&c.costs) state.costs=c.costs.map(x=>({name:x.name,sheets:{[x.sheetName]:x.rows},sheetName:x.sheetName,headerRow:x.headerRow,map:x.map,kind:x.kind||'',link:x.link||''}));
  refreshAll(false);
  setupAutoRefresh();
  syncWorkerSheets(false);
  if(!state.tracks.length&&!state.costs.length) $('#srcPanel').hidden=false;
})();
</script>
<script id="pd-navigation-live">
(()=>{
 const navs=[...document.querySelectorAll('.pd-nav[data-go]')];
 const sections=()=>[...document.querySelectorAll('#dash .sec')];
 const findSection=(key)=>{
   if(key==='tracker') return document.querySelector('#tracker-section');
   if(key==='costing') return sections().find(x=>/^costing analysis/i.test((x.textContent||'').trim()))||null;
   if(key==='charts') return sections().find(x=>/^charts?$/i.test((x.textContent||'').trim()))||null;
   return null;
 };
 const go=(key)=>{
   let target=null;
   if(key==='overview') target=document.querySelector('.banner');
   else if(['tracker','costing','charts'].includes(key)) target=findSection(key)||document.querySelector('#dash');
   else {
     const panels={sources:'#srcPanel',mapping:'#mapping',settings:'#settings'};
     const selector=panels[key];
     if(selector){
       const panel=document.querySelector(selector);
       if(panel) panel.hidden=false;
       target=panel;
     }
   }
   navs.forEach(button=>button.classList.toggle('active',button.dataset.go===key));
   if(target) target.scrollIntoView({behavior:'smooth',block:'start'});
 };
 navs.forEach(button=>button.addEventListener('click',()=>go(button.dataset.go)));
})();
</script>
<script src="./auth.js"></script>
</body>
</html>
