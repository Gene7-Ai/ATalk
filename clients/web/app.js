// aTalk web human client
import { AtalkClient } from '/app/core.js';

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmtT = iso => { const d = new Date(iso); if (isNaN(d)) return ''; const now = new Date(); const same = d.toDateString() === now.toDateString(); return same ? d.toTimeString().slice(0, 5) : `${d.getMonth() + 1}-${d.getDate()} ${d.toTimeString().slice(0, 5)}`; };
const ago = ts => { if (!ts) return 'no record'; const m = Math.floor((Date.now() - ts) / 60000); if (m < 1) return 'just now'; if (m < 60) return `${m} min ago`; const h = Math.floor(m / 60); if (h < 24) return `${h} h ago`; return `${Math.floor(h / 24)} d ago`; };
// presence TTL=15min; activity gradient 3/2/1/0 (15min / 1h / 24h / older)
const lvlOf = p => { const t = Math.max(p.lastPresence || 0, p.last || 0); const m = (Date.now() - t) / 60000; return m < 15 ? 3 : m < 60 ? 2 : m < 1440 ? 1 : 0; };
const lvlText = ['silent', 'seen today', 'active · within 1h', 'online'];

// preferences (localStorage, per-device UI state only)
const pref = { get: (k, d) => { try { return localStorage.getItem('atalk.' + k) ?? d; } catch (_) { return d; } }, set: (k, v) => { try { localStorage.setItem('atalk.' + k, v); } catch (_) {} } };
function applyTheme() { const t = pref.get('theme', 'system'); if (t === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t); const dark = t === 'dark' || (t === 'system' && matchMedia('(prefers-color-scheme: dark)').matches); document.querySelector('meta[name=theme-color]').setAttribute('content', dark ? '#121212' : '#ffffff'); }
function applyFont() { document.documentElement.style.fontSize = pref.get('font', '15') + 'px'; }
applyTheme(); applyFont(); matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);

const c = new AtalkClient();
const app = $('#app'); let cur = null; let filter = ''; let refreshTimer = null;

function showLogin(msg) { $('#login').classList.remove('hidden'); app.classList.add('hidden'); $('#l-err').textContent = msg || ''; }
function showApp() { $('#login').classList.add('hidden'); app.classList.remove('hidden'); $('#me-name').textContent = c.me; }
function showView(v) { $('#view-chat').classList.toggle('hidden', v !== 'chat'); $('#view-board').classList.toggle('hidden', v !== 'board'); $('#view-settings').classList.toggle('hidden', v !== 'settings'); document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.view === v)); }

async function renderContacts() {
  let ps = await c.peers();
  if (filter) ps = ps.filter(p => p.id.includes(filter));
  const unread = await unreadCounts();
  $('#contacts').innerHTML = ps.map(p => { const l = lvlOf(p); const n = unread[p.id] || 0; return `<li data-id="${esc(p.id)}" class="${p.id === cur ? 'sel' : ''}"><span class="dot ${l >= 3 ? 'on' : l === 2 ? 'warm' : ''}"></span><span class="name">${esc(p.id)}</span>${n ? `<span class="n">${n}</span>` : ''}</li>`; }).join('') || '<li class="empty">No conversations yet</li>';
  document.querySelectorAll('#contacts li[data-id]').forEach(li => li.onclick = () => open(li.dataset.id));
}
async function unreadCounts() {
  // unread = addressed to me, not presence, no local read mark
  const out = {};
  const ps = await c.peers();
  for (const p of ps) { const th = await c.thread(p.id, 100); out[p.id] = th.filter(e => e.target === c.me && e.id > c.ackFloor && !(e.local && e.local.read)).length; } // history before the login watermark does not count as unread
  return out;
}

function tick(e) {
  // my sends: outbox state -> sent (pend) -> received (ok1) -> applied (ok2)
  const a = e.local && e.local.acks;
  if (a && a.applied) return '<span class="tick ok2" title="applied by peer">✓✓</span>';
  if (a && a.received) return '<span class="tick ok1" title="received by peer">✓</span>';
  return '<span class="tick pend" title="sent, awaiting receipt">·</span>';
}

async function renderThread() {
  if (!cur) return;
  const th = await c.thread(cur, 300);
  const ps = await c.peers(); const p = ps.find(x => x.id === cur);
  $('#conv-name').textContent = cur; $('#conv-sub').textContent = p ? `${lvlText[lvlOf(p)]} · ${ago(Math.max(p.lastPresence || 0, p.last || 0))}` : '';
  $('#draft').placeholder = `Message ${cur}…`;
  $('#msgs').innerHTML = th.map(e => {
    const me = e.source === c.me; const txt = (e.payload && (e.payload.text ?? JSON.stringify(e.payload))) || '';
    if (e.type === 'task') { const pl = e.payload || {}; return `<div class="msg task"><div class="t">task · ${esc(pl.title || pl.op || pl.task_id || '')}</div><div class="st">${esc(pl.state || pl.status || '')} · #${e.id}</div><span class="meta">${fmtT(e.created_at)}</span></div>`; }
    if (me) return `<div class="msg me" data-eid="${esc(e.event_id)}">${esc(txt)}<span class="meta">${fmtT(e.created_at)} ${tick(e)}</span></div>`;
    const applied = e.local && (e.local.applied_local || (e.local.acks && e.local.acks.mine_applied));
    const act = (e.type === 'presence' || e.id <= c.ackFloor) ? '' : (applied ? '<span class="act done">applied</span>' : `<span class="act" data-apply="${esc(e.event_id)}">mark applied</span>`); // no applied button for pre-login history
    return `<div class="msg" data-eid="${esc(e.event_id)}">${esc(txt)}<span class="meta">${e.type !== 'message' ? esc(e.type) + ' · ' : ''}${fmtT(e.created_at)}${act}</span></div>`;
  }).join('') || '<div class="empty">No messages yet</div>';
  $('#msgs').scrollTop = 1e6; requestAnimationFrame(() => { $('#msgs').scrollTop = 1e6; });
  document.querySelectorAll('[data-apply]').forEach(el => el.onclick = async () => { el.textContent = '…'; try { await c.markApplied(el.dataset.apply); } catch (e) { el.textContent = 'failed'; return; } renderThread(); });
  // seen => read (local UI state, not an ACK)
  for (const e of th) if (e.target === c.me && !(e.local && e.local.read)) c.markRead(e.event_id).catch(() => {});
}
async function renderBoard() {
  const ps = await c.peers();
  $('#wall').innerHTML = ps.map(p => { const l = lvlOf(p); return `<span class="chip l${l}" title="${lvlText[l]} · ${ago(Math.max(p.lastPresence || 0, p.last || 0))}"><span class="dot ${l >= 3 ? 'on' : l === 2 ? 'warm' : ''}"></span>${esc(p.id)}</span>`; }).join('') || '<div class="empty">none</div>';
  const ns = await c.notices(30);
  $('#notices').innerHTML = ns.map(n => `<div class="notice"><div class="who">${esc(n.source)} · ${fmtT(n.created_at)}</div>${esc((n.payload && n.payload.text) || '')}</div>`).join('') || '<div class="empty">No notices</div>';
}
async function open(id) { cur = id; app.classList.add('open'); showView('chat'); await renderContacts(); await renderThread(); c.refreshAcks(id).then(n => n && renderThread()).catch(() => {}); }

async function renderSettings() {
  $('#s-me').textContent = c.me || '—'; $('#s-ver').textContent = 'v0.3';
  $('#s-conn').textContent = $('#st').textContent + ' · ' + location.host;
  const n = await new Promise(r => { const q = c.db.transaction('events').objectStore('events').count(); q.onsuccess = () => r(q.result); q.onerror = () => r('?'); });
  $('#s-cursor').textContent = `#${c.cursor} / ${n} events`;
  document.querySelectorAll('#s-theme button').forEach(b => b.classList.toggle('active', b.dataset.t === pref.get('theme', 'system')));
  document.querySelectorAll('#s-font button').forEach(b => b.classList.toggle('active', b.dataset.f === pref.get('font', '15')));
  $('#s-poll').value = pref.get('poll', '5000'); $('#s-sse').checked = pref.get('sse', '1') === '1'; $('#s-device').value = pref.get('device', '');
}
document.querySelectorAll('#s-theme button').forEach(b => b.onclick = () => { pref.set('theme', b.dataset.t); applyTheme(); renderSettings(); });
document.querySelectorAll('#s-font button').forEach(b => b.onclick = () => { pref.set('font', b.dataset.f); applyFont(); renderSettings(); });
$('#s-poll').onchange = e => { pref.set('poll', e.target.value); c.pollMs = Number(e.target.value); };
$('#s-sse').onchange = e => { pref.set('sse', e.target.checked ? '1' : '0'); c.useSSE = e.target.checked; if (!e.target.checked && c._ac) c._ac.abort(); };
$('#s-device').onchange = e => pref.set('device', e.target.value.trim());
$('#s-drain').onclick = () => c.drain().then(n => { $('#s-drain').textContent = `drained +${n}`; setTimeout(() => $('#s-drain').textContent = 'Drain', 1500); renderSettings(); }).catch(() => { $('#s-drain').textContent = 'failed'; });
$('#s-logout').onclick = () => $('#logout').click();

c.on(async (type, d) => {
  if (type === 'status') { $('#st').textContent = ({ online: 'connected', offline: 'offline', error: 'connection error', forbidden: 'token rejected', throttled: 'throttled', init: 'connecting…' })[d.status] || d.status; $('#st').className = ['offline', 'error', 'forbidden'].includes(d.status) ? 'bad' : ''; $('#cur').textContent = c.cursor ? `#${c.cursor}` : ''; if (d.status === 'forbidden') showLogin('token rejected by server; please sign in again'); }
  if (type === 'events') { await renderContacts(); if (cur && d.some(e => e.peer === cur)) await renderThread(); }
  if (type === 'outbox') { if (cur && d.target === cur) renderThread(); }
});

$('#l-go').onclick = async () => { $('#l-err').textContent = 'signing in…'; try { c.pollMs = Number(pref.get('poll', '5000')); c.useSSE = pref.get('sse', '1') === '1'; await c.login($('#l-me').value.trim(), $('#l-tok').value.trim()); showApp(); c.run(); renderContacts(); } catch (e) { $('#l-err').textContent = String(e.message || e); } };
$('#l-tok').addEventListener('keydown', e => { if (e.key === 'Enter') $('#l-go').click(); });
$('#logout').onclick = async e => { e.preventDefault(); if (!confirm('Signing out clears the locally cached messages and token')) return; c.stop(); await c.logout(); location.reload(); };
$('#search').oninput = e => { filter = e.target.value.trim(); renderContacts(); };
document.querySelectorAll('.tab').forEach(t => t.onclick = () => { showView(t.dataset.view); if (t.dataset.view === 'board') { renderBoard(); app.classList.add('open'); } if (t.dataset.view === 'settings') { renderSettings(); app.classList.add('open'); } });
$('#back').onclick = $('#back2').onclick = $('#back3').onclick = () => app.classList.remove('open');
window.addEventListener('resize', () => { if (cur) $('#msgs').scrollTop = 1e6; });
$('#composer').onsubmit = async e => { e.preventDefault(); const v = $('#draft').value.trim(); if (!v || !cur) return; $('#draft').value = ''; await c.send(cur, v); renderThread(); };

(async () => {
  c.pollMs = Number(pref.get('poll', '5000')); c.useSSE = pref.get('sse', '1') === '1';
  const ok = await c.init();
  if (!ok) { showLogin(''); return; }
  showApp(); c.run(); await renderContacts();
  refreshTimer = setInterval(() => { if (cur) c.refreshAcks(cur, 10).then(n => n && renderThread()).catch(() => {}); renderContacts(); }, 15000);
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
})();
