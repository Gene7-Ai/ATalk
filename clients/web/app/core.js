// aTalk web client core
// Client of the ATalk HTTP API. Zero external dependencies.
// R2: an event and the cursor persist in ONE IndexedDB transaction before we ACK received. Rendering != received; only an explicit user 'handled' marks applied.
// R3: on every start/reconnect/poll/wake, drain in a loop by last id until a short page; each page persists before the cursor advances.

const DB_NAME = 'atalk-web';
const DB_VER = 1;
const PAGE = 200;
const API = '/api';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = () => {
      const db = req.result;
      const ev = db.createObjectStore('events', { keyPath: 'id' });          // server id (integer, monotonic)
      ev.createIndex('by_peer', 'peer', { unique: false });                   // peer (whichever of source/target is not me)
      ev.createIndex('by_event_id', 'event_id', { unique: true });
      db.createObjectStore('meta', { keyPath: 'k' });                         // cursor / me / token / device
      db.createObjectStore('outbox', { keyPath: 'event_id' });                // queued/sending (stable event_id)
      db.createObjectStore('local', { keyPath: 'event_id' });                 // local UI state: read / applied_local
    };
    req.onsuccess = () => { const db = req.result; db.onversionchange = () => db.close(); resolve(db); }; // step aside when another connection wants to delete/upgrade the DB
    req.onerror = () => reject(req.error);
  });
}

function tx(db, stores, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, mode);
    let out;
    t.oncomplete = () => resolve(out);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('tx aborted'));
    Promise.resolve(fn(t)).then(v => { out = v; }).catch(e => { try { t.abort(); } catch (_) {} reject(e); });
  });
}
const rq = r => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });

export class AtalkClient {
  constructor() { this.db = null; this.me = null; this.token = null; this.cursor = 0; this.listeners = new Set(); this.online = null; this.status = 'init'; }

  async init() {
    this.db = await openDB();
    const m = await tx(this.db, ['meta'], 'readonly', async t => {
      const s = t.objectStore('meta');
      return { me: await rq(s.get('me')), token: await rq(s.get('token')), cursor: await rq(s.get('cursor')) };
    });
    this.me = m.me?.v || null; this.token = m.token?.v || null; this.cursor = m.cursor?.v || 0;
    const af = await tx(this.db, ['meta'], 'readonly', async t => rq(t.objectStore('meta').get('ack_floor')));
    this.ackFloor = af?.v ?? 0;
    return !!(this.me && this.token);
  }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit(type, data) { for (const fn of this.listeners) { try { fn(type, data); } catch (e) { console.error(e); } } }
  setStatus(s, extra) { this.status = s; this.emit('status', { status: s, ...extra }); }

  async login(me, token) {
    // probe: /events without a token is 403, so ping once with the token
    const r = await this.api(`/events?target=${encodeURIComponent(me)}&since_id=0&limit=1`, { token });
    if (r.status === 403 || r.status === 401) throw new Error('invalid token (403)');
    if (!r.ok) throw new Error(`login probe failed HTTP ${r.status}`);
    // server watermark at login = history; only events arriving after it get a received ACK
    let floor = 0;
    try { floor = await this.serverMaxId(me, token); } catch (_) {}
    await tx(this.db, ['meta'], 'readwrite', async t => { const s = t.objectStore('meta'); s.put({ k: 'me', v: me }); s.put({ k: 'token', v: token }); s.put({ k: 'ack_floor', v: floor }); });
    this.me = me; this.token = token; this.ackFloor = floor;
  }

  async logout() {
    // sign-out clears token + cursor + local events
    this.db.close();
    await new Promise((res, rej) => { const r = indexedDB.deleteDatabase(DB_NAME); r.onsuccess = res; r.onerror = () => rej(r.error); r.onblocked = res; });
    this.me = null; this.token = null; this.cursor = 0; this.db = await openDB();
  }

  async api(path, { method = 'GET', body, token } = {}) {
    const headers = { 'Authorization': `Bearer ${token || this.token}` };
    if (body) headers['Content-Type'] = 'application/json';
    const r = await fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined, cache: 'no-store' });
    return r;
  }

  peerOf(ev) { return ev.source === this.me ? ev.target : ev.source; }

  // login watermark: page to the server's last page for the max id (not persisted), only for ack_floor
  async serverMaxId(me, token) {
    let since = 0, max = 0;
    for (let i = 0; i < 200; i++) {
      const r = await this.api(`/events?target=${encodeURIComponent(me)}&since_id=${since}&limit=${PAGE}&state=all`, { token });
      if (!r.ok) break;
      const d = await r.json(); const page = Array.isArray(d) ? d : (d.events || []);
      if (!page.length) break;
      max = since = page[page.length - 1].id;
      if (page.length < PAGE) break;
    }
    return max;
  }

  // broadcasts (target=*) are treated as notices, not contacts
  async notices(limit = 50) {
    return tx(this.db, ['events'], 'readonly', async t => {
      const all = await rq(t.objectStore('events').index('by_peer').getAll('*'));
      return all.filter(e => e.type !== 'presence').sort((a, b) => b.id - a.id).slice(0, limit);
    });
  }

  // R3: drain by pages. Returns count newly persisted this round. Any failed page stops the loop (cursor never passes a failed page).
  async drain() {
    let got = 0;
    for (;;) {
      const r = await this.api(`/events?target=${encodeURIComponent(this.me)}&since_id=${this.cursor}&limit=${PAGE}&state=all`);
      if (r.status === 403) { this.setStatus('forbidden'); throw new Error('403'); }
      if (r.status === 429) { this.setStatus('throttled'); await new Promise(x => setTimeout(x, 5000)); continue; }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      const page = Array.isArray(d) ? d : (d.events || []);
      if (!page.length) break;
      // R2: event + cursor in one transaction
      const last = page[page.length - 1].id;
      const fresh = await tx(this.db, ['events', 'meta'], 'readwrite', async t => {
        const es = t.objectStore('events'); const ms = t.objectStore('meta'); const newOnes = [];
        for (const ev of page) {
          const exists = await rq(es.get(ev.id));
          if (!exists) { ev.peer = this.peerOf(ev); es.put(ev); newOnes.push(ev); }
        }
        ms.put({ k: 'cursor', v: Math.max(this.cursor, last) });
        return newOnes;
      });
      this.cursor = Math.max(this.cursor, last);
      got += fresh.length;
      // ACK received only after a successful write (only for events addressed to me, not presence, not my own sends, and newer than the login history watermark — history is not re-ACKed)
      for (const ev of fresh) {
        if (ev.id > this.ackFloor && ev.target === this.me && ev.source !== this.me && ev.requires_ack !== false && ev.type !== 'presence') this.ack(ev.event_id, 'received').catch(() => {});
      }
      if (fresh.length) this.emit('events', fresh);
      if (page.length < PAGE) break;
    }
    this.setStatus('online', { cursor: this.cursor });
    return got;
  }

  async ack(event_id, ack_type) {
    const r = await this.api('/ack', { method: 'POST', body: { agent_id: this.me, event_id, ack_type } });
    if (!r.ok && r.status !== 409) throw new Error(`ack ${ack_type} HTTP ${r.status}`);
    if (ack_type === 'applied') await tx(this.db, ['local'], 'readwrite', async t => { t.objectStore('local').put({ event_id, applied_local: true, t: Date.now() }); });
    return true;
  }

  // explicit user "handled" -> applied (R2)
  markApplied(event_id) { return this.ack(event_id, 'applied'); }

  // for my sends: query the peer's ACK (GET /acks?event_id&agent=me), cache the result in the local store
  async acksFor(event_id) {
    const r = await this.api(`/acks?event_id=${encodeURIComponent(event_id)}&agent=${encodeURIComponent(this.me)}`);
    if (!r.ok) return null;
    const list = await r.json();
    const st = { received: null, applied: null, mine_applied: null };
    for (const a of (Array.isArray(list) ? list : [])) { if (a.agent_id === this.me) { if (a.ack_type === 'applied') st.mine_applied = a.created_at || true; continue; } if (a.ack_type === 'received' && !st.received) st.received = a.created_at || true; if (a.ack_type === 'applied') st.applied = a.created_at || true; }
    await tx(this.db, ['local'], 'readwrite', async t => { const s = t.objectStore('local'); const cur = (await rq(s.get(event_id))) || { event_id }; cur.acks = st; cur.acks_t = Date.now(); s.put(cur); });
    return st;
  }
  // refresh ACKs for my recent not-yet-applied sends in a peer thread
  async refreshAcks(peer, n = 30) {
    const th = await this.thread(peer, 200);
    // my sends: await peer received/applied; their sends (after the watermark): sync the applied I marked on another device
    const mine = th.filter(e => e.source === this.me && !(e.local && e.local.acks && e.local.acks.applied)).slice(-n);
    const theirs = th.filter(e => e.target === this.me && e.id > this.ackFloor && e.type !== 'presence' && !(e.local && (e.local.applied_local || (e.local.acks && e.local.acks.mine_applied)))).slice(-n);
    for (const e of [...mine, ...theirs]) { try { await this.acksFor(e.event_id); } catch (_) {} }
    return mine.length + theirs.length;
  }

  async markRead(event_id) { await tx(this.db, ['local'], 'readwrite', async t => { const s = t.objectStore('local'); const cur = (await rq(s.get(event_id))) || { event_id }; cur.read = true; s.put(cur); }); }

  // idempotent send: event_id goes into the outbox before sending; retries reuse the same id (server-idempotent)
  async send(target, text, type = 'message', extra = {}) {
    const event_id = (crypto.randomUUID ? crypto.randomUUID() : ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)));
    const item = { event_id, target, type, payload: { text, ...extra }, created: Date.now(), state: 'queued', tries: 0 };
    await tx(this.db, ['outbox'], 'readwrite', async t => { t.objectStore('outbox').put(item); });
    this.emit('outbox', item);
    return this.flushOne(item);
  }

  async flushOne(item) {
    item.tries++; item.state = 'sending';
    let r;
    try {
      r = await this.api('/events', { method: 'POST', body: { source: this.me, target: item.target, type: item.type, event_id: item.event_id, payload: item.payload } });
    } catch (e) { item.state = 'offline'; await this.saveOutbox(item); this.emit('outbox', item); return item; }
    if (r.status === 201 || r.status === 200 || r.status === 409) { // 2xx accepted; 409 = already exists = idempotent success
      // GET /events?target=me does not return my own sends, so persist locally on success (using the id/created_at from the 201)
      let body = null; try { body = await r.json(); } catch (_) {}
      const ev = { id: body && body.id, event_id: item.event_id, source: this.me, target: item.target, type: item.type, payload: item.payload, created_at: (body && body.created_at) || new Date().toISOString(), seq: body && body.seq, peer: item.target, mine: true };
      await tx(this.db, ['outbox', 'events'], 'readwrite', async t => { t.objectStore('outbox').delete(item.event_id); if (ev.id) t.objectStore('events').put(ev); });
      item.state = 'sent'; this.emit('outbox', item); if (ev.id) this.emit('events', [ev]); return item;
    }
    item.state = r.status === 429 ? 'throttled' : r.status === 403 ? 'forbidden' : `error-${r.status}`;
    await this.saveOutbox(item); this.emit('outbox', item); return item;
  }
  async saveOutbox(item) { await tx(this.db, ['outbox'], 'readwrite', async t => { t.objectStore('outbox').put(item); }); }
  async flushOutbox() { const items = await tx(this.db, ['outbox'], 'readonly', async t => rq(t.objectStore('outbox').getAll())); for (const it of items) if (it.state !== 'sending') await this.flushOne(it); }

  // read: a peer's history (local store), ascending by id
  async thread(peer, limit = 300) {
    return tx(this.db, ['events', 'local'], 'readonly', async t => {
      const all = await rq(t.objectStore('events').index('by_peer').getAll(peer));
      const ls = t.objectStore('local');
      const out = all.filter(e => e.type !== 'presence').sort((a, b) => a.id - b.id).slice(-limit);
      for (const e of out) e.local = (await rq(ls.get(e.event_id))) || null;
      return out;
    });
  }
  async peers() {
    // contact list + last presence (TTL=15min; expired = silent)
    return tx(this.db, ['events'], 'readonly', async t => {
      const all = await rq(t.objectStore('events').getAll());
      const m = new Map();
      for (const e of all) {
        const p = e.peer; if (!p || p === this.me || p === '*') continue;
        const cur = m.get(p) || { id: p, last: 0, lastPresence: 0, unread: 0, lastText: '' };
        const ts = Date.parse(e.created_at || 0) || 0;
        if (e.type === 'presence') { if (ts > cur.lastPresence) cur.lastPresence = ts; }
        else { if (ts > cur.last) { cur.last = ts; cur.lastText = (e.payload && e.payload.text) || ''; } }
        m.set(p, cur);
      }
      return [...m.values()].sort((a, b) => Math.max(b.last, b.lastPresence) - Math.max(a.last, a.lastPresence));
    });
  }

  // optional wake: streamed SSE via fetch (with bearer); any data: line -> drain(). On disconnect just exit; the caller decides whether to reconnect.
  async wake(signal) {
    const r = await fetch(`${API}/stream?agent=${encodeURIComponent(this.me)}`, { headers: { 'Authorization': `Bearer ${this.token}`, 'Accept': 'text/event-stream' }, signal, cache: 'no-store' });
    if (!r.ok || !r.body) throw new Error(`stream HTTP ${r.status}`);
    const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = '';
    for (;;) {
      const { value, done } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i; while ((i = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (line.startsWith('data:')) this.drain().catch(() => {}); }
    }
  }

  // main loop: drain is the source of truth, 5s polling as fallback, SSE only wakes
  async run() {
    let stop = false; this._stop = () => { stop = true; };
    const loop = async () => { while (!stop) { try { await this.flushOutbox(); await this.drain(); } catch (e) { this.setStatus(navigator.onLine ? 'error' : 'offline', { error: String(e) }); } await new Promise(x => setTimeout(x, this.pollMs || 5000)); } };
    const wake = async () => { while (!stop) { if (this.useSSE === false) { await new Promise(x => setTimeout(x, 3000)); continue; } const ac = new AbortController(); this._ac = ac; try { await this.wake(ac.signal); } catch (e) {} await new Promise(x => setTimeout(x, 3000)); } };
    document.addEventListener('visibilitychange', () => { if (!document.hidden) this.drain().catch(() => {}); }); // drain immediately when returning from lock screen
    window.addEventListener('online', () => this.drain().catch(() => {}));
    loop(); wake();
  }
  stop() { if (this._stop) this._stop(); if (this._ac) this._ac.abort(); }
}
