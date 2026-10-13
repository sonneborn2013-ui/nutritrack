/* Paydar — control de finanzas personales (PWA) v2
 *
 * Seguridad (resumen):
 *  - Llave de datos (DK) aleatoria de 256 bits. Los datos locales se cifran con AES-256-GCM usando DK.
 *  - DK se guarda envuelta (cifrada) con: PIN (PBKDF2-SHA256 310k) y, opcionalmente, biometría
 *    (WebAuthn + extensión PRF → HKDF). Sin PIN o biometría no se puede abrir.
 *  - Nube (opcional, Supabase): cifrado de extremo a extremo. Los datos suben cifrados con una
 *    llave de nube (CK) que el servidor nunca ve. CK se envuelve con la contraseña de la cuenta y
 *    con un código de recuperación. Al servidor de autenticación se le envía un derivado de la
 *    contraseña, nunca la contraseña real.
 *  - Recordatorios con la app cerrada: el usuario los activa; se suben solo nombre corto y fechas
 *    (sin montos) para que el servidor pueda enviar la notificación.
 */
'use strict';
(() => {
  const APP = 'Paydar';
  const VERSION = '2.1.0';
  const K_META = 'pd.meta.v2';
  const K_DATA = 'pd.data.v2';
  const OLD_META = 'ac.meta.v1', OLD_DATA = 'ac.data.v1';
  const PIN_LEN = 6;
  const PW_MIN = 10;
  const IDLE_LOCK_MS = 3 * 60 * 1000;
  const BG_LOCK_MS = 60 * 1000;
  const PBKDF2_ITER = 310000;
  const CFG = Object.assign({ supabaseUrl: '', supabaseAnonKey: '', vapidPublicKey: '', appUrl: '' }, window.PAYDAR_CONFIG || {});
  CFG.supabaseUrl = CFG.supabaseUrl.replace(/\/+$/, '');
  const TRIAL = !!CFG.trial;
  const CLOUD = !TRIAL && !!(CFG.supabaseUrl && CFG.supabaseAnonKey);
  const APP_URL = CFG.appUrl || (location.origin + location.pathname);

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const app = $('#app');
  const sheet = $('#sheet');
  const fmt = new Intl.NumberFormat('es-MX', { style: 'currency', currency: 'MXN' });
  const money = (n) => fmt.format(Number(n) || 0);
  const round2 = (n) => Math.round((Number(n) || 0) * 100) / 100;
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
  const uid = () => Array.from(rand(8), (b) => b.toString(16).padStart(2, '0')).join('');
  const MES = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
  const MES3 = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];
  const isApple = /iPhone|iPad|iPod|Macintosh/.test(navigator.userAgent);
  const BIO = isApple ? 'Face ID / Touch ID' : 'huella digital';

  /* ---------- Íconos ---------- */
  const P = {
    home: '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    card: '<rect x="2.5" y="5" width="19" height="14" rx="2.5"/><path d="M2.5 10h19"/><path d="M6 15h4"/>',
    bill: '<path d="M6 3h12v18l-3-2-3 2-3-2-3 2z"/><path d="M9 8h6M9 12h6"/>',
    swap: '<path d="M7 7h13l-4-4"/><path d="M17 17H4l4 4"/>',
    debt: '<path d="M12 3v18"/><path d="M17 7.5c0-1.9-2.2-3-5-3s-5 1.1-5 3 2 2.7 5 3.2 5 1.4 5 3.3-2.2 3.3-5 3.3-5-1.2-5-3.1"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
    luz: '<path d="M9 18h6M10 21h4"/><path d="M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.5 1 2.5h6c0-1 .3-1.8 1-2.5A6 6 0 0 0 12 3z"/>',
    agua: '<path d="M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z"/>',
    gas: '<path d="M12 3c1 3 5 5 5 10a5 5 0 0 1-10 0c0-2.5 1.5-4 2.5-5 .3 1.5 1 2.5 2 3 0-3 .5-5.5.5-8z"/>',
    internet: '<path d="M2 9a15 15 0 0 1 20 0"/><path d="M5.5 12.5a10 10 0 0 1 13 0"/><path d="M9 16a5 5 0 0 1 6 0"/><path d="M12 19.5h.01"/>',
    celular: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18h2"/>',
    otro: '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
    tag: '<path d="M3 12V4h8l10 10-8 8z"/><circle cx="7.5" cy="8.5" r="1.5"/>',
    up: '<path d="M12 19V5M5 12l7-7 7 7"/>',
    down: '<path d="M12 5v14M5 12l7 7 7-7"/>',
    cal: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
    left: '<path d="M15 18l-6-6 6-6"/>', right: '<path d="M9 18l6-6-6-6"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
    bell: '<path d="M6 16V11a6 6 0 0 1 12 0v5l2 2H4z"/><path d="M10 21h4"/>',
    save: '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/>',
    cloud: '<path d="M7 18a5 5 0 0 1-.6-10A6 6 0 0 1 18 9a4.5 4.5 0 0 1-.5 9z"/>',
    finger: '<path d="M12 11v3a8 8 0 0 0 1.5 4.7"/><path d="M8.5 13.5a3.5 3.5 0 0 1 7 0v1"/><path d="M5.5 15a6.5 6.5 0 0 1 13-2"/><path d="M4 9.5a9 9 0 0 1 16 0"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M15 8l2 2"/>',
    mic: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/>',
    camera: '<path d="M4 8h3l2-3h6l2 3h3v11H4z"/><circle cx="12" cy="13" r="3.5"/>',
    spark: '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/><path d="M19 16l.7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7z"/>',
    renta: '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    colegiatura: '<path d="M2 9l10-5 10 5-10 5z"/><path d="M6 11v5c3 2 9 2 12 0v-5"/>',
    seguro: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
    suscripcion: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M10 9l5 3-5 3z"/>',
    mantenimiento: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5"/>',
  };
  const icon = (n) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[n] || P.otro}</svg>`;

  /* ---------- Catálogos ---------- */
  const CAT_GASTO = ['Súper y despensa', 'Comida fuera', 'Transporte y gasolina', 'Hogar', 'Servicios', 'Salud', 'Educación', 'Seguros', 'Entretenimiento', 'Ropa', 'Cuidado personal', 'Mascotas', 'Regalos', 'Deudas', 'Otros'];
  const gastoCats = () => [...CAT_GASTO.slice(0, -1), ...(state?.customCats || []), 'Otros'];
  const CAT_INGRESO = ['Sueldo', 'Honorarios', 'Ventas', 'Rentas', 'Otros ingresos'];
  const BILL_TYPES = [
    { v: 'luz', l: 'Luz' }, { v: 'agua', l: 'Agua' }, { v: 'gas', l: 'Gas' },
    { v: 'internet', l: 'Internet / TV' }, { v: 'celular', l: 'Celular' }, { v: 'renta', l: 'Renta / hipoteca' },
    { v: 'colegiatura', l: 'Colegiatura' }, { v: 'seguro', l: 'Seguro' }, { v: 'suscripcion', l: 'Suscripción' },
    { v: 'mantenimiento', l: 'Mantenimiento' }, { v: 'otro', l: 'Otro pago fijo' },
  ];
  const billLabel = (t) => (BILL_TYPES.find((b) => b.v === t) || BILL_TYPES[BILL_TYPES.length - 1]).l;
  const BILL_CAT = { luz: 'Servicios', agua: 'Servicios', gas: 'Servicios', internet: 'Servicios', celular: 'Servicios', renta: 'Hogar', colegiatura: 'Educación', seguro: 'Seguros', suscripcion: 'Entretenimiento', mantenimiento: 'Hogar', otro: 'Otros' };
  const RECUR = [{ v: '1', l: 'Cada mes' }, { v: '2', l: 'Cada 2 meses' }, { v: '0', l: 'Una sola vez' }];

  /* ---------- Fechas ---------- */
  const pad2 = (n) => String(n).padStart(2, '0');
  const iso = (d) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
  const parseISO = (s) => { const [y, m, d] = String(s).split('-').map(Number); return new Date(y, (m || 1) - 1, d || 1); };
  const today0 = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };
  const todayISO = () => iso(today0());
  const addDays = (d, n) => new Date(d.getFullYear(), d.getMonth(), d.getDate() + n);
  const daysUntil = (s) => Math.round((parseISO(s) - today0()) / 86400000);
  const lastDay = (y, m) => new Date(y, m + 1, 0).getDate();
  const dateIn = (y, m, day) => new Date(y, m, Math.min(day, lastDay(y, m)));
  const fmtDate = (s) => { const d = parseISO(s); return `${d.getDate()} ${MES3[d.getMonth()]}`; };
  function nextOnOrAfter(day, from) {
    const f = new Date(from.getFullYear(), from.getMonth(), from.getDate());
    let y = f.getFullYear(), m = f.getMonth();
    for (let i = 0; i < 3; i++) {
      const d = dateIn(y, m, day);
      if (d >= f) return d;
      m++; if (m > 11) { m = 0; y++; }
    }
    return f;
  }
  function prevOccurrence(day) {
    const n = nextOnOrAfter(day, today0());
    const y = n.getMonth() === 0 ? n.getFullYear() - 1 : n.getFullYear();
    const m = n.getMonth() === 0 ? 11 : n.getMonth() - 1;
    return iso(dateIn(y, m, day));
  }
  function addMonthsISO(s, months, day) {
    const d = parseISO(s);
    let m = d.getMonth() + months; const y = d.getFullYear() + Math.floor(m / 12);
    m = ((m % 12) + 12) % 12;
    return iso(dateIn(y, m, day || d.getDate()));
  }
  const dueOf = (item) => iso(nextOnOrAfter(item.payDay, addDays(parseISO(item.lastPaid), 1)));
  function statusOf(dateStr) {
    const d = daysUntil(dateStr);
    const alert = state.settings.alertDays;
    if (d < 0) return { cls: 'bad', txt: `Vencido hace ${-d} ${-d === 1 ? 'día' : 'días'}`, d };
    if (d === 0) return { cls: 'bad', txt: 'Vence hoy', d };
    if (d === 1) return { cls: 'warn', txt: 'Mañana', d };
    if (d <= alert) return { cls: 'warn', txt: `En ${d} días`, d };
    return { cls: 'ok', txt: `En ${d} días`, d };
  }
  const ago = (ms) => { if (!ms) return 'nunca'; const m = Math.round((Date.now() - ms) / 60000); if (m < 1) return 'hace un momento'; if (m < 60) return `hace ${m} min`; const h = Math.round(m / 60); if (h < 24) return `hace ${h} h`; return `hace ${Math.round(h / 24)} días`; };

  /* ---------- Criptografía ---------- */
  const te = new TextEncoder(), td = new TextDecoder();
  function toB64(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
  function fromB64(s) { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function b64urlToBytes(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return fromB64(s); }
  const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  async function pbkdf2Key(secret, salt, iter = PBKDF2_ITER) {
    const base = await crypto.subtle.importKey('raw', te.encode(secret), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function pbkdf2Bits(secret, salt, iter = PBKDF2_ITER) {
    const base = await crypto.subtle.importKey('raw', te.encode(secret), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, 256));
  }
  async function hkdfKey(bytes, label) {
    const base = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: te.encode('paydar-v2'), info: te.encode(label) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  const aesImport = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  async function encBytes(key, bytes) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
  }
  async function decBytes(key, pkg) { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(pkg.iv) }, key, fromB64(pkg.ct))); }
  const encJSON = (key, obj) => encBytes(key, te.encode(JSON.stringify(obj)));
  const decJSON = async (key, pkg) => JSON.parse(td.decode(await decBytes(key, pkg)));
  const RC_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const newRecoveryCode = () => Array.from(rand(24), (b) => RC_ALPHA[b % 32]).join('').match(/.{4}/g).join('-');
  const normCode = (c) => String(c).toUpperCase().replace(/[^A-Z0-9]/g, '');
  const authSecretOf = async (email, pw) => 'pd1-' + toHex(await pbkdf2Bits(pw, te.encode('paydar-auth|' + email.trim().toLowerCase())));

  /* ---------- Estado ---------- */
  const defaultMeta = () => ({ v: 2, pin: null, bio: null, fails: 0, lockUntil: 0, dev: { notify: false, push: false }, cloud: null, sync: { rev: 0, dirty: false, lastAt: 0 }, remHash: '' });
  let meta = readJSON(K_META);
  let state = null;
  let dkBytes = null, dkKey = null, ckBytes = null, ckKey = null;
  let pendingCloud = null;     // datos recuperados de la nube antes de crear el PIN local
  let legacy = null;           // datos de la versión 1 por migrar
  let view = 'inicio', monthCursor = null;
  let lastActive = Date.now(), hiddenAt = 0;
  let saving = Promise.resolve();
  let lastIdx = {};
  let bootMsg = '';

  function readJSON(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } }
  const defaultState = () => ({ v: 2, profile: { name: '' }, settings: { alertDays: 3, cloudReminders: false }, budgets: {}, customCats: [], cards: [], bills: [], moves: [], debts: [], notified: {}, deleted: {}, psU: 0 });
  const COLLS = ['cards', 'bills', 'debts', 'moves'];
  function migrate(d) {
    const s = Object.assign(defaultState(), d || {});
    s.settings = Object.assign(defaultState().settings, s.settings || {});
    delete s.settings.notify;
    for (const k of COLLS) if (!Array.isArray(s[k])) s[k] = [];
    s.cards.forEach((c) => { if (!Array.isArray(c.promos)) c.promos = []; });
    for (const k of ['notified', 'deleted', 'budgets']) if (!s[k] || typeof s[k] !== 'object') s[k] = {};
    if (!Array.isArray(s.customCats)) s.customCats = [];
    return s;
  }
  const isEmptyState = (s) => !s.cards.length && !s.bills.length && !s.debts.length && !s.moves.length;
  function saveMeta() { try { localStorage.setItem(K_META, JSON.stringify(meta)); } catch { /* almacenamiento no disponible */ } }

  // Marca qué registros cambiaron (para combinar datos entre dispositivos)
  const itemSig = (o) => { const { u, ...r } = o; return JSON.stringify(r); };
  function snapshotIndex() {
    lastIdx = {};
    for (const c of COLLS) for (const it of state[c]) lastIdx[it.id] = itemSig(it);
    lastIdx.__ps = JSON.stringify([state.profile, state.settings, state.budgets, state.customCats]);
  }
  function stampChanges() {
    const now = Date.now(); const seen = new Set();
    for (const c of COLLS) for (const it of state[c]) {
      seen.add(it.id); const s = itemSig(it);
      if (lastIdx[it.id] !== s) { it.u = now; lastIdx[it.id] = s; }
    }
    for (const id of Object.keys(lastIdx)) if (id !== '__ps' && !seen.has(id)) { state.deleted[id] = now; delete lastIdx[id]; }
    const ps = JSON.stringify([state.profile, state.settings, state.budgets, state.customCats]);
    if (ps !== lastIdx.__ps) { state.psU = now; lastIdx.__ps = ps; }
    const old = now - 180 * 86400000;
    for (const [k, v] of Object.entries(state.deleted)) if (v < old) delete state.deleted[k];
  }
  function mergeStates(a, b) {
    const out = migrate(clone(a));
    const del = { ...(a.deleted || {}) };
    for (const [k, v] of Object.entries(b.deleted || {})) del[k] = Math.max(del[k] || 0, v);
    for (const c of COLLS) {
      const m = new Map();
      for (const it of [...(a[c] || []), ...(b[c] || [])]) { const p = m.get(it.id); if (!p || (it.u || 0) > (p.u || 0)) m.set(it.id, it); }
      out[c] = [...m.values()].filter((it) => !(del[it.id] >= (it.u || 0)));
    }
    out.deleted = del;
    if ((b.psU || 0) > (a.psU || 0)) { out.profile = b.profile; out.settings = b.settings; out.budgets = b.budgets; out.customCats = b.customCats; out.psU = b.psU; }
    out.notified = { ...(b.notified || {}), ...(a.notified || {}) };
    return migrate(out);
  }

  function writeLocal() {
    const snap = clone(state); const k = dkKey;
    saving = saving.then(async () => {
      if (!k) return;
      try { localStorage.setItem(K_DATA, JSON.stringify(await encJSON(k, snap))); }
      catch { toast('No se pudo guardar. Revisa el espacio del teléfono.'); }
    });
    return saving;
  }
  function save() {
    if (!state) return saving;
    stampChanges();
    const p = writeLocal();
    if (ckKey) { meta.sync.dirty = true; saveMeta(); scheduleSync(); }
    return p;
  }

  /* ---------- Nube (Supabase, llamadas directas) ---------- */
  class CloudError extends Error { constructor(msg, status, code) { super(msg); this.status = status; this.code = code; } }
  async function sbFetch(path, { method = 'GET', body, token, headers = {} } = {}) {
    if (!CLOUD) throw new CloudError('La nube no está configurada.', 0);
    const h = { apikey: CFG.supabaseAnonKey, 'Content-Type': 'application/json', ...headers };
    const t = token === undefined ? await accessToken() : token;
    if (t) h.Authorization = 'Bearer ' + t;
    let r;
    try { r = await fetch(CFG.supabaseUrl + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }); }
    catch { throw new CloudError('Sin conexión a internet.', 0, 'offline'); }
    const txt = await r.text(); let j = null; try { j = txt ? JSON.parse(txt) : null; } catch { /* texto */ }
    if (!r.ok) throw new CloudError(cloudMsg(j, r.status), r.status, j?.error_code || j?.code || j?.error);
    return j;
  }
  function cloudMsg(j, status) {
    const raw = String(j?.msg || j?.error_description || j?.message || j?.error || '').toLowerCase();
    if (raw.includes('invalid login')) return 'Correo o contraseña incorrectos.';
    if (raw.includes('not confirmed')) return 'Primero confirma tu correo (revisa tu bandeja y spam).';
    if (raw.includes('already registered') || raw.includes('already exists')) return 'Ese correo ya tiene cuenta. Usa "Iniciar sesión".';
    if (raw.includes('rate limit') || status === 429) return 'Demasiados intentos. Espera unos minutos.';
    if (raw.includes('invalid') && raw.includes('email')) return 'Revisa el correo electrónico.';
    if (status === 401 || status === 403) return 'Tu sesión venció. Vuelve a iniciar sesión.';
    return 'No se pudo completar. Intenta de nuevo.';
  }
  const sessFrom = (j) => ({ access: j.access_token, refresh: j.refresh_token, expiresAt: Date.now() + (Number(j.expires_in) || 3600) * 1000 });
  async function accessToken() {
    const s = meta?.cloud?.session;
    if (!s) throw new CloudError('Tu sesión venció. Vuelve a iniciar sesión.', 401, 'nosession');
    if (Date.now() < s.expiresAt - 60000) return s.access;
    try {
      const j = await sbFetch('/auth/v1/token?grant_type=refresh_token', { method: 'POST', body: { refresh_token: s.refresh }, token: null });
      meta.cloud.session = sessFrom(j); saveMeta(); return meta.cloud.session.access;
    } catch (e) {
      if (e.code !== 'offline') { meta.cloud.session = null; saveMeta(); }
      throw e;
    }
  }
  async function cloudSignIn(email, pw) {
    const secret = await authSecretOf(email, pw);
    const j = await sbFetch('/auth/v1/token?grant_type=password', { method: 'POST', body: { email: email.trim(), password: secret }, token: null });
    return { session: sessFrom(j), userId: j.user.id, email: j.user.email };
  }
  async function getVault(userId, token) {
    const rows = await sbFetch(`/rest/v1/vaults?user_id=eq.${encodeURIComponent(userId)}&select=*`, { token });
    return rows?.[0] || null;
  }
  async function createVault(pw, userId, token) {
    const ck = rand(32);
    const saltPw = rand(16), saltRec = rand(16);
    const code = newRecoveryCode();
    const wrapPw = await encBytes(await pbkdf2Key(pw, saltPw), ck);
    const wrapRec = await encBytes(await pbkdf2Key(normCode(code), saltRec, 100000), ck);
    const data = await encJSON(await aesImport(ck), state);
    await sbFetch('/rest/v1/vaults', { method: 'POST', token, body: { user_id: userId, salt_pw: toB64(saltPw), wrap_pw: wrapPw, salt_rec: toB64(saltRec), wrap_rec: wrapRec, data, rev: 1 } });
    return { ck, code };
  }
  async function attachCloud({ email, userId, session, ck, rev }) {
    ckBytes = ck; ckKey = await aesImport(ck);
    meta.cloud = { email, userId, session, ck: await encBytes(dkKey, ck) };
    meta.sync = { rev, dirty: false, lastAt: Date.now() };
    meta.remHash = '';
    saveMeta();
  }

  let syncTimer = null, syncing = false;
  function scheduleSync(ms = 2000) {
    if (!ckKey || !meta.cloud?.session) return;
    clearTimeout(syncTimer); syncTimer = setTimeout(() => syncNow().catch(() => {}), ms);
  }
  async function syncNow(manual = false, attempt = 0) {
    if (!ckKey || !state || syncing) return;
    syncing = true;
    try {
      const uidc = meta.cloud.userId;
      const r = await getVault(uidc);
      if (!r) throw new CloudError('No se encontró tu respaldo en la nube.', 404);
      if (r.rev > meta.sync.rev) {
        const remote = migrate(await decJSON(ckKey, r.data));
        state = meta.sync.dirty ? mergeStates(state, remote) : remote;
        meta.sync.rev = r.rev;
        snapshotIndex(); await writeLocal(); saveMeta();
        if (!sheet.open) render();
      }
      if (meta.sync.dirty) {
        const payload = await encJSON(ckKey, state);
        const res = await sbFetch(`/rest/v1/vaults?user_id=eq.${encodeURIComponent(uidc)}&rev=eq.${meta.sync.rev}`, {
          method: 'PATCH', headers: { Prefer: 'return=representation' }, body: { data: payload, rev: meta.sync.rev + 1, updated_at: new Date().toISOString() },
        });
        if (!res?.length) { syncing = false; if (attempt < 3) return syncNow(manual, attempt + 1); throw new CloudError('Conflicto al sincronizar.', 409); }
        meta.sync.rev += 1; meta.sync.dirty = false;
      }
      meta.sync.lastAt = Date.now(); saveMeta();
      await uploadReminders().catch(() => {});
      if (manual) toast('Sincronizado ✔');
    } catch (e) {
      if (manual) toast(e.message || 'No se pudo sincronizar.');
    } finally { syncing = false; }
  }

  /* ---------- Recordatorios en el servidor (app cerrada) ---------- */
  function reminderRows() {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'America/Mexico_City';
    const a = state.settings.alertDays;
    const base = (item_id, label, next_due, dom, interval) => ({ item_id, label: String(label).slice(0, 80), next_due, day_of_month: dom, interval_months: interval, alert_days: a, tz, lang: 'es' });
    const rows = [];
    state.cards.forEach((c) => rows.push(base('card-' + c.id, `Tarjeta ${c.alias}`, dueOf(c), c.payDay, 1)));
    state.bills.filter((b) => !b.done).forEach((b) => rows.push(base('bill-' + b.id, b.name || billLabel(b.type), b.dueDate, b.dueDay || parseISO(b.dueDate).getDate(), Number(b.recur) || 0)));
    state.debts.filter((d) => d.balance > 0).forEach((d) => rows.push(base('debt-' + d.id, d.name, dueOf(d), d.payDay, 1)));
    state.cards.forEach((c) => c.promos.filter((p) => daysUntil(p.endDate) >= 0).forEach((p) => rows.push(base('promo-' + p.id, `Promoción: ${p.title}`, p.endDate, parseISO(p.endDate).getDate(), 0))));
    return rows;
  }
  async function uploadReminders(force) {
    if (!state?.settings.cloudReminders || !meta.cloud?.session) return;
    const rows = reminderRows(); const h = JSON.stringify(rows);
    if (!force && h === meta.remHash) return;
    const u = meta.cloud.userId;
    await sbFetch(`/rest/v1/reminders?user_id=eq.${encodeURIComponent(u)}`, { method: 'DELETE' });
    if (rows.length) await sbFetch('/rest/v1/reminders', { method: 'POST', body: rows.map((r) => ({ ...r, user_id: u })) });
    meta.remHash = h; saveMeta();
  }
  async function enablePush() {
    if (!CFG.vapidPublicKey) return 'Los avisos con la app cerrada aún no están configurados en esta copia de la app.';
    if (!meta.cloud?.session) return 'Primero inicia sesión en tu cuenta.';
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
      return isApple ? 'En iPhone primero agrega la app a tu pantalla de inicio (Compartir → Agregar a inicio), ábrela desde ahí y vuelve a intentarlo.' : 'Este navegador no permite avisos. Usa Chrome.';
    }
    const reg = await navigator.serviceWorker.getRegistration();
    if (!reg) return 'Abre la app desde su dirección https para activar avisos.';
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return 'No diste permiso para avisos. Puedes activarlo en los ajustes del teléfono.';
    const sub = (await reg.pushManager.getSubscription()) || (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64urlToBytes(CFG.vapidPublicKey) }));
    const j = sub.toJSON();
    await sbFetch('/rest/v1/push_subscriptions?on_conflict=endpoint', { method: 'POST', headers: { Prefer: 'resolution=merge-duplicates' }, body: { endpoint: j.endpoint, p256dh: j.keys.p256dh, auth: j.keys.auth, user_id: meta.cloud.userId } });
    meta.dev.push = true; meta.dev.notify = true; saveMeta();
    state.settings.cloudReminders = true; save();
    await uploadReminders(true);
    return null;
  }
  async function disablePush() {
    try {
      const reg = await navigator.serviceWorker?.getRegistration();
      const sub = await reg?.pushManager?.getSubscription();
      if (sub) { await sbFetch(`/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(sub.endpoint)}`, { method: 'DELETE' }).catch(() => {}); await sub.unsubscribe(); }
    } catch { /* ignorar */ }
    meta.dev.push = false; saveMeta();
  }

  /* ---------- Biometría (WebAuthn + PRF) ---------- */
  async function bioAvailable() {
    if (TRIAL) return false;
    try { return !!window.PublicKeyCredential && window.isSecureContext && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch { return false; }
  }
  async function bioAssert(credId, prfSalt) {
    const a = await navigator.credentials.get({ publicKey: {
      challenge: rand(32), allowCredentials: [{ type: 'public-key', id: credId }], userVerification: 'required', timeout: 60000,
      extensions: { prf: { eval: { first: prfSalt } } },
    } });
    const r = a.getClientExtensionResults()?.prf?.results?.first;
    if (!r) throw new Error('noprf');
    return new Uint8Array(r);
  }
  async function enableBio() {
    const prfSalt = rand(32);
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: rand(32), rp: { name: APP }, user: { id: rand(16), name: state.profile.name || APP, displayName: state.profile.name || APP },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
      timeout: 60000, extensions: { prf: { eval: { first: prfSalt } } },
    } });
    const ext = cred.getClientExtensionResults()?.prf;
    if (!ext || ext.enabled === false) throw new Error('noprf');
    let out = ext.results?.first ? new Uint8Array(ext.results.first) : null;
    const credId = new Uint8Array(cred.rawId);
    if (!out) out = await bioAssert(credId, prfSalt);
    const w = await encBytes(await hkdfKey(out, 'bio-kek'), dkBytes);
    meta.bio = { credId: toB64(credId), prfSalt: toB64(prfSalt), ...w };
    saveMeta();
  }
  const bioErrMsg = (e) => (e?.message === 'noprf'
    ? `Este teléfono o navegador todavía no permite abrir datos cifrados con ${BIO}. Sigue usando tu PIN. (Requiere iOS 18+ o Android con Chrome actualizado.)`
    : e?.name === 'NotAllowedError' ? 'Cancelado.' : `No se pudo activar ${BIO}.`);
  async function offerBio() {
    if (meta.bio || !(await bioAvailable())) return;
    if (await confirmBox(`¿Quieres entrar con ${BIO} en lugar de escribir tu PIN?`, `Activar ${BIO}`)) {
      try { await enableBio(); toast(`Listo: ya puedes entrar con ${BIO} ✔`); } catch (e) { if (e?.name !== 'NotAllowedError') toast(bioErrMsg(e)); }
    }
  }

  /* ---------- Utilidades UI ---------- */
  let toastT;
  function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 3200); }
  function applyWidths(root = document) { $$('[data-w]', root).forEach((el) => { el.style.width = Math.max(0, Math.min(100, Number(el.dataset.w) || 0)) + '%'; }); }
  const parseMoney = (v) => { const n = Number(String(v ?? '').replace(/[$,\s]/g, '')); return Number.isFinite(n) ? round2(n) : NaN; };
  const cardById = (id) => state.cards.find((c) => c.id === id);
  const debtById = (id) => state.debts.find((c) => c.id === id);
  const billById = (id) => state.bills.find((c) => c.id === id);
  const methodOptions = () => [{ v: 'cash', l: 'Efectivo o débito' }, ...state.cards.map((c) => ({ v: 'card:' + c.id, l: `Tarjeta ${c.alias}${c.last4 ? ' ••' + c.last4 : ''}` }))];
  const dayOptions = () => Array.from({ length: 31 }, (_, i) => ({ v: String(i + 1), l: `Día ${i + 1}` }));
  const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);

  /* ---------- Formularios (hoja inferior) ---------- */
  function fieldHTML(f) {
    const id = 'f_' + f.name;
    const req = f.required ? ' required' : '';
    const help = f.help ? `<div class="help">${esc(f.help)}</div>` : '';
    const val = f.value ?? '';
    let inner = '';
    switch (f.type) {
      case 'money':
        inner = `<div class="money"><span>$</span><input id="${id}" name="${f.name}" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${val === '' ? '' : esc(val)}"${req}></div>`;
        if (f.quick?.length) inner += `<div class="quick">${f.quick.map((q) => `<button type="button" class="btn soft sm" data-quick="${esc(q.v)}" data-for="${id}">${esc(q.l)}: ${money(q.v)}</button>`).join('')}</div>`;
        break;
      case 'select':
        inner = `<select id="${id}" name="${f.name}"${req}>${f.options.map((o) => `<option value="${esc(o.v)}"${String(o.v) === String(val) ? ' selected' : ''}>${esc(o.l)}</option>`).join('')}</select>`;
        break;
      case 'seg':
        return `<div class="field"><label>${esc(f.label)}</label><div class="seg" role="radiogroup">${f.options.map((o) => `<label><input type="radio" name="${f.name}" value="${esc(o.v)}"${String(o.v) === String(val) ? ' checked' : ''}><span>${esc(o.l)}</span></label>`).join('')}</div>${help}</div>`;
      case 'pin':
        inner = `<input id="${id}" name="${f.name}" type="password" inputmode="numeric" autocomplete="off" maxlength="${PIN_LEN}" placeholder="${'•'.repeat(PIN_LEN)}"${req}>`;
        break;
      case 'password':
        inner = `<input id="${id}" name="${f.name}" type="password" autocomplete="${f.autocomplete || 'current-password'}" maxlength="128"${req}>`;
        break;
      case 'email':
        inner = `<input id="${id}" name="${f.name}" type="email" inputmode="email" autocomplete="email" autocapitalize="off" maxlength="120" value="${esc(val)}"${req}>`;
        break;
      case 'two':
        return `<div class="two">${f.fields.map(fieldHTML).join('')}</div>`;
      case 'html':
        return f.html;
      default:
        inner = `<input id="${id}" name="${f.name}" type="${f.type || 'text'}" value="${esc(val)}" maxlength="${f.max || 60}" autocomplete="off"${f.inputmode ? ` inputmode="${f.inputmode}"` : ''}${f.autocap === false ? ' autocapitalize="characters"' : ''}${f.placeholder ? ` placeholder="${esc(f.placeholder)}"` : ''}${req}>`;
    }
    return `<div class="field"><label for="${id}">${esc(f.label)}</label>${inner}${help}</div>`;
  }
  const flatFields = (fs) => fs.flatMap((f) => (f.type === 'two' ? f.fields : [f])).filter((f) => f.name);

  function readForm(form, fields) {
    const vals = {};
    for (const f of flatFields(fields)) {
      let v;
      if (f.type === 'seg') v = ($(`input[name="${f.name}"]:checked`, form) || {}).value;
      else if (f.type === 'password') v = form.elements[f.name]?.value ?? '';
      else v = form.elements[f.name]?.value?.trim();
      if (f.type === 'money') {
        if (v === '' && !f.required) { vals[f.name] = 0; continue; }
        v = parseMoney(v);
        if (!Number.isFinite(v) || v < 0 || (f.required && v === 0 && !f.allowZero)) return { err: `Escribe una cantidad válida en "${f.label}".` };
      }
      if (f.required && (v === undefined || v === '')) return { err: `Falta llenar "${f.label}".` };
      if (f.type === 'pin' && v && !new RegExp(`^\\d{${PIN_LEN}}$`).test(v)) return { err: `El PIN debe tener ${PIN_LEN} números.` };
      if (f.type === 'email' && v && !validEmail(v)) return { err: 'Revisa el correo electrónico.' };
      if (f.pattern && v && !f.pattern.test(v)) return { err: f.patternMsg || `Revisa "${f.label}".` };
      vals[f.name] = v;
    }
    return { vals };
  }

  function openForm({ title, fields, submitLabel = 'Guardar', onSubmit, danger, extraButtons = [], banner = '' }) {
    sheet.innerHTML = `<form class="sheet-form" novalidate>
      <div class="sheet-head"><h2>${esc(title)}</h2><button type="button" class="icon-btn" data-close aria-label="Cerrar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div>
      ${banner}${fields.map(fieldHTML).join('')}
      <p class="form-err" hidden></p>
      <div class="sheet-actions">${danger ? `<button type="button" class="btn ghost danger" data-danger>${esc(danger.label)}</button>` : ''}${extraButtons.map((b, i) => `<button type="button" class="btn ghost" data-extra="${i}">${esc(b.label)}</button>`).join('')}<button class="btn primary" type="submit">${esc(submitLabel)}</button></div>
    </form>`;
    const form = $('form', sheet);
    const err = $('.form-err', form);
    const btn = $('button[type="submit"]', form);
    const showErr = (m) => { err.textContent = m; err.hidden = false; err.scrollIntoView({ block: 'nearest' }); };
    $$('[data-quick]', form).forEach((b) => b.addEventListener('click', () => { $('#' + b.dataset.for, form).value = b.dataset.quick; }));
    if (danger) $('[data-danger]', form).addEventListener('click', async () => { if (await confirmBox(danger.confirm || '¿Seguro?')) danger.run(); });
    extraButtons.forEach((b, i) => $(`[data-extra="${i}"]`, form).addEventListener('click', () => b.run(form)));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const { vals, err: e1 } = readForm(form, fields);
      if (e1) return showErr(e1);
      const label = btn.textContent; btn.disabled = true; btn.textContent = 'Un momento…'; err.hidden = true;
      try {
        const res = await onSubmit(vals);
        if (typeof res === 'string') { btn.disabled = false; btn.textContent = label; return showErr(res); }
        if (res !== false && sheet.contains(form)) closeSheet();
      } catch (ex) { btn.disabled = false; btn.textContent = label; showErr(ex instanceof CloudError ? ex.message : 'Ocurrió un error. Intenta de nuevo.'); }
    });
    openSheet();
    const first = $('input:not([type=radio]),select', form);
    if (first && matchMedia('(pointer:fine)').matches) first.focus();
  }
  function openSheet() { if (!sheet.open) sheet.showModal(); }
  function closeSheet() { if (sheet.open) sheet.close(); sheet.innerHTML = ''; }
  sheet.addEventListener('click', (e) => { if (e.target === sheet || e.target.closest('[data-close]')) closeSheet(); });
  sheet.addEventListener('cancel', (e) => { e.preventDefault(); closeSheet(); });

  function confirmBox(msg, okLabel = 'Sí, continuar') {
    return new Promise((resolve) => {
      const d = document.createElement('dialog');
      d.className = 'confirm';
      d.innerHTML = `<div class="sheet-form"><h2>${esc(msg)}</h2><div class="sheet-actions"><button class="btn ghost" data-no>Cancelar</button><button class="btn primary" data-yes>${esc(okLabel)}</button></div></div>`;
      document.body.appendChild(d); d.showModal();
      const done = (v) => { d.close(); d.remove(); resolve(v); };
      $('[data-yes]', d).onclick = () => done(true);
      $('[data-no]', d).onclick = () => done(false);
      d.addEventListener('cancel', (e) => { e.preventDefault(); done(false); });
    });
  }
  function infoSheet(title, html, okLabel = 'Entendido', onOk) {
    sheet.innerHTML = `<div class="sheet-form"><div class="sheet-head"><h2>${esc(title)}</h2></div>${html}<div class="sheet-actions"><button class="btn primary" data-ok>${esc(okLabel)}</button></div></div>`;
    openSheet();
    $('[data-ok]', sheet).onclick = () => { closeSheet(); onOk?.(); };
  }
  function showRecoveryCode(code, onDone) {
    sheet.innerHTML = `<div class="sheet-form">
      <div class="sheet-head"><h2>Tu código de recuperación</h2></div>
      <p class="note">Si olvidas tu contraseña, este código es <b>la única forma</b> de recuperar tus datos. Nadie más lo tiene, ni nosotros. Guárdalo fuera del teléfono (en papel o en tu gestor de contraseñas).</p>
      <div class="code">${esc(code)}</div>
      <div class="btn-row"><button class="btn soft" data-copy>Copiar</button><button class="btn soft" data-dl>Descargar</button></div>
      <label class="check"><input type="checkbox" data-ok-check> Ya lo guardé en un lugar seguro</label>
      <div class="sheet-actions"><button class="btn primary" data-ok disabled>Continuar</button></div></div>`;
    openSheet();
    sheet.oncancel = (e) => e.preventDefault();
    $('[data-copy]', sheet).onclick = async () => { try { await navigator.clipboard.writeText(code); toast('Copiado'); } catch { toast('No se pudo copiar; escríbelo a mano.'); } };
    $('[data-dl]', sheet).onclick = () => download(`${APP.toLowerCase()}-codigo-recuperacion.txt`, `${APP} — código de recuperación\r\n\r\n${code}\r\n\r\nGuárdalo en un lugar seguro. Sirve para recuperar tus datos si olvidas tu contraseña.\r\n`, 'text/plain');
    $('[data-ok-check]', sheet).onchange = (e) => { $('[data-ok]', sheet).disabled = !e.target.checked; };
    $('[data-ok]', sheet).onclick = () => { sheet.oncancel = null; closeSheet(); onDone?.(); };
  }

  /* ---------- Movimientos y efectos ---------- */
  function applyEffect(ef, sign) {
    const t = ef.kind === 'card' ? cardById(ef.id) : ef.kind === 'debt' ? debtById(ef.id) : null;
    if (t) t.balance = round2(Math.max(0, (Number(t.balance) || 0) + sign * ef.delta));
  }
  function addMove(m) {
    const mv = Object.assign({ id: uid(), effects: [], restore: [] }, m);
    if (mv.type === 'gasto' && mv.method?.startsWith('card:')) mv.effects.push({ kind: 'card', id: mv.method.slice(5), delta: mv.amount });
    mv.effects.forEach((ef) => applyEffect(ef, 1));
    state.moves.push(mv);
    return mv;
  }
  function deleteMove(id) {
    const i = state.moves.findIndex((m) => m.id === id); if (i < 0) return;
    const m = state.moves[i];
    (m.effects || []).forEach((ef) => applyEffect(ef, -1));
    (m.restore || []).forEach((r) => {
      const coll = r.kind === 'card' ? state.cards : r.kind === 'debt' ? state.debts : state.bills;
      const t = coll.find((x) => x.id === r.id); if (t) Object.assign(t, r.fields);
    });
    state.moves.splice(i, 1);
  }

  /* ---------- Próximos pagos ---------- */
  function upcoming() {
    const out = [];
    for (const c of state.cards) {
      const amt = Number(c.noInterest) > 0 ? c.noInterest : 0;
      out.push({ kind: 'card', id: c.id, icon: 'card', title: `Tarjeta ${c.alias}`, sub: amt > 0 ? 'Pago para no generar intereses' : 'Sin monto por pagar registrado', amount: amt, date: dueOf(c), act: 'pay-card' });
    }
    for (const b of state.bills) if (!b.done) out.push({ kind: 'bill', id: b.id, icon: b.type, title: b.name || billLabel(b.type), sub: billLabel(b.type), amount: b.amount, date: b.dueDate, act: 'pay-bill' });
    for (const d of state.debts) if (d.balance > 0) out.push({ kind: 'debt', id: d.id, icon: 'debt', title: d.name, sub: `Mensualidad · ${d.lender || 'Préstamo'}`, amount: Math.min(d.monthly, d.balance), date: dueOf(d), act: 'pay-debt' });
    return out.sort((a, b) => a.date.localeCompare(b.date));
  }
  function promosSoon(limitDays = 30) {
    const out = [];
    for (const c of state.cards) for (const p of c.promos) { const d = daysUntil(p.endDate); if (d >= -1 && d <= limitDays) out.push({ card: c, promo: p, d }); }
    return out.sort((a, b) => a.d - b.d);
  }
  function monthMoves(y, m) { const pre = `${y}-${pad2(m + 1)}`; return state.moves.filter((x) => x.date.startsWith(pre)); }
  function monthTotals(y, m) {
    const mv = monthMoves(y, m);
    const sum = (t) => round2(mv.filter((x) => x.type === t).reduce((s, x) => s + x.amount, 0));
    const ing = sum('ingreso'), gas = sum('gasto'), pag = sum('pago');
    return { ing, gas, pag, bal: round2(ing - gas), mv };
  }

  /* ---------- Render principal ---------- */
  const TABS = [
    { v: 'inicio', l: 'Inicio', i: 'home' }, { v: 'tarjetas', l: 'Tarjetas', i: 'card' }, { v: 'pagos', l: 'Servicios', i: 'bill' },
    { v: 'movimientos', l: 'Gastos', i: 'swap' }, { v: 'deudas', l: 'Deudas', i: 'debt' },
  ];
  const TITLES = { inicio: 'Resumen', tarjetas: 'Mis tarjetas', pagos: 'Servicios y pagos fijos', movimientos: 'Gastos y presupuesto', deudas: 'Deudas' };

  function render() {
    if (!state) return;
    const name = state.profile.name ? `Hola, ${esc(state.profile.name)}` : 'Hola';
    const cloudBad = meta.cloud && !meta.cloud.session;
    app.innerHTML = `
      <header class="top"><div class="t"><div class="hello">${name}</div><h1>${TITLES[view]}</h1></div>
        <button class="icon-btn" data-act="lock" aria-label="Bloquear">${icon('lock')}</button>
        <button class="icon-btn${cloudBad ? ' dot' : ''}" data-act="settings" aria-label="Ajustes">${icon('gear')}</button></header>
      <main class="wrap" id="main">${TRIAL ? '<div class="banner warn">'+icon('alert')+'<span>Versión de prueba. No guardes aquí tus datos reales: pueden borrarse.</span></div>' : ''}${cloudBad ? `<button class="banner warn" data-act="settings">${icon('cloud')}<span>Tu respaldo en la nube está en pausa. Toca aquí para volver a iniciar sesión.</span></button>` : ''}${VIEWS[view]()}</main>
      <nav class="tabs" aria-label="Secciones"><div class="in">${TABS.map((t) => `<button class="tab" data-act="go" data-id="${t.v}"${t.v === view ? ' aria-current="page"' : ''}>${icon(t.i)}<span>${t.l}</span></button>`).join('')}</div></nav>
      <button class="fab" data-act="quick" aria-label="Agregar">${icon('plus')}</button>`;
    applyWidths(app);
  }

  function eventRow(ev) {
    const st = statusOf(ev.date);
    return `<div class="row"><div class="ico ${st.cls === 'ok' ? '' : st.cls}">${icon(ev.icon)}</div>
      <div class="main"><div class="ttl">${esc(ev.title)}</div><div class="sub">${esc(ev.sub)} · ${fmtDate(ev.date)}</div></div>
      <div class="end"><span class="amt">${ev.amount ? money(ev.amount) : '—'}</span><span class="chip ${st.cls}">${st.txt}</span>
      <button class="btn primary sm" data-act="${ev.act}" data-id="${ev.id}">Pagar</button></div></div>`;
  }

  const VIEWS = {
    inicio() {
      const now = new Date();
      const t = monthTotals(now.getFullYear(), now.getMonth());
      if (isEmptyState(state)) {
        return `<div class="panel pad section"><div class="empty"><h3>Empecemos en 3 pasos</h3><p>Agrega lo que pagas cada mes y ${APP} te avisará antes de cada vencimiento.</p></div>
          <div class="start">
            <button class="btn soft" data-act="new-card">${icon('card')}<span><b>1. Agrega tu tarjeta de crédito</b><br><small>Día de corte, día de pago y promociones</small></span></button>
            <button class="btn soft" data-act="new-bill">${icon('luz')}<span><b>2. Agrega tus servicios</b><br><small>Luz, agua, gas, internet, celular</small></span></button>
            <button class="btn soft" data-act="new-move" data-id="ingreso">${icon('up')}<span><b>3. Registra tu ingreso</b><br><small>Sueldo, honorarios, ventas…</small></span></button>
          </div><p class="note section">💡 También puedes <b>dictar</b> o <b>tomar foto</b> de un ticket, recibo o estado de cuenta: botón <b>+</b>.</p></div>
          <p class="note section">🔒 Tus datos están cifrados con tu PIN. ${CLOUD && !meta.cloud ? 'Crea tu cuenta en Ajustes para tener respaldo automático y no perder nada si cambias de teléfono.' : ''}</p>`;
      }
      const ev = upcoming();
      const overdue = ev.filter((e) => daysUntil(e.date) < 0);
      const next30 = ev.filter((e) => daysUntil(e.date) <= 30);
      const week = round2(ev.filter((e) => daysUntil(e.date) <= 7).reduce((s, e) => s + (Number(e.amount) || 0), 0));
      const cardDebt = round2(state.cards.reduce((s, c) => s + (Number(c.balance) || 0), 0));
      const otherDebt = round2(state.debts.reduce((s, d) => s + (Number(d.balance) || 0), 0));
      const promos = promosSoon(30);
      const cats = categoryBars(t.mv);
      const nudge = CLOUD && !meta.cloud ? `<button class="banner warn" data-act="settings">${icon('cloud')}<span>Tus datos solo están en este teléfono. Crea tu cuenta para respaldarlos automáticamente.</span></button>` : '';
      return `
        ${overdue.length ? `<div class="banner">${icon('alert')}<span>Tienes ${overdue.length} ${overdue.length === 1 ? 'pago vencido' : 'pagos vencidos'}. Págalo${overdue.length === 1 ? '' : 's'} cuanto antes para evitar recargos.</span></div>` : ''}
        ${nudge}
        ${(() => { const bs = budgetStatus(now.getFullYear(), now.getMonth()); const over = bs.rows.filter((r) => r.pct >= 100); return over.length ? `<button class="banner warn" data-act="go" data-id="movimientos">${icon('target')}<span>Te pasaste del presupuesto en ${over.map((r) => esc(r.cat)).join(', ')}.</span></button>` : ''; })()}
        <div class="capture section"><button class="btn primary" data-act="dictate">${icon('mic')} Dictar</button><button class="btn primary" data-act="photo">${icon('camera')} Tomar foto</button></div>
        <div class="tiles section">
          <div class="panel tile hero"><div class="lbl">Te queda este mes (${MES[now.getMonth()]})</div><div class="val">${money(t.bal)}</div><div class="foot">Ingresos ${money(t.ing)} · Gastos ${money(t.gas)}</div></div>
          <div class="panel tile"><div class="lbl">Por pagar en 7 días</div><div class="val">${money(week)}</div></div>
          <div class="panel tile"><div class="lbl">Saldo en tarjetas</div><div class="val">${money(cardDebt)}</div></div>
          <div class="panel tile"><div class="lbl">Otras deudas</div><div class="val">${money(otherDebt)}</div></div>
          <div class="panel tile"><div class="lbl">Pagado a tarjetas</div><div class="val">${money(t.pag)}</div></div>
        </div>
        <div class="section"><div class="section-h"><h2>Próximos pagos</h2><span class="chip">30 días</span></div>
          <div class="panel list">${next30.length ? next30.map(eventRow).join('') : '<div class="empty">No tienes pagos en los próximos 30 días. 🎉</div>'}</div></div>
        ${promos.length ? `<div class="section"><div class="section-h"><h2>Promociones por vencer</h2></div><div class="panel list">${promos.map(promoRow).join('')}</div></div>` : ''}
        <div class="section"><div class="section-h"><h2>Presupuesto del mes</h2><button class="lnk" data-act="${Object.keys(state.budgets).length ? 'go' : 'budget'}" data-id="movimientos">${Object.keys(state.budgets).length ? 'Ver todo' : 'Definir'}</button></div>${budgetBlock(now.getFullYear(), now.getMonth(), true)}</div>
        <div class="section"><div class="section-h"><h2>¿En qué se va mi dinero?</h2><button class="lnk" data-act="go" data-id="movimientos">Ver todo</button></div>
          <div class="panel pad">${cats || '<div class="empty">Aún no registras gastos este mes.</div>'}</div></div>`;
    },

    tarjetas() {
      if (!state.cards.length) return `<div class="panel section"><div class="empty"><h3>Sin tarjetas todavía</h3><p>Agrega tu tarjeta con su día de corte y de pago. Solo pedimos un nombre y, si quieres, los últimos 4 dígitos.</p><button class="btn primary" data-act="new-card">${icon('plus')} Agregar tarjeta</button></div></div>`;
      return `<div class="section">${state.cards.map(cardBlock).join('')}</div>
        <button class="btn soft block" data-act="new-card">${icon('plus')} Agregar otra tarjeta</button>`;
    },

    pagos() {
      const bills = state.bills.filter((b) => !b.done).sort((a, b) => a.dueDate.localeCompare(b.dueDate));
      const recent = state.moves.filter((m) => m.billId).sort((a, b) => b.date.localeCompare(a.date)).slice(0, 6);
      if (!state.bills.length) return `<div class="panel section"><div class="empty"><h3>Agrega tus servicios y pagos fijos</h3><p>Luz, agua, gas, internet, celular, renta, colegiaturas, seguros, suscripciones… Te avisamos antes de que venzan.</p><button class="btn primary" data-act="new-bill">${icon('plus')} Agregar</button></div></div>`;
      const total = round2(bills.filter((b) => daysUntil(b.dueDate) <= 30).reduce((s, b) => s + (Number(b.amount) || 0), 0));
      return `
        <div class="tiles section"><div class="panel tile hero"><div class="lbl">Servicios por pagar (30 días)</div><div class="val">${money(total)}</div></div></div>
        <div class="section"><div class="section-h"><h2>Pendientes</h2></div><div class="panel list">
          ${bills.length ? bills.map((b) => { const st = statusOf(b.dueDate); return `<div class="row"><div class="ico ${st.cls === 'ok' ? '' : st.cls}">${icon(b.type)}</div>
            <div class="main"><div class="ttl">${esc(b.name || billLabel(b.type))}</div><div class="sub">${esc(RECUR.find((r) => r.v === String(b.recur))?.l || '')} · vence ${fmtDate(b.dueDate)}</div></div>
            <div class="end"><span class="amt">${money(b.amount)}</span><span class="chip ${st.cls}">${st.txt}</span>
            <div class="btn-row"><button class="btn ghost sm" data-act="edit-bill" data-id="${b.id}">Editar</button><button class="btn primary sm" data-act="pay-bill" data-id="${b.id}">Pagar</button></div></div></div>`; }).join('') : '<div class="empty">Todo al corriente. 🎉</div>'}
        </div></div>
        ${recent.length ? `<div class="section"><div class="section-h"><h2>Pagados recientemente</h2></div><div class="panel list">${recent.map(moveRow).join('')}</div></div>` : ''}
        <div class="section"><button class="btn soft block" data-act="new-bill">${icon('plus')} Agregar servicio</button></div>`;
    },

    movimientos() {
      const now = new Date();
      if (!monthCursor) monthCursor = { y: now.getFullYear(), m: now.getMonth() };
      const { y, m } = monthCursor;
      const t = monthTotals(y, m);
      const list = [...t.mv].sort((a, b) => b.date.localeCompare(a.date));
      return `
        <div class="month-nav section"><button class="icon-btn" data-act="month" data-id="-1" aria-label="Mes anterior">${icon('left')}</button><b>${MES[m]} ${y}</b><button class="icon-btn" data-act="month" data-id="1" aria-label="Mes siguiente">${icon('right')}</button></div>
        <div class="tiles section">
          <div class="panel tile hero"><div class="lbl">Balance del mes</div><div class="val">${money(t.bal)}</div></div>
          <div class="panel tile"><div class="lbl">Ingresos</div><div class="val pos">${money(t.ing)}</div></div>
          <div class="panel tile"><div class="lbl">Gastos</div><div class="val neg">${money(t.gas)}</div></div>
        </div>
        <div class="btn-row section"><button class="btn primary" data-act="new-move" data-id="gasto">${icon('down')} Gasto</button><button class="btn soft" data-act="new-move" data-id="ingreso">${icon('up')} Ingreso</button><button class="btn soft" data-act="dictate">${icon('mic')} Dictar</button><button class="btn soft" data-act="photo">${icon('camera')} Foto</button></div>
        <div class="section"><div class="section-h"><h2>Presupuesto de ${MES[m]}</h2>${Object.keys(state.budgets).length ? '<button class="lnk" data-act="budget">Editar</button>' : ''}</div>${budgetBlock(y, m, false)}</div>
        ${t.gas ? `<div class="section"><div class="section-h"><h2>Gastos por categoría</h2></div><div class="panel pad">${categoryBars(t.mv)}</div></div>` : ''}
        <div class="section"><div class="section-h"><h2>Detalle</h2><span class="chip">${list.length}</span></div>
          <div class="panel list">${list.length ? list.map(moveRow).join('') : '<div class="empty">Sin movimientos en este mes.</div>'}</div></div>
        <p class="note section">Las compras con tarjeta cuentan como gasto el día que compras. El pago a la tarjeta no se vuelve a contar como gasto (se muestra como "pago").</p>`;
    },

    deudas() {
      if (!state.debts.length) return `<div class="panel section"><div class="empty"><h3>Sin deudas registradas</h3><p>Préstamos personales, crédito de auto, hipoteca, préstamos de familiares… Lleva el saldo y la fecha de cada mensualidad.</p><button class="btn primary" data-act="new-debt">${icon('plus')} Agregar deuda</button></div></div>`;
      const total = round2(state.debts.reduce((s, d) => s + (Number(d.balance) || 0), 0));
      const monthly = round2(state.debts.filter((d) => d.balance > 0).reduce((s, d) => s + (Number(d.monthly) || 0), 0));
      return `
        <div class="tiles section"><div class="panel tile hero"><div class="lbl">Total que debo (sin tarjetas)</div><div class="val">${money(total)}</div><div class="foot">Mensualidades: ${money(monthly)} al mes</div></div></div>
        <div class="section panel list">${state.debts.map((d) => {
          const paidPct = d.original > 0 ? ((d.original - d.balance) / d.original) * 100 : 0;
          const done = d.balance <= 0;
          const st = done ? { cls: 'ok', txt: 'Liquidada' } : statusOf(dueOf(d));
          const left = !done && d.monthly > 0 ? Math.ceil(d.balance / d.monthly) : 0;
          return `<div class="row"><div class="ico ${st.cls === 'ok' ? '' : st.cls}">${icon('debt')}</div>
            <div class="main"><div class="ttl">${esc(d.name)}</div><div class="sub">${esc(d.lender || '')}${done ? '' : ` · ${money(d.monthly)}/mes · próximo ${fmtDate(dueOf(d))}${left ? ` · faltan ~${left} pagos` : ''}`}</div>
              <div class="track"><div class="fill" data-w="${paidPct.toFixed(1)}"></div></div><div class="sub">Pagado ${paidPct.toFixed(0)}% · Debo ${money(d.balance)}</div></div>
            <div class="end"><span class="chip ${st.cls}">${st.txt}</span><div class="btn-row"><button class="btn ghost sm" data-act="edit-debt" data-id="${d.id}">Editar</button>${done ? '' : `<button class="btn primary sm" data-act="pay-debt" data-id="${d.id}">Pagar</button>`}</div></div></div>`;
        }).join('')}</div>
        <div class="section"><button class="btn soft block" data-act="new-debt">${icon('plus')} Agregar deuda</button></div>`;
    },
  };

  function categoryBars(moves) {
    const g = {};
    moves.filter((m) => m.type === 'gasto').forEach((m) => { g[m.category] = round2((g[m.category] || 0) + m.amount); });
    const arr = Object.entries(g).sort((a, b) => b[1] - a[1]);
    if (!arr.length) return '';
    const total = arr.reduce((s, x) => s + x[1], 0);
    return `<div class="bars">${arr.map(([c, v]) => `<div><div class="bar-h"><span>${esc(c)}</span><b>${money(v)} · ${Math.round((v / total) * 100)}%</b></div><div class="track"><div class="fill" data-w="${((v / arr[0][1]) * 100).toFixed(1)}"></div></div></div>`).join('')}</div>`;
  }
  function moveRow(m) {
    const card = m.method?.startsWith('card:') ? cardById(m.method.slice(5)) : null;
    const sign = m.type === 'ingreso' ? '+' : m.type === 'gasto' ? '−' : '';
    const cls = m.type === 'ingreso' ? 'pos' : m.type === 'gasto' ? 'neg' : '';
    const ic = m.type === 'ingreso' ? 'up' : m.type === 'pago' ? 'card' : 'down';
    const sub = [fmtDate(m.date), m.type === 'pago' ? 'Pago a tarjeta' : m.category, card ? `con ${card.alias}` : ''].filter(Boolean).join(' · ');
    return `<div class="row" data-act="edit-move" data-id="${m.id}" role="button" tabindex="0"><div class="ico">${icon(ic)}</div>
      <div class="main"><div class="ttl">${esc(m.note || m.category || 'Movimiento')}</div><div class="sub">${esc(sub)}</div></div>
      <div class="end"><span class="amt ${cls}">${sign}${money(m.amount)}</span></div></div>`;
  }
  function promoRow({ card, promo, d }) {
    const cls = d <= 3 ? 'bad' : d <= 10 ? 'warn' : 'ok';
    const txt = d < 0 ? 'Venció' : d === 0 ? 'Termina hoy' : `Termina en ${d} días`;
    return `<div class="row"><div class="ico ${cls === 'ok' ? '' : cls}">${icon('tag')}</div><div class="main"><div class="ttl">${esc(promo.title)}</div><div class="sub">Tarjeta ${esc(card.alias)} · hasta ${fmtDate(promo.endDate)}${promo.note ? ' · ' + esc(promo.note) : ''}</div></div><div class="end"><span class="chip ${cls}">${txt}</span></div></div>`;
  }
  function cardBlock(c, i) {
    const util = c.limit > 0 ? (c.balance / c.limit) * 100 : 0;
    const ucls = util > 70 ? 'bad' : util > 30 ? 'warn' : '';
    const due = dueOf(c); const st = statusOf(due);
    const cut = iso(nextOnOrAfter(c.cutDay, today0()));
    const best = (c.cutDay % 31) + 1;
    return `<div class="panel cc-card">
      <div class="cc cc-${(c.color ?? i) % 6}">
        <div class="cc-top"><span>${esc(c.alias)}</span><span class="bank">${esc(c.bank || '')}</span></div>
        <div class="cc-num">•••• •••• •••• ${esc(c.last4 || '····')}</div>
        <div class="cc-sub">Saldo actual</div><div class="cc-bal">${money(c.balance)}</div>
        ${c.limit > 0 ? `<div class="track"><div class="fill ${ucls}" data-w="${util.toFixed(1)}"></div></div><div class="cc-sub">Usas ${util.toFixed(0)}% de ${money(c.limit)} · disponible ${money(Math.max(0, c.limit - c.balance))}</div>` : ''}
      </div>
      <div class="cc-info">
        <div><div class="k">Fecha límite de pago</div><div class="v">${fmtDate(due)} <span class="chip ${st.cls}">${st.txt}</span></div></div>
        <div><div class="k">Próximo corte</div><div class="v">${fmtDate(cut)} <span class="chip">en ${daysUntil(cut)} d</span></div></div>
        <div><div class="k">Pago para no generar intereses</div><div class="v">${money(c.noInterest)}</div></div>
        <div><div class="k">Pago mínimo</div><div class="v">${money(c.minPay)}</div></div>
      </div>
      <div class="tip">💡 Mejor día para comprar: el <b>${best}</b> de cada mes (justo después del corte, tienes más días para pagar).${util > 30 ? ' Procura usar menos del 30% de tu línea para cuidar tu historial.' : ''}</div>
      ${c.promos.slice().sort((a, b) => a.endDate.localeCompare(b.endDate)).map((p) => { const d = daysUntil(p.endDate); const cls = d < 0 ? '' : d <= 3 ? 'bad' : d <= 10 ? 'warn' : 'ok'; return `<div class="promo">${icon('tag')}<div class="main"><b>${esc(p.title)}</b><div class="sub">hasta ${fmtDate(p.endDate)}${p.note ? ' · ' + esc(p.note) : ''}</div></div><span class="chip ${cls}">${d < 0 ? 'Vencida' : d === 0 ? 'Hoy' : d + ' d'}</span><button class="icon-btn" data-act="del-promo" data-id="${c.id}|${p.id}" aria-label="Quitar promoción">${icon('trash')}</button></div>`; }).join('')}
      <div class="cc-actions">
        <button class="btn primary sm" data-act="pay-card" data-id="${c.id}">Pagar</button>
        <button class="btn soft sm" data-act="statement" data-id="${c.id}">Nuevo estado de cuenta</button>
        <button class="btn soft sm" data-act="new-promo" data-id="${c.id}">+ Promoción</button>
        <button class="btn ghost sm" data-act="edit-card" data-id="${c.id}">Editar</button>
      </div></div>`;
  }

  /* ---------- Acciones ---------- */
  function commit(msg) { save(); render(); if (msg) toast(msg); }

  const ACTIONS = {
    go(v) { view = v; window.scrollTo(0, 0); render(); },
    lock() { lock(); },
    month(dir) { const d = new Date(monthCursor.y, monthCursor.m + Number(dir), 1); monthCursor = { y: d.getFullYear(), m: d.getMonth() }; render(); },
    quick() {
      sheet.innerHTML = `<div class="sheet-form"><div class="sheet-head"><h2>¿Qué quieres hacer?</h2><button type="button" class="icon-btn" data-close aria-label="Cerrar">✕</button></div>
        <div class="capture"><button class="btn primary" data-act="dictate">${icon('mic')} Dictar</button><button class="btn primary" data-act="photo">${icon('camera')} Foto</button></div>
        <p class="note">Dicta o fotografía un ticket, recibo, estado de cuenta o promoción y llenamos el formulario por ti.</p>
        <div class="menu">
          <button class="btn soft" data-act="new-move" data-id="gasto">${icon('down')} Registrar un gasto</button>
          <button class="btn soft" data-act="new-move" data-id="ingreso">${icon('up')} Registrar un ingreso</button>
          <button class="btn soft" data-act="new-bill">${icon('bill')} Agregar servicio o pago fijo (luz, renta, colegiatura…)</button>
          <button class="btn soft" data-act="budget">${icon('target')} Definir presupuesto mensual</button>
          <button class="btn soft" data-act="new-card">${icon('card')} Agregar tarjeta de crédito</button>
          <button class="btn soft" data-act="new-debt">${icon('debt')} Agregar deuda o préstamo</button>
        </div></div>`;
      openSheet();
    },
    'new-card'(_, pre) { cardForm(null, pre); },
    'edit-card'(id) { cardForm(cardById(id)); },
    statement(id, pre = {}) {
      const c = cardById(id);
      openForm({
        title: `Estado de cuenta · ${c.alias}`, submitLabel: 'Actualizar', banner: pre.banner,
        fields: [
          ...(pre.banner ? [] : [{ type: 'html', html: '<p class="note">Copia estos datos de tu estado de cuenta o tómale una foto con el botón + → Foto.</p>' }]),
          { name: 'balance', label: 'Saldo actual', type: 'money', value: pre.balance ?? c.balance, allowZero: true },
          { type: 'two', fields: [
            { name: 'noInterest', label: 'Pago para no generar intereses', type: 'money', value: pre.noInterest ?? c.noInterest, allowZero: true },
            { name: 'minPay', label: 'Pago mínimo', type: 'money', value: pre.minPay ?? c.minPay, allowZero: true }] },
          ...(pre.payDate ? [{ name: 'payDate', label: 'Fecha límite de pago', type: 'date', value: pre.payDate }] : []),
        ],
        onSubmit(v) {
          const { payDate, ...rest } = v; Object.assign(c, rest);
          if (payDate) { const d = parseISO(payDate).getDate(); if (d !== c.payDay) c.payDay = d; c.lastPaid = iso(dateIn(parseISO(payDate).getFullYear(), parseISO(payDate).getMonth() - 1, d)); }
          if (pre.cutDay) c.cutDay = pre.cutDay;
          commit('Estado de cuenta actualizado');
        },
      });
    },
    'pay-card'(id, pre = {}) {
      const c = cardById(id); const due = dueOf(c);
      openForm({
        title: `Pagar tarjeta ${c.alias}`, submitLabel: 'Registrar pago', banner: pre.banner,
        fields: [
          { name: 'amount', label: '¿Cuánto pagaste?', type: 'money', required: true, value: pre.amount ?? (c.noInterest || ''), quick: [c.noInterest > 0 && { l: 'Sin intereses', v: c.noInterest }, c.minPay > 0 && { l: 'Mínimo', v: c.minPay }].filter(Boolean),
            help: 'Pagar solo el mínimo genera intereses altos. Si puedes, paga el monto "sin intereses".' },
          { name: 'date', label: 'Fecha del pago', type: 'date', value: pre.date || todayISO(), required: true },
        ],
        onSubmit(v) {
          const restore = [{ kind: 'card', id: c.id, fields: { lastPaid: c.lastPaid, noInterest: c.noInterest, minPay: c.minPay } }];
          addMove({ type: 'pago', amount: v.amount, category: 'Pago de tarjeta', date: v.date, note: `Pago tarjeta ${c.alias}`, method: 'cash', cardPayId: c.id, effects: [{ kind: 'card', id: c.id, delta: -v.amount }], restore });
          c.noInterest = round2(Math.max(0, c.noInterest - v.amount));
          c.minPay = round2(Math.max(0, c.minPay - v.amount));
          if (c.minPay === 0 || c.noInterest === 0) c.lastPaid = due;
          commit('Pago registrado ✔');
        },
      });
    },
    'new-promo'(id, pre = {}) {
      const c = id ? cardById(id) : null;
      openForm({
        title: c ? `Promoción · ${c.alias}` : 'Nueva promoción', submitLabel: 'Guardar promoción', banner: pre.banner,
        fields: [
          ...(c ? [] : [{ name: 'cardId', label: '¿De qué tarjeta?', type: 'select', options: state.cards.map((x) => ({ v: x.id, l: `${x.alias}${x.bank ? ' · ' + x.bank : ''}` })) }]),
          { name: 'title', label: '¿Cuál es la promoción?', required: true, value: pre.title, placeholder: 'Ej. 12 MSI en tiendas departamentales', max: 80 },
          { name: 'endDate', label: '¿Hasta cuándo es válida?', type: 'date', required: true, value: pre.endDate },
          { name: 'note', label: 'Nota (opcional)', value: pre.note, placeholder: 'Ej. compra mínima $3,000', max: 80 },
        ],
        onSubmit(v) { const card = c || cardById(v.cardId); const { cardId, ...p } = v; card.promos.push({ id: uid(), ...p }); commit('Promoción guardada. Te avisaremos antes de que termine.'); },
      });
    },
    async 'del-promo'(ids) {
      const [cid, pid] = ids.split('|'); const c = cardById(cid);
      if (!(await confirmBox('¿Quitar esta promoción?', 'Quitar'))) return;
      c.promos = c.promos.filter((p) => p.id !== pid); commit('Promoción eliminada');
    },
    'new-bill'(_, pre) { billForm(null, pre); },
    'edit-bill'(id, pre) { billForm(billById(id), pre); },
    'pay-bill'(id, pre = {}) {
      const b = billById(id);
      openForm({
        title: `Pagar ${b.name || billLabel(b.type)}`, submitLabel: 'Registrar pago', banner: pre.banner,
        fields: [
          { name: 'amount', label: '¿Cuánto pagaste?', type: 'money', required: true, value: pre.amount ?? (b.amount || '') },
          { type: 'two', fields: [
            { name: 'date', label: 'Fecha del pago', type: 'date', value: pre.date || todayISO(), required: true },
            { name: 'method', label: '¿Con qué pagaste?', type: 'select', options: methodOptions(), value: pre.method || b.method || 'cash' }] },
          ...(Number(b.recur) > 0 ? [{ name: 'nextAmount', label: 'Monto estimado del próximo recibo', type: 'money', value: b.amount, allowZero: true, help: 'Puedes dejarlo igual y corregirlo cuando llegue el recibo.' }] : []),
        ],
        onSubmit(v) {
          const restore = [{ kind: 'bill', id: b.id, fields: { dueDate: b.dueDate, done: !!b.done, amount: b.amount } }];
          addMove({ type: 'gasto', amount: v.amount, category: BILL_CAT[b.type] || 'Servicios', date: v.date, note: b.name || billLabel(b.type), method: v.method, billId: b.id, restore });
          const r = Number(b.recur);
          if (r > 0) { b.dueDate = addMonthsISO(b.dueDate, r, b.dueDay || parseISO(b.dueDate).getDate()); if (v.nextAmount) b.amount = v.nextAmount; } else b.done = true;
          b.method = v.method;
          commit(r > 0 ? `Pagado ✔ Próximo vencimiento: ${fmtDate(b.dueDate)}` : 'Pagado ✔');
        },
      });
    },
    'new-debt'(_, pre) { debtForm(null, pre); },
    'edit-debt'(id) { debtForm(debtById(id)); },
    'pay-debt'(id, pre = {}) {
      const d = debtById(id); const due = dueOf(d);
      openForm({
        title: `Pagar ${d.name}`, submitLabel: 'Registrar pago', banner: pre.banner,
        fields: [
          { name: 'amount', label: '¿Cuánto pagaste?', type: 'money', required: true, value: pre.amount ?? (Math.min(d.monthly, d.balance) || ''), help: 'Si tu pago incluye intereses, registra el total; luego ajusta el saldo real en "Editar".' },
          { type: 'two', fields: [
            { name: 'date', label: 'Fecha del pago', type: 'date', value: pre.date || todayISO(), required: true },
            { name: 'method', label: '¿Con qué pagaste?', type: 'select', options: methodOptions(), value: pre.method || 'cash' }] },
        ],
        onSubmit(v) {
          const restore = [{ kind: 'debt', id: d.id, fields: { lastPaid: d.lastPaid } }];
          addMove({ type: 'gasto', amount: v.amount, category: 'Deudas', date: v.date, note: `Pago ${d.name}`, method: v.method, debtId: d.id, effects: [{ kind: 'debt', id: d.id, delta: -v.amount }], restore });
          d.lastPaid = due;
          commit(d.balance <= 0 ? '¡Felicidades, deuda liquidada! 🎉' : 'Pago registrado ✔');
        },
      });
    },
    'new-move'(type, pre) { moveForm(type || 'gasto', pre); },
    budget() { budgetForm(); },
    dictate() { dictateSheet(); },
    photo() { photoSheet(); },
    'edit-move'(id) {
      const m = state.moves.find((x) => x.id === id); if (!m) return;
      openForm({
        title: m.type === 'ingreso' ? 'Ingreso' : m.type === 'pago' ? 'Pago a tarjeta' : 'Gasto', submitLabel: 'Guardar cambios',
        fields: [
          { type: 'html', html: `<p class="note">${money(m.amount)} · ${fmtDate(m.date)} · ${esc(m.category)}${m.billId || m.debtId || m.cardPayId ? '<br>Si eliminas este pago, el vencimiento y el saldo vuelven a como estaban.' : ''}</p>` },
          { name: 'note', label: 'Descripción', value: m.note, max: 80 },
          ...(m.type !== 'pago' && !m.billId && !m.debtId ? [{ name: 'category', label: 'Categoría', type: 'select', options: (m.type === 'ingreso' ? CAT_INGRESO : gastoCats()).map((c) => ({ v: c, l: c })), value: m.category }] : []),
        ],
        danger: { label: 'Eliminar', confirm: '¿Eliminar este movimiento?', run() { deleteMove(m.id); closeSheet(); commit('Movimiento eliminado'); } },
        onSubmit(v) { m.note = v.note; if (v.category) m.category = v.category; commit('Guardado'); },
      });
    },
    settings() { settingsSheet(); },
  };

  function cardForm(c, pre = {}) {
    const isNew = !c;
    c = c || pre;
    openForm({
      title: isNew ? 'Nueva tarjeta de crédito' : `Editar ${c.alias}`, submitLabel: isNew ? 'Agregar tarjeta' : 'Guardar', banner: pre.banner,
      fields: [
        { type: 'two', fields: [
          { name: 'alias', label: 'Nombre de la tarjeta', required: true, value: c?.alias, placeholder: 'Ej. Oro, Costco', max: 30 },
          { name: 'bank', label: 'Banco', value: c?.bank, placeholder: 'Ej. BBVA', max: 30 }] },
        { name: 'last4', label: 'Últimos 4 dígitos (opcional)', value: c?.last4, inputmode: 'numeric', max: 4, pattern: /^\d{4}$/, patternMsg: 'Escribe solo los últimos 4 números.', help: 'Nunca escribas el número completo ni el código de seguridad.' },
        { type: 'two', fields: [
          { name: 'cutDay', label: 'Día de corte', type: 'select', options: dayOptions(), value: c?.cutDay || 1 },
          { name: 'payDay', label: 'Día límite de pago', type: 'select', options: dayOptions(), value: c?.payDay || 20 }] },
        { type: 'two', fields: [
          { name: 'limit', label: 'Límite de crédito', type: 'money', value: c?.limit, allowZero: true },
          { name: 'balance', label: 'Saldo actual', type: 'money', value: c?.balance, allowZero: true }] },
        { type: 'two', fields: [
          { name: 'noInterest', label: 'Pago para no generar intereses', type: 'money', value: c?.noInterest, allowZero: true },
          { name: 'minPay', label: 'Pago mínimo', type: 'money', value: c?.minPay, allowZero: true }] },
        { name: 'color', label: 'Color', type: 'seg', options: [0, 1, 2, 3, 4, 5].map((n) => ({ v: String(n), l: ['Verde', 'Azul', 'Vino', 'Negro', 'Oro', 'Morado'][n] })), value: String(c?.color ?? state.cards.length % 6) },
      ],
      danger: isNew ? null : { label: 'Eliminar', confirm: `¿Eliminar la tarjeta ${c.alias}? Sus movimientos se conservan.`, run() { state.cards = state.cards.filter((x) => x.id !== c.id); closeSheet(); commit('Tarjeta eliminada'); } },
      onSubmit(v) {
        const data = { alias: v.alias, bank: v.bank || '', last4: v.last4 || '', cutDay: +v.cutDay, payDay: +v.payDay, limit: v.limit, balance: v.balance, noInterest: v.noInterest, minPay: v.minPay, color: +v.color };
        if (isNew) state.cards.push({ id: uid(), promos: [], lastPaid: prevOccurrence(data.payDay), ...data });
        else { if (c.payDay !== data.payDay) c.lastPaid = prevOccurrence(data.payDay); Object.assign(c, data); }
        commit(isNew ? 'Tarjeta agregada ✔' : 'Cambios guardados');
      },
    });
  }
  function billForm(b, pre = {}) {
    const isNew = !b;
    openForm({
      title: isNew ? 'Nuevo servicio o pago fijo' : `Editar ${b.name || billLabel(b.type)}`, submitLabel: isNew ? 'Agregar' : 'Guardar', banner: pre.banner,
      fields: [
        { name: 'type', label: 'Tipo', type: 'select', options: BILL_TYPES, value: pre.type || b?.type || 'luz' },
        { name: 'name', label: 'Nombre (opcional)', value: pre.name ?? b?.name, placeholder: 'Ej. CFE casa, Renta depa, Telcel Ana', max: 40 },
        { type: 'two', fields: [
          { name: 'amount', label: 'Monto', type: 'money', value: pre.amount ?? b?.amount, allowZero: true },
          { name: 'dueDate', label: 'Fecha de vencimiento', type: 'date', value: pre.dueDate || b?.dueDate || iso(addDays(today0(), 10)), required: true }] },
        { name: 'recur', label: '¿Cada cuándo se paga?', type: 'seg', options: RECUR, value: String(pre.recur ?? b?.recur ?? '1'), help: 'La luz (CFE) y el agua suelen ser cada 2 meses. Renta, colegiatura e internet, cada mes.' },
      ],
      danger: isNew ? null : { label: 'Eliminar', confirm: '¿Eliminar este servicio?', run() { state.bills = state.bills.filter((x) => x.id !== b.id); closeSheet(); commit('Servicio eliminado'); } },
      onSubmit(v) {
        const data = { type: v.type, name: v.name || '', amount: v.amount, dueDate: v.dueDate, dueDay: parseISO(v.dueDate).getDate(), recur: Number(v.recur), done: false };
        if (isNew) state.bills.push({ id: uid(), ...data }); else Object.assign(b, data);
        commit(isNew ? 'Servicio agregado ✔' : 'Cambios guardados');
      },
    });
  }
  function debtForm(d, pre = {}) {
    const isNew = !d;
    d = d || (Object.keys(pre).length ? pre : null);
    openForm({
      title: isNew ? 'Nueva deuda o préstamo' : `Editar ${d.name}`, submitLabel: isNew ? 'Agregar deuda' : 'Guardar', banner: pre.banner,
      fields: [
        { type: 'two', fields: [
          { name: 'name', label: '¿Qué es?', required: true, value: d?.name, placeholder: 'Ej. Crédito auto', max: 40 },
          { name: 'lender', label: '¿A quién le debo?', value: d?.lender, placeholder: 'Ej. Banorte, mi hermano', max: 40 }] },
        { type: 'two', fields: [
          { name: 'balance', label: 'Lo que debo hoy', type: 'money', required: isNew, value: d?.balance, allowZero: !isNew },
          { name: 'monthly', label: 'Pago mensual', type: 'money', value: d?.monthly, allowZero: true }] },
        { type: 'two', fields: [
          { name: 'payDay', label: 'Día de pago', type: 'select', options: dayOptions(), value: d?.payDay || 15 },
          { name: 'original', label: 'Monto original (opcional)', type: 'money', value: d?.original, allowZero: true }] },
      ],
      danger: isNew ? null : { label: 'Eliminar', confirm: `¿Eliminar ${d.name}?`, run() { state.debts = state.debts.filter((x) => x.id !== d.id); closeSheet(); commit('Deuda eliminada'); } },
      onSubmit(v) {
        const data = { name: v.name, lender: v.lender || '', balance: v.balance, monthly: v.monthly, payDay: +v.payDay, original: v.original || Math.max(v.balance, d?.original || 0) };
        if (isNew) state.debts.push({ id: uid(), lastPaid: prevOccurrence(data.payDay), ...data });
        else { if (d.payDay !== data.payDay) d.lastPaid = prevOccurrence(data.payDay); Object.assign(d, data); }
        commit(isNew ? 'Deuda agregada ✔' : 'Cambios guardados');
      },
    });
  }
  function moveForm(type, pre = {}) {
    const isIn = type === 'ingreso';
    const cats = isIn ? CAT_INGRESO : gastoCats();
    openForm({
      title: isIn ? 'Registrar ingreso' : 'Registrar gasto', submitLabel: 'Guardar', banner: pre.banner,
      fields: [
        { name: 'amount', label: '¿Cuánto?', type: 'money', required: true, value: pre.amount ?? '' },
        { name: 'category', label: 'Categoría', type: 'select', options: cats.map((c) => ({ v: c, l: c })), value: cats.includes(pre.category) ? pre.category : (isIn ? 'Sueldo' : 'Súper y despensa') },
        { type: 'two', fields: [
          { name: 'date', label: 'Fecha', type: 'date', value: pre.date || todayISO(), required: true },
          isIn ? { type: 'html', html: '<div></div>' } : { name: 'method', label: '¿Con qué pagaste?', type: 'select', options: methodOptions(), value: pre.method || 'cash' }] },
        { name: 'note', label: 'Descripción (opcional)', value: pre.note, placeholder: isIn ? 'Ej. Quincena' : 'Ej. Walmart', max: 80 },
      ],
      onSubmit(v) {
        addMove({ type, amount: v.amount, category: v.category, date: v.date, note: v.note || '', method: v.method || 'cash' });
        const warn = isIn ? '' : budgetWarn(v.category);
        commit((isIn ? 'Ingreso guardado ✔' : 'Gasto guardado ✔') + warn);
      },
    });
  }

  /* ---------- Presupuesto mensual ---------- */
  function budgetStatus(y, m) {
    const mv = monthMoves(y, m).filter((x) => x.type === 'gasto');
    const spent = {};
    mv.forEach((x) => { spent[x.category] = round2((spent[x.category] || 0) + x.amount); });
    const rows = Object.entries(state.budgets).filter(([, v]) => v > 0).map(([cat, limit]) => {
      const used = spent[cat] || 0; const pct = limit > 0 ? (used / limit) * 100 : 0;
      return { cat, limit, used, pct, left: round2(limit - used), cls: pct >= 100 ? 'bad' : pct >= 80 ? 'warn' : 'ok' };
    }).sort((a, b) => b.pct - a.pct);
    const unbudgeted = Object.entries(spent).filter(([c]) => !(state.budgets[c] > 0)).sort((a, b) => b[1] - a[1]);
    const totalLimit = round2(rows.reduce((s, r) => s + r.limit, 0));
    const totalUsed = round2(rows.reduce((s, r) => s + r.used, 0));
    return { rows, unbudgeted, totalLimit, totalUsed, pct: totalLimit ? (totalUsed / totalLimit) * 100 : 0 };
  }
  function budgetWarn(cat) {
    const lim = state.budgets[cat]; if (!(lim > 0)) return '';
    const now = new Date();
    const r = budgetStatus(now.getFullYear(), now.getMonth()).rows.find((x) => x.cat === cat);
    if (!r) return '';
    if (r.pct >= 100) return ` · ⚠️ Te pasaste del presupuesto de ${cat}`;
    if (r.pct >= 80) return ` · Llevas ${Math.round(r.pct)}% del presupuesto de ${cat}`;
    return '';
  }
  function budgetForm() {
    const cats = gastoCats().filter((c) => c !== 'Deudas');
    const pairs = [];
    for (let i = 0; i < cats.length; i += 2) pairs.push({ type: 'two', fields: cats.slice(i, i + 2).map((c, j) => ({ name: 'b' + (i + j), label: c, type: 'money', value: state.budgets[c] || '', allowZero: true })) });
    openForm({
      title: 'Presupuesto mensual', submitLabel: 'Guardar presupuesto',
      fields: [
        { type: 'html', html: '<p class="note">Escribe cuánto quieres gastar al mes en cada categoría. Deja en blanco las que no quieras controlar. Te avisaremos al llegar al 80% y al pasarte.</p>' },
        ...pairs,
        { name: 'newCat', label: 'Agregar una categoría propia (opcional)', placeholder: 'Ej. Gimnasio, Gastos de la oficina', max: 30 },
        { name: 'newCatAmt', label: 'Presupuesto para esa categoría', type: 'money', allowZero: true },
      ],
      onSubmit(v) {
        const b = {};
        cats.forEach((c, i) => { if (v['b' + i] > 0) b[c] = v['b' + i]; });
        const nc = (v.newCat || '').trim();
        if (nc) {
          if (gastoCats().some((c) => c.toLowerCase() === nc.toLowerCase())) return 'Esa categoría ya existe.';
          state.customCats.push(nc); if (v.newCatAmt > 0) b[nc] = v.newCatAmt;
        }
        state.budgets = b; commit('Presupuesto guardado ✔');
      },
    });
  }
  function budgetBlock(y, m, compact) {
    const st = budgetStatus(y, m);
    if (!st.rows.length) {
      return `<div class="panel pad"><div class="empty"><h3>Controla tus gastos generales</h3><p>Ponle un límite mensual a cada categoría (súper, gasolina, comida fuera…) y te avisamos antes de que te pases.</p><button class="btn primary" data-act="budget">${icon('target')} Definir mi presupuesto</button></div></div>`;
    }
    const rows = (compact ? st.rows.slice(0, 4) : st.rows).map((r) => `<div><div class="bar-h"><span>${esc(r.cat)}</span><b>${money(r.used)} de ${money(r.limit)}</b></div><div class="track"><div class="fill ${r.cls === 'ok' ? '' : r.cls}" data-w="${Math.min(100, r.pct).toFixed(1)}"></div></div><div class="sub">${r.left >= 0 ? `Te quedan ${money(r.left)}` : `Te pasaste por ${money(-r.left)}`} · ${Math.round(r.pct)}%</div></div>`).join('');
    const extra = !compact && st.unbudgeted.length ? `<div class="sub section">Sin presupuesto: ${st.unbudgeted.map(([c, v]) => `${esc(c)} ${money(v)}`).join(' · ')}</div>` : '';
    return `<div class="panel pad"><div class="bar-h"><span><b>Total</b></span><b>${money(st.totalUsed)} de ${money(st.totalLimit)}</b></div><div class="track"><div class="fill ${st.pct >= 100 ? 'bad' : st.pct >= 80 ? 'warn' : ''}" data-w="${Math.min(100, st.pct).toFixed(1)}"></div></div>
      <div class="bars section">${rows}</div>${extra}</div>`;
  }

  /* ---------- Captura inteligente: voz y foto ---------- */
  const samplePromise = (TRIAL && window.claude?.use) ? Promise.resolve(window.claude.use('sample')).catch(() => null) : Promise.resolve(null);
  async function aiMode() {
    if (TRIAL) {
      const s = await samplePromise;
      if (!s) return null;
      const lim = await s.limits?.().catch(() => null);
      return { kind: 'sample', s, images: !!lim?.images };
    }
    if (CLOUD && CFG.aiEnabled && meta.cloud?.session) return { kind: 'cloud', images: true };
    return null;
  }
  function aiContext() {
    return {
      hoy: todayISO(),
      categorias_gasto: gastoCats(),
      categorias_ingreso: CAT_INGRESO,
      tarjetas: state.cards.map((c) => ({ alias: c.alias, banco: c.bank || '', ultimos4: c.last4 || '' })),
      servicios: state.bills.filter((b) => !b.done).map((b) => ({ nombre: b.name || billLabel(b.type), tipo: b.type })),
      deudas: state.debts.filter((d) => d.balance > 0).map((d) => d.name),
      tipos_servicio: BILL_TYPES.map((b) => b.v),
    };
  }
  // El mismo texto de instrucciones está en supabase/functions/ai-extract (mantener iguales)
  function aiPrompt(text, hasImage, ctx) {
    return `Eres el asistente de captura de una app de finanzas personales en México. Convierte la entrada del usuario en UN objeto JSON.
${hasImage ? 'La imagen adjunta es una foto de un ticket de compra, recibo de servicio, estado de cuenta de tarjeta, comprobante de pago o promoción bancaria.' : ''}
${text ? `Texto dictado por el usuario: """${String(text).slice(0, 1500)}"""` : ''}
Datos del usuario (JSON): ${JSON.stringify(ctx)}

Reglas:
- "tipo" es uno de: gasto, ingreso, pago_servicio (ya pagó un servicio o pago fijo), recibo_servicio (le llegó un recibo POR PAGAR), estado_cuenta (estado de cuenta de tarjeta de crédito), pago_tarjeta (pagó su tarjeta), promocion, nueva_deuda, pago_deuda, desconocido.
- Montos en pesos como número sin símbolos ni comas. En un ticket usa el TOTAL pagado.
- Fechas en formato YYYY-MM-DD. Hoy es ${ctx.hoy}; "ayer", "el lunes", "el 25" se calculan a partir de hoy (un gasto es pasado; un vencimiento suele ser futuro).
- "categoria": exactamente una de categorias_gasto o categorias_ingreso.
- "tarjeta": el alias EXACTO de la lista de tarjetas si se puede identificar (por nombre, banco o últimos 4 dígitos); si no, null.
- "metodo": "tarjeta" si se pagó con tarjeta de crédito, si no "efectivo".
- "servicio_tipo": uno de tipos_servicio. "servicio_nombre": usa el nombre exacto de la lista de servicios si coincide.
- En un estado de cuenta extrae saldo, pago_minimo, pago_sin_intereses (pago para no generar intereses), fecha_limite_pago, fecha_corte y limite_credito.
- Usa null en lo que no sepas. No inventes datos.
- "descripcion": máximo 6 palabras (comercio o concepto).

Responde SOLO con este JSON:
{"tipo":"","monto":null,"fecha":null,"categoria":null,"descripcion":null,"metodo":null,"tarjeta":null,"servicio_tipo":null,"servicio_nombre":null,"vencimiento":null,"recurrencia_meses":null,"saldo":null,"pago_minimo":null,"pago_sin_intereses":null,"fecha_limite_pago":null,"fecha_corte":null,"limite_credito":null,"banco":null,"ultimos4":null,"promo_titulo":null,"promo_vigencia":null,"deuda_nombre":null,"acreedor":null,"mensualidad":null,"dia_pago":null}`;
  }
  async function shrinkImage(file, max = 1600) {
    const bmp = await createImageBitmap(file).catch(() => null);
    if (!bmp) return file;
    const k = Math.min(1, max / Math.max(bmp.width, bmp.height));
    const cv = document.createElement('canvas'); cv.width = Math.round(bmp.width * k); cv.height = Math.round(bmp.height * k);
    cv.getContext('2d').drawImage(bmp, 0, 0, cv.width, cv.height);
    return await new Promise((res) => cv.toBlob((b) => res(b || file), 'image/jpeg', 0.85));
  }
  const blobToB64 = (blob) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1]); r.onerror = rej; r.readAsDataURL(blob); });
  async function aiExtract(mode, text, image) {
    const ctx = aiContext();
    if (mode.kind === 'sample') {
      const opts = { modelTier: 'default', cache: false };
      if (image) opts.images = [image];
      return await mode.s.json(aiPrompt(text, !!image, ctx), opts);
    }
    const body = { text: text || '', context: ctx };
    if (image) { const small = await shrinkImage(image); body.image = await blobToB64(small); body.media_type = 'image/jpeg'; }
    return await sbFetch('/functions/v1/ai-extract', { method: 'POST', body });
  }
  const aiErrMsg = (e) => {
    const c = e?.code;
    if (c === 'not_granted' || c === 'sampling_disabled') return 'No diste permiso para usar la lectura automática.';
    if (c === 'rate_limited' || e?.status === 429) return 'Demasiadas lecturas seguidas. Espera un momento.';
    if (c === 'image_rejected') return 'No pudimos abrir esa imagen. Prueba con otra foto.';
    if (c === 'invalid_json' || c === 'empty_completion') return 'No entendimos bien. Intenta de nuevo con más detalle.';
    if (e instanceof CloudError) return e.message;
    return 'No se pudo leer. Revisa tu conexión e intenta de nuevo.';
  };

  // Intérprete local (sin internet ni IA) para frases dictadas sencillas
  const KW_CAT = [
    [/(s[uú]per|walmart|soriana|\bheb\b|costco|chedraui|bodega aurrera|despensa|mercado|sam'?s)/, 'Súper y despensa'],
    [/(restaurante|comida|cena|desayuno|almuerzo|tacos|caf[eé]|starbucks|rappi|uber eats|didi food|pizza|hamburguesa)/, 'Comida fuera'],
    [/(gasolina|uber|didi|taxi|estacionamiento|caseta|cami[oó]n|metro|transporte|pemex)/, 'Transporte y gasolina'],
    [/(farmacia|doctor|m[eé]dico|consulta|medicina|hospital|dentista|laboratorio)/, 'Salud'],
    [/(colegiatura|escuela|libro|curso|[uú]tiles|universidad)/, 'Educación'],
    [/(seguro)/, 'Seguros'],
    [/(cine|netflix|spotify|disney|concierto|\bbar\b|fiesta|boletos|juego)/, 'Entretenimiento'],
    [/(ropa|zapatos|tenis|liverpool|zara|palacio de hierro|coppel)/, 'Ropa'],
    [/(ferreter|home depot|muebles|limpieza|plomero|electricista|jard[ií]n)/, 'Hogar'],
    [/(est[eé]tica|corte de pelo|barber|perfume|maquillaje|gimnasio|gym)/, 'Cuidado personal'],
    [/(veterinari|perro|gato|mascota|croquetas)/, 'Mascotas'],
    [/(regalo|cumplea)/, 'Regalos'],
  ];
  const KW_BILL = [[/\b(luz|cfe)\b/, 'luz'], [/\bagua\b/, 'agua'], [/\bgas\b/, 'gas'], [/(internet|izzi|totalplay|telmex|megacable|infinitum)/, 'internet'], [/(celular|telcel|at&t|movistar|recarga)/, 'celular'], [/\b(renta|hipoteca)\b/, 'renta'], [/colegiatura/, 'colegiatura'], [/\bseguro\b/, 'seguro'], [/(netflix|spotify|disney|suscripci|youtube premium|amazon prime)/, 'suscripcion'], [/mantenimiento/, 'mantenimiento']];
  function localParse(text) {
    const t = ' ' + text.toLowerCase().normalize('NFC') + ' ';
    const r = { tipo: 'gasto' };
    let m = t.match(/\$?\s*(\d{1,3}(?:[,\s]\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(mil\b)?/);
    if (m) { let n = Number(m[1].replace(/[,\s]/g, '') + (m[2] ? '.' + m[2] : '')); if (m[3]) n *= 1000; r.monto = n; }
    else if (/\bmil\b/.test(t)) r.monto = 1000;
    const today = today0();
    if (/\bantier|anteayer\b/.test(t)) r.fecha = iso(addDays(today, -2));
    else if (/\bayer\b/.test(t)) r.fecha = iso(addDays(today, -1));
    const dm = t.match(/\b(?:el|para el|vence el|hasta el)\s+(\d{1,2})(?:\s+de\s+(\w+))?/);
    let dayDate = null;
    if (dm) {
      const d = Number(dm[1]); const mi = dm[2] ? MES.indexOf(dm[2]) : -1;
      if (d >= 1 && d <= 31) dayDate = { d, mi };
    }
    const bill = KW_BILL.find(([re]) => re.test(t));
    const card = state.cards.find((c) => t.includes(c.alias.toLowerCase()) || (c.last4 && t.includes(c.last4)));
    const debt = state.debts.find((d) => t.includes(d.name.toLowerCase()));
    if (/(me pagaron|me depositaron|cobr[eé]|recib[ií] (un )?pago|ingreso|quincena|sueldo|n[oó]mina|vend[ií]|honorarios|me transfirieron)/.test(t)) r.tipo = 'ingreso';
    else if (/(pagu[eé]|abon[eé]).{0,40}(tarjeta)/.test(t) && card) r.tipo = 'pago_tarjeta';
    else if (/(pagu[eé]|abon[eé]).{0,40}(pr[eé]stamo|cr[eé]dito|deuda|mensualidad)/.test(t) || (debt && /(pagu[eé]|abon[eé])/.test(t))) r.tipo = 'pago_deuda';
    else if (/(promo|meses sin intereses|\bmsi\b)/.test(t)) r.tipo = 'promocion';
    else if (bill && /(pagu[eé]|ya pagu)/.test(t)) r.tipo = 'pago_servicio';
    else if (bill && /(lleg[oó]|vence|recibo|me toca)/.test(t)) r.tipo = 'recibo_servicio';
    if (r.tipo === 'ingreso') r.categoria = /(quincena|sueldo|n[oó]mina)/.test(t) ? 'Sueldo' : /honorarios/.test(t) ? 'Honorarios' : /vend[ií]/.test(t) ? 'Ventas' : /renta/.test(t) ? 'Rentas' : 'Otros ingresos';
    else { const k = KW_CAT.find(([re]) => re.test(t)); if (k) r.categoria = k[1]; const own = (state.customCats || []).find((c) => t.includes(c.toLowerCase())); if (own) r.categoria = own; }
    if (bill) { r.servicio_tipo = bill[1]; if (!r.categoria) r.categoria = BILL_CAT[bill[1]]; }
    if (card) { r.tarjeta = card.alias; if (/tarjeta|con la /.test(t)) r.metodo = 'tarjeta'; }
    if (/efectivo|d[eé]bito/.test(t)) r.metodo = 'efectivo';
    if (debt) r.deuda_nombre = debt.name;
    if (dayDate) {
      const future = r.tipo === 'recibo_servicio' || r.tipo === 'promocion';
      let y = today.getFullYear(), mo = dayDate.mi >= 0 ? dayDate.mi : today.getMonth();
      let dt = dateIn(y, mo, dayDate.d);
      if (dayDate.mi < 0) { if (future && dt < today) dt = dateIn(y, mo + 1, dayDate.d); if (!future && dt > today) dt = dateIn(y, mo - 1, dayDate.d); }
      if (future) { r.vencimiento = iso(dt); r.promo_vigencia = iso(dt); } else r.fecha = iso(dt);
    }
    const cap = (x) => x.trim().replace(/^./, (c) => c.toUpperCase());
    const hit = (r.tipo === 'ingreso' ? t.match(/(quincena|sueldo|n[oó]mina|honorarios|venta|renta)/) : null)
      || (bill ? t.match(bill[0]) : null) || (() => { for (const [re] of KW_CAT) { const x = t.match(re); if (x) return x; } return null; })();
    r.descripcion = hit ? cap(hit[0]) : '';
    if (r.tipo === 'promocion') r.promo_titulo = text.slice(0, 80);
    return r;
  }

  const num = (x) => { const n = Number(String(x ?? '').replace(/[$,\s]/g, '')); return Number.isFinite(n) && n > 0 ? round2(n) : undefined; };
  const isoOk = (x) => (/^\d{4}-\d{2}-\d{2}$/.test(String(x || '')) ? x : undefined);
  const findCard = (r) => {
    const a = String(r.tarjeta || '').toLowerCase(); const l4 = String(r.ultimos4 || '').slice(-4); const bk = String(r.banco || '').toLowerCase();
    return state.cards.find((c) => a && c.alias.toLowerCase() === a) || state.cards.find((c) => l4 && c.last4 === l4)
      || (bk ? state.cards.filter((c) => (c.bank || '').toLowerCase().includes(bk)) : []).find((_, i, arr) => arr.length === 1) || null;
  };
  const findBill = (r) => {
    const n = String(r.servicio_nombre || '').toLowerCase(); const open = state.bills.filter((b) => !b.done);
    return open.find((b) => n && (b.name || '').toLowerCase() === n) || open.filter((b) => b.type === r.servicio_tipo).find((_, i, arr) => arr.length === 1) || null;
  };
  function applyCapture(r, source) {
    const banner = `<div class="captured">${icon('spark')}<div><b>Llenado automático${source ? ` desde ${source}` : ''}.</b> Revisa los datos y corrige lo que haga falta antes de guardar.</div></div>`;
    const tipo = String(r?.tipo || 'desconocido');
    const amount = num(r.monto); const date = isoOk(r.fecha);
    const card = findCard(r);
    const method = r.metodo === 'tarjeta' && card ? 'card:' + card.id : 'cash';
    const note = r.descripcion ? String(r.descripcion).slice(0, 80) : (r.servicio_tipo ? billLabel(r.servicio_tipo) : undefined);
    switch (tipo) {
      case 'gasto': return moveForm('gasto', { banner, amount, date, category: r.categoria, note, method });
      case 'ingreso': return moveForm('ingreso', { banner, amount, date, category: r.categoria, note });
      case 'pago_servicio': {
        const b = findBill(r);
        if (b) return ACTIONS['pay-bill'](b.id, { banner, amount, date, method });
        return moveForm('gasto', { banner, amount, date, category: BILL_CAT[r.servicio_tipo] || r.categoria || 'Servicios', note: note || billLabel(r.servicio_tipo), method });
      }
      case 'recibo_servicio': {
        const b = findBill(r);
        const pre = { banner, amount, dueDate: isoOk(r.vencimiento), type: BILL_TYPES.some((x) => x.v === r.servicio_tipo) ? r.servicio_tipo : undefined, name: r.servicio_nombre || undefined, recur: r.recurrencia_meses ?? undefined };
        return billForm(b, b ? { banner, amount, dueDate: pre.dueDate } : pre);
      }
      case 'estado_cuenta': {
        const fl = isoOk(r.fecha_limite_pago); const fc = isoOk(r.fecha_corte);
        const pre = { banner, balance: num(r.saldo), noInterest: num(r.pago_sin_intereses), minPay: num(r.pago_minimo), payDate: fl, cutDay: fc ? parseISO(fc).getDate() : undefined };
        if (card) return ACTIONS.statement(card.id, pre);
        return cardForm(null, { banner, alias: r.banco || '', bank: r.banco || '', last4: /^\d{4}$/.test(String(r.ultimos4 || '')) ? String(r.ultimos4) : '', cutDay: pre.cutDay, payDay: fl ? parseISO(fl).getDate() : undefined, limit: num(r.limite_credito), balance: pre.balance, noInterest: pre.noInterest, minPay: pre.minPay });
      }
      case 'pago_tarjeta': if (card) return ACTIONS['pay-card'](card.id, { banner, amount, date }); break;
      case 'promocion': {
        if (!state.cards.length) { toast('Primero agrega la tarjeta de esa promoción.'); return cardForm(null, { banner, bank: r.banco || '' }); }
        return ACTIONS['new-promo'](card?.id || null, { banner, title: r.promo_titulo || note, endDate: isoOk(r.promo_vigencia) || isoOk(r.vencimiento), note: r.descripcion && r.promo_titulo ? undefined : undefined });
      }
      case 'nueva_deuda': return debtForm(null, { banner, name: r.deuda_nombre || note || '', lender: r.acreedor || '', balance: num(r.saldo) ?? amount, monthly: num(r.mensualidad), payDay: Number(r.dia_pago) || undefined });
      case 'pago_deuda': {
        const d = state.debts.find((x) => x.name.toLowerCase() === String(r.deuda_nombre || '').toLowerCase()) || (state.debts.filter((x) => x.balance > 0).length === 1 ? state.debts.find((x) => x.balance > 0) : null);
        if (d) return ACTIONS['pay-debt'](d.id, { banner, amount, date, method });
        return moveForm('gasto', { banner, amount, date, category: 'Deudas', note, method });
      }
      default: break;
    }
    if (amount) return moveForm('gasto', { banner, amount, date, category: r.categoria, note, method });
    toast('No entendimos bien. Intenta con más detalle, por ejemplo: "gasté 350 en gasolina".');
    return false;
  }

  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  const EXAMPLES = ['Gasté 350 de gasolina con la tarjeta Oro', 'Me llegó el recibo de luz por 860, vence el 25', 'Me pagaron la quincena de 18,500', 'Ayer pagué 549 de internet', 'Pagué 2,000 a la tarjeta'];
  function dictateSheet() {
    sheet.innerHTML = `<div class="sheet-form">
      <div class="sheet-head"><h2>Dictar</h2><button type="button" class="icon-btn" data-close aria-label="Cerrar">✕</button></div>
      ${SR ? `<button class="mic" id="micBtn" type="button" aria-label="Hablar">${icon('mic')}<span id="micLbl">Toca y habla</span></button>` : ''}
      <div class="field"><label for="capText">Lo que quieres registrar</label><textarea id="capText" rows="3" maxlength="400" placeholder="Ej. Gasté 350 de gasolina con la tarjeta Oro"></textarea>
      <div class="help">${SR ? 'Si el botón no funciona, ' : ''}toca el micrófono 🎤 de tu teclado y habla.</div></div>
      <div class="chips">${EXAMPLES.map((e) => `<button type="button" class="chip-btn" data-ex="${esc(e)}">${esc(e)}</button>`).join('')}</div>
      <p class="form-err" hidden></p>
      <div class="sheet-actions"><button class="btn primary" id="capGo" type="button">${icon('spark')} Continuar</button></div></div>`;
    openSheet();
    const ta = $('#capText', sheet); const err = $('.form-err', sheet); const go = $('#capGo', sheet);
    $$('[data-ex]', sheet).forEach((b) => b.onclick = () => { ta.value = b.dataset.ex; });
    let rec = null;
    $('#micBtn', sheet)?.addEventListener('click', () => {
      const lbl = $('#micLbl', sheet); const btn = $('#micBtn', sheet);
      if (rec) { rec.stop(); return; }
      try {
        rec = new SR(); rec.lang = 'es-MX'; rec.interimResults = true; rec.continuous = false;
        const base = ta.value ? ta.value.trim() + ' ' : '';
        rec.onresult = (e) => { ta.value = base + Array.from(e.results).map((x) => x[0].transcript).join(' '); };
        rec.onerror = (e) => { lbl.textContent = e.error === 'not-allowed' || e.error === 'service-not-allowed' ? 'Sin permiso de micrófono: usa el 🎤 del teclado' : 'No te escuché, intenta otra vez'; };
        rec.onend = () => { rec = null; btn.classList.remove('on'); if (!/micrófono|escuché/.test(lbl.textContent)) lbl.textContent = 'Toca y habla'; };
        rec.start(); btn.classList.add('on'); lbl.textContent = 'Te escucho… toca para terminar';
      } catch { rec = null; lbl.textContent = 'Usa el 🎤 del teclado'; }
    });
    go.onclick = async () => {
      const text = ta.value.trim();
      if (text.length < 3) { err.textContent = 'Escribe o dicta qué quieres registrar.'; err.hidden = false; return; }
      rec?.stop();
      go.disabled = true; go.textContent = 'Entendiendo…'; err.hidden = true;
      const mode = await aiMode();
      let r = null;
      if (mode) { try { r = await aiExtract(mode, text, null); } catch (e) { if (e?.code !== 'not_granted') toast(aiErrMsg(e)); } }
      if (!r || typeof r !== 'object') r = localParse(text);
      closeSheet();
      if (applyCapture(r, 'tu dictado') === false) dictateSheet();
    };
  }
  async function photoSheet() {
    const mode = await aiMode();
    if (!mode || !mode.images) {
      const why = TRIAL ? 'La lectura de fotos necesita tu permiso para usar Claude en esta página. Si lo rechazaste, vuelve a abrir la liga.'
        : CLOUD && CFG.aiEnabled ? 'Para leer fotos inicia sesión en tu cuenta (Ajustes → Cuenta).' : 'La lectura de fotos aún no está activada en esta copia de la app (ver guía, Parte G).';
      return infoSheet('Foto de ticket o recibo', `<p class="note">${esc(why)}</p>`);
    }
    sheet.innerHTML = `<div class="sheet-form">
      <div class="sheet-head"><h2>Foto de ticket o recibo</h2><button type="button" class="icon-btn" data-close aria-label="Cerrar">✕</button></div>
      <p class="note">Sirve para: <b>tickets de compra</b>, <b>recibos</b> (luz, agua, gas, internet, renta…), <b>estados de cuenta</b> de tarjeta, <b>comprobantes de pago</b> y <b>promociones</b>. Toma la foto de frente, con buena luz y que se lea el total.</p>
      <div class="capture"><label class="btn primary" for="camIn">${icon('camera')} Tomar foto</label><label class="btn soft" for="galIn">Elegir de mis fotos</label></div>
      <input type="file" id="camIn" accept="image/*" capture="environment" class="sr"><input type="file" id="galIn" accept="image/*" class="sr">
      <div id="photoPrev" class="photo-prev" hidden></div>
      <p class="form-err" hidden></p></div>`;
    openSheet();
    const err = $('.form-err', sheet); const prev = $('#photoPrev', sheet);
    const handle = async (file) => {
      if (!file) return;
      if (!/^image\//.test(file.type)) { err.textContent = 'Ese archivo no es una imagen.'; err.hidden = false; return; }
      err.hidden = true; prev.hidden = false;
      const url = URL.createObjectURL(file);
      prev.innerHTML = `<img alt="Foto seleccionada"><div class="reading">${icon('spark')} Leyendo la foto… puede tardar unos segundos</div>`;
      $('img', prev).src = url;
      $$('.capture label', sheet).forEach((l) => l.classList.add('disabled'));
      try {
        const small = await shrinkImage(file);
        const r = await aiExtract(mode, '', small);
        URL.revokeObjectURL(url);
        closeSheet();
        if (applyCapture(r || {}, 'la foto') === false) photoSheet();
      } catch (e) {
        prev.hidden = true; $$('.capture label', sheet).forEach((l) => l.classList.remove('disabled'));
        err.textContent = aiErrMsg(e); err.hidden = false;
      }
    };
    $('#camIn', sheet).onchange = (e) => handle(e.target.files?.[0]);
    $('#galIn', sheet).onchange = (e) => handle(e.target.files?.[0]);
  }

  /* ---------- Ajustes ---------- */
  async function settingsSheet() {
    const bioOk = await bioAvailable();
    const perm = 'Notification' in window ? Notification.permission : 'unsupported';
    const c = meta.cloud;
    let cloudHTML;
    if (!CLOUD) cloudHTML = '<p class="note">El respaldo en la nube aún no está configurado en esta copia de la app (ver guía de instalación).</p>';
    else if (!c) cloudHTML = `<button class="btn primary" data-s="signup">${icon('cloud')} Crear cuenta y respaldar</button><button class="btn soft" data-s="login">Ya tengo cuenta: iniciar sesión</button>
      <p class="note">Con tu cuenta, tus datos se respaldan solos y puedes usarlos en otro teléfono. Se suben cifrados: ni nosotros podemos leerlos.</p>`;
    else if (!c.session) cloudHTML = `<p class="note">Cuenta: <b>${esc(c.email)}</b><br>⚠️ Tu sesión venció; el respaldo está en pausa.</p><button class="btn primary" data-s="relogin">Volver a iniciar sesión</button><button class="btn ghost" data-s="logout">Desconectar esta cuenta</button>`;
    else cloudHTML = `<p class="note">Cuenta: <b>${esc(c.email)}</b><br>Última sincronización: ${ago(meta.sync.lastAt)}${meta.sync.dirty ? ' · hay cambios por subir' : ' ✔'}</p>
      <button class="btn soft" data-s="sync">${icon('cloud')} Sincronizar ahora</button>
      <button class="btn soft" data-s="newcode">${icon('key')} Generar nuevo código de recuperación</button>
      <button class="btn soft" data-s="chpw">Cambiar contraseña</button>
      <button class="btn ghost" data-s="logout">Cerrar sesión en este teléfono</button>
      <button class="btn ghost danger" data-s="delacct">Eliminar mi cuenta en la nube</button>`;
    const pushOk = CLOUD && CFG.vapidPublicKey && c?.session;
    sheet.innerHTML = `<div class="sheet-form">
      <div class="sheet-head"><h2>Ajustes</h2><button type="button" class="icon-btn" data-close aria-label="Cerrar">✕</button></div>
      <div class="set-group"><h3>Perfil</h3><button class="btn soft" data-s="profile">${icon('edit')} Mi nombre y días de aviso</button></div>
      ${TRIAL ? '<div class="set-group"><h3>Avisos</h3><p class="note">Los avisos, el calendario y la huella digital funcionan en la versión instalada, no en esta liga de prueba.</p></div>' : `<div class="set-group"><h3>Avisos</h3>
        ${pushOk ? `<button class="btn ${meta.dev.push ? 'soft' : 'primary'}" data-s="${meta.dev.push ? 'pushoff' : 'pushon'}">${icon('bell')} ${meta.dev.push ? 'Avisos con la app cerrada: activos ✔ (toca para apagar)' : 'Activar avisos aunque la app esté cerrada'}</button>`
    : CLOUD && CFG.vapidPublicKey ? '<p class="note">Para recibir avisos con la app cerrada, primero crea tu cuenta o inicia sesión.</p>' : ''}
        ${!meta.dev.push ? `<button class="btn soft" data-s="notify">${icon('bell')} ${meta.dev.notify && perm === 'granted' ? 'Avisos al abrir la app: activos ✔' : 'Activar avisos al abrir la app'}</button>` : ''}
        <button class="btn soft" data-s="ics">${icon('cal')} Agregar mis fechas de pago a mi calendario</button>
        <p class="note">Te avisamos ${state.settings.alertDays} ${state.settings.alertDays === 1 ? 'día' : 'días'} antes y el mismo día del vencimiento.${meta.dev.push ? ' Para esto el servidor solo conoce el nombre corto y la fecha de cada pago, nunca los montos.' : ''}</p></div>`}
      <div class="set-group"><h3>Seguridad</h3>
        ${meta.bio ? `<button class="btn soft" data-s="biooff">${icon('finger')} ${BIO}: activo ✔ (toca para apagar)</button>` : bioOk ? `<button class="btn primary" data-s="bioon">${icon('finger')} Entrar con ${BIO}</button>` : ''}
        <button class="btn soft" data-s="pin-change">${icon('lock')} Cambiar PIN</button>
        <p class="note">🔒 Datos cifrados con AES-256 en este teléfono. La app se bloquea sola tras 3 minutos sin uso.</p></div>
      <div class="set-group"><h3>Cuenta y respaldo en la nube</h3>${cloudHTML}</div>
      <div class="set-group"><h3>Respaldo en archivo</h3>
        ${TRIAL ? '' : `<button class="btn soft" data-s="export">${icon('save')} Descargar respaldo cifrado</button>`}
        <button class="btn soft" data-s="import">Restaurar desde un archivo</button>
        <input type="file" accept="application/json,.json" id="importFile" class="sr">
        <p class="note">El archivo va cifrado: para abrirlo necesitas el PIN que tenías al descargarlo.</p></div>
      <div class="set-group"><h3>Otros</h3>
        ${isEmptyState(state) ? '<button class="btn soft" data-s="demo">Ver con datos de ejemplo</button>' : ''}
        <button class="btn ghost danger" data-s="wipe">${icon('trash')} Borrar todos los datos de este teléfono</button>
        <p class="note">${APP} v${VERSION}. Sin anuncios, sin rastreo y sin conexión a tu banco.</p></div>
    </div>`;
    openSheet();
    $$('[data-s]', sheet).forEach((b) => b.addEventListener('click', () => SETTINGS[b.dataset.s]()));
    $('#importFile', sheet).addEventListener('change', importBackup);
  }

  const pwFields = (withConfirm, label = 'Contraseña') => [
    { name: 'pw', label, type: 'password', required: true, autocomplete: withConfirm ? 'new-password' : 'current-password', help: withConfirm ? `Mínimo ${PW_MIN} caracteres. Usa una frase fácil de recordar para ti.` : '' },
    ...(withConfirm ? [{ name: 'pw2', label: 'Repite la contraseña', type: 'password', required: true, autocomplete: 'new-password' }] : []),
  ];
  const pwError = (v) => (v.pw.length < PW_MIN ? `La contraseña debe tener al menos ${PW_MIN} caracteres.` : v.pw2 !== undefined && v.pw !== v.pw2 ? 'Las contraseñas no coinciden.' : null);
  const forgotBtn = { label: 'Olvidé mi contraseña', run: (form) => forgotPassword(form.elements.email?.value?.trim() || meta.cloud?.email || '') };

  async function forgotPassword(email) {
    if (!validEmail(email)) return toast('Escribe tu correo primero.');
    try {
      await sbFetch(`/auth/v1/recover?redirect_to=${encodeURIComponent(APP_URL)}`, { method: 'POST', token: null, body: { email } });
      infoSheet('Revisa tu correo', `<p class="note">Si <b>${esc(email)}</b> tiene cuenta, te enviamos un enlace. Ábrelo <b>en este teléfono</b>. Te pediremos tu <b>código de recuperación</b> y una nueva contraseña.</p>`);
    } catch (e) { toast(e.message); }
  }

  // Inicia sesión desde un teléfono ya desbloqueado (crea la bóveda si no existe, o combina datos)
  async function loginAndAttach(email, pw) {
    const s = await cloudSignIn(email, pw);
    const vault = await getVault(s.userId, s.session.access);
    if (!vault) {
      const { ck, code } = await createVault(pw, s.userId, s.session.access);
      await attachCloud({ email: s.email, userId: s.userId, session: s.session, ck, rev: 1 });
      render(); showRecoveryCode(code, () => toast('Respaldo activo ✔'));
      return;
    }
    let ck;
    try { ck = await decBytes(await pbkdf2Key(pw, fromB64(vault.salt_pw)), vault.wrap_pw); }
    catch { return 'No se pudo abrir tu respaldo con esa contraseña.'; }
    const remote = migrate(await decJSON(await aesImport(ck), vault.data));
    if (!isEmptyState(state) && !isEmptyState(remote)) {
      if (!(await confirmBox('Tu cuenta ya tiene datos. Vamos a combinarlos con los de este teléfono (no se borra nada). ¿Continuar?', 'Combinar'))) return 'Cancelado.';
      state = mergeStates(state, remote);
    } else if (isEmptyState(state)) state = remote;
    await attachCloud({ email: s.email, userId: s.userId, session: s.session, ck, rev: vault.rev });
    snapshotIndex(); await writeLocal();
    meta.sync.dirty = true; saveMeta();
    await syncNow();
    render(); toast('Sesión iniciada. Respaldo activo ✔');
  }

  const SETTINGS = {
    profile() {
      openForm({
        title: 'Mi perfil', fields: [
          { name: 'name', label: '¿Cómo te llamas?', value: state.profile.name, max: 30 },
          { name: 'alertDays', label: '¿Con cuántos días de anticipación te aviso?', type: 'seg', options: [{ v: '1', l: '1' }, { v: '3', l: '3' }, { v: '5', l: '5' }, { v: '7', l: '7' }], value: String(state.settings.alertDays) },
        ],
        onSubmit(v) { state.profile.name = v.name || ''; state.settings.alertDays = Number(v.alertDays) || 3; commit('Guardado'); },
      });
    },
    async notify() {
      if (!('Notification' in window)) return toast('Este navegador no permite avisos. Usa el calendario.');
      const p = await Notification.requestPermission();
      meta.dev.notify = p === 'granted'; saveMeta(); closeSheet();
      toast(p === 'granted' ? 'Avisos activados ✔' : 'No diste permiso. Puedes usar el calendario.');
      if (p === 'granted') checkNotifications(true);
    },
    async pushon() {
      closeSheet(); toast('Activando avisos…');
      try { const err = await enablePush(); if (err) infoSheet('Avisos', `<p class="note">${esc(err)}</p>`); else toast('Listo: te avisaremos aunque la app esté cerrada ✔'); }
      catch (e) { toast(e instanceof CloudError ? e.message : 'No se pudieron activar los avisos.'); }
    },
    async pushoff() {
      if (!(await confirmBox('¿Apagar los avisos con la app cerrada en este teléfono?', 'Apagar'))) return;
      await disablePush(); closeSheet(); toast('Avisos apagados en este teléfono');
    },
    ics() { download(`${APP.toLowerCase()}-pagos.ics`, buildICS(), 'text/calendar'); toast('Abre el archivo descargado para agregarlo a tu calendario'); },
    async bioon() {
      closeSheet();
      try { await enableBio(); toast(`Listo: ya puedes entrar con ${BIO} ✔`); } catch (e) { if (e?.name !== 'NotAllowedError') infoSheet(BIO, `<p class="note">${esc(bioErrMsg(e))}</p>`); }
    },
    async biooff() {
      if (!(await confirmBox(`¿Dejar de usar ${BIO}? Seguirás entrando con tu PIN.`, 'Apagar'))) return;
      meta.bio = null; saveMeta(); closeSheet(); toast(`Ya no se usará ${BIO}`);
    },
    'pin-change'() {
      openForm({ title: 'Cambiar PIN', submitLabel: 'Cambiar', fields: [
        { name: 'old', label: 'PIN actual', type: 'pin', required: true },
        { name: 'p1', label: 'Nuevo PIN', type: 'pin', required: true }, { name: 'p2', label: 'Repite el nuevo PIN', type: 'pin', required: true }],
        async onSubmit(v) {
          try { await decBytes(await pbkdf2Key(v.old, fromB64(meta.pin.salt)), meta.pin); } catch { return 'El PIN actual no es correcto.'; }
          if (v.p1 !== v.p2) return 'Los PIN nuevos no coinciden.';
          if (weakPin(v.p1)) return 'Ese PIN es muy fácil de adivinar.';
          const salt = rand(16);
          meta.pin = { salt: toB64(salt), ...(await encBytes(await pbkdf2Key(v.p1, salt), dkBytes)) }; saveMeta();
          toast('PIN cambiado 🔒');
        } });
    },
    signup() {
      openForm({ title: 'Crear cuenta', submitLabel: 'Crear cuenta', fields: [
        { type: 'html', html: '<p class="note">Tu contraseña cifra tus datos antes de subirlos. <b>No la compartas.</b> Si la olvidas, solo podrás recuperar tus datos con el código de recuperación que te daremos.</p>' },
        { name: 'email', label: 'Correo electrónico', type: 'email', required: true }, ...pwFields(true)],
        async onSubmit(v) {
          const pe = pwError(v); if (pe) return pe;
          const secret = await authSecretOf(v.email, v.pw);
          const j = await sbFetch(`/auth/v1/signup?redirect_to=${encodeURIComponent(APP_URL)}`, { method: 'POST', token: null, body: { email: v.email, password: secret } });
          if (j?.access_token) { await loginAndAttach(v.email, v.pw); return; }
          if (j && Array.isArray(j.identities) && j.identities.length === 0) return 'Ese correo ya tiene cuenta. Usa "Iniciar sesión".';
          setTimeout(() => infoSheet('Confirma tu correo', `<p class="note">Te enviamos un correo a <b>${esc(v.email)}</b>. Ábrelo y toca el enlace de confirmación. Después regresa aquí: <b>Ajustes → Ya tengo cuenta: iniciar sesión</b>.</p>`), 50);
        } });
    },
    login() {
      openForm({ title: 'Iniciar sesión', submitLabel: 'Entrar', extraButtons: [forgotBtn], fields: [
        { name: 'email', label: 'Correo electrónico', type: 'email', required: true }, ...pwFields(false)],
        onSubmit: (v) => loginAndAttach(v.email, v.pw) });
    },
    relogin() {
      openForm({ title: 'Volver a iniciar sesión', submitLabel: 'Entrar', extraButtons: [forgotBtn], fields: [
        { name: 'email', label: 'Correo electrónico', type: 'email', value: meta.cloud.email, required: true }, ...pwFields(false)],
        async onSubmit(v) {
          const s = await cloudSignIn(v.email, v.pw);
          if (s.userId !== meta.cloud.userId) return 'Esa no es la cuenta conectada a este teléfono.';
          meta.cloud.session = s.session; saveMeta(); await syncNow(); render(); toast('Respaldo reanudado ✔');
        } });
    },
    sync() { closeSheet(); syncNow(true); },
    async newcode() {
      if (!(await confirmBox('Se generará un código nuevo y el anterior dejará de servir. ¿Continuar?', 'Generar'))) return;
      try {
        const code = newRecoveryCode(); const salt = rand(16);
        const wrap = await encBytes(await pbkdf2Key(normCode(code), salt, 100000), ckBytes);
        await sbFetch(`/rest/v1/vaults?user_id=eq.${encodeURIComponent(meta.cloud.userId)}`, { method: 'PATCH', body: { salt_rec: toB64(salt), wrap_rec: wrap } });
        showRecoveryCode(code);
      } catch (e) { toast(e.message || 'No se pudo generar.'); }
    },
    chpw() {
      openForm({ title: 'Cambiar contraseña', submitLabel: 'Cambiar', fields: [
        { name: 'old', label: 'Contraseña actual', type: 'password', required: true }, ...pwFields(true, 'Nueva contraseña')],
        async onSubmit(v) {
          const pe = pwError(v); if (pe) return pe;
          try { await cloudSignIn(meta.cloud.email, v.old); } catch (e) { return e.message; }
          const salt = rand(16);
          const wrap = await encBytes(await pbkdf2Key(v.pw, salt), ckBytes);
          await sbFetch(`/rest/v1/vaults?user_id=eq.${encodeURIComponent(meta.cloud.userId)}`, { method: 'PATCH', body: { salt_pw: toB64(salt), wrap_pw: wrap } });
          await sbFetch('/auth/v1/user', { method: 'PUT', body: { password: await authSecretOf(meta.cloud.email, v.pw) } });
          toast('Contraseña cambiada ✔');
        } });
    },
    async logout() {
      if (!(await confirmBox('Tus datos se quedan en este teléfono, pero dejarán de respaldarse. ¿Cerrar sesión?', 'Cerrar sesión'))) return;
      if (meta.dev.push) await disablePush();
      if (meta.cloud?.session) await sbFetch('/auth/v1/logout', { method: 'POST' }).catch(() => {});
      meta.cloud = null; meta.sync = { rev: 0, dirty: false, lastAt: 0 }; ckBytes = null; ckKey = null; saveMeta();
      closeSheet(); render(); toast('Sesión cerrada');
    },
    delacct() {
      openForm({ title: 'Eliminar cuenta en la nube', submitLabel: 'Eliminar definitivamente', fields: [
        { type: 'html', html: '<p class="note">Se borran tu cuenta, tu respaldo en la nube y tus recordatorios del servidor. Tus datos en <b>este teléfono</b> se conservan. No se puede deshacer.</p>' },
        { name: 'confirm', label: 'Escribe ELIMINAR para confirmar', required: true, max: 10 }],
        async onSubmit(v) {
          if (v.confirm.toUpperCase() !== 'ELIMINAR') return 'Escribe la palabra ELIMINAR.';
          if (meta.dev.push) await disablePush();
          await sbFetch('/rest/v1/rpc/delete_my_account', { method: 'POST', body: {} });
          meta.cloud = null; meta.sync = { rev: 0, dirty: false, lastAt: 0 }; ckBytes = null; ckKey = null;
          state.settings.cloudReminders = false; saveMeta(); save(); render(); toast('Cuenta eliminada');
        } });
    },
    export() {
      const backup = { app: 'paydar', v: 2, exportedAt: new Date().toISOString(), pin: meta.pin, data: readJSON(K_DATA) };
      download(`${APP.toLowerCase()}-respaldo-${todayISO()}.json`, JSON.stringify(backup), 'application/json');
      toast('Respaldo descargado ✔');
    },
    import() { $('#importFile', sheet).click(); },
    demo() { loadDemo(); closeSheet(); commit('Datos de ejemplo cargados'); },
    wipe() {
      openForm({ title: 'Borrar todo de este teléfono', submitLabel: 'Borrar definitivamente', fields: [
        { type: 'html', html: `<p class="note">Elimina tarjetas, servicios, movimientos, deudas, PIN y ${BIO} de este teléfono.${meta.cloud ? ' Tu respaldo en la nube <b>no</b> se borra.' : ' No se puede deshacer.'}</p>` },
        { name: 'confirm', label: 'Escribe BORRAR para confirmar', required: true, max: 10 }],
        async onSubmit(v) {
          if (v.confirm.toUpperCase() !== 'BORRAR') return 'Escribe la palabra BORRAR.';
          if (meta.dev.push) await disablePush();
          localStorage.removeItem(K_DATA); localStorage.removeItem(K_META); location.reload();
        } });
    },
  };
  const weakPin = (p) => /^(\d)\1+$/.test(p) || '0123456789'.includes(p) || '9876543210'.includes(p);

  async function importBackup(e) {
    const file = e.target.files?.[0]; if (!file) return;
    if (file.size > 5 * 1024 * 1024) return toast('El archivo es demasiado grande.');
    try {
      const b = JSON.parse(await file.text());
      if (b?.app === 'paydar' && b.pin?.salt && b.data?.iv) {
        if (!(await confirmBox('Esto reemplazará los datos de este teléfono. Necesitarás el PIN del respaldo. ¿Continuar?', 'Restaurar'))) return;
        if (meta.dev.push) await disablePush();
        localStorage.setItem(K_DATA, JSON.stringify(b.data));
        localStorage.setItem(K_META, JSON.stringify({ ...defaultMeta(), pin: b.pin }));
        location.reload(); return;
      }
      if (b?.app === 'al-corriente' && b.data) {
        if (!(await confirmBox('Respaldo de la versión anterior. Reemplazará los datos de este teléfono. ¿Continuar?', 'Restaurar'))) return;
        localStorage.removeItem(K_META); localStorage.removeItem(K_DATA);
        localStorage.setItem(OLD_DATA, JSON.stringify(b.data));
        localStorage.setItem(OLD_META, JSON.stringify({ pin: !!b.meta?.pin, salt: b.meta?.salt || null }));
        location.reload(); return;
      }
      throw new Error('formato');
    } catch { toast(`Ese archivo no es un respaldo válido de ${APP}.`); }
  }
  function download(name, text, type) {
    const blob = new Blob([text], { type });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
  }

  /* ---------- Calendario (.ics) ---------- */
  function buildICS() {
    const L = ['BEGIN:VCALENDAR', 'VERSION:2.0', `PRODID:-//${APP}//Finanzas//ES`, 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH', `X-WR-CALNAME:Mis pagos (${APP})`];
    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
    const icsEsc = (s) => String(s).replace(/[\\;,]/g, (c) => '\\' + c).replace(/\n/g, '\\n');
    const pre = state.settings.alertDays;
    const rule = (day, interval = 1) => `FREQ=MONTHLY;INTERVAL=${interval};` + (day > 28 ? `BYMONTHDAY=${day},-1;BYSETPOS=1` : `BYMONTHDAY=${day}`);
    const ev = (id, summary, date, rrule) => {
      L.push('BEGIN:VEVENT', `UID:${id}@paydar`, `DTSTAMP:${stamp}`, `DTSTART;VALUE=DATE:${date.replace(/-/g, '')}`, `SUMMARY:${icsEsc(summary)}`, 'TRANSP:TRANSPARENT');
      if (rrule) L.push('RRULE:' + rrule);
      L.push('BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${icsEsc(summary)}`, `TRIGGER:-P${pre}D`, 'END:VALARM',
        'BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${icsEsc(summary)}`, 'TRIGGER:PT9H', 'END:VALARM', 'END:VEVENT');
    };
    state.cards.forEach((c) => ev('card-' + c.id, `💳 Pagar tarjeta ${c.alias}`, dueOf(c), rule(c.payDay)));
    state.bills.filter((b) => !b.done).forEach((b) => { const r = Number(b.recur); ev('bill-' + b.id, `🧾 Pagar ${b.name || billLabel(b.type)}`, b.dueDate, r > 0 ? rule(b.dueDay || parseISO(b.dueDate).getDate(), r) : null); });
    state.debts.filter((d) => d.balance > 0).forEach((d) => ev('debt-' + d.id, `💵 Pago ${d.name}`, dueOf(d), rule(d.payDay)));
    state.cards.forEach((c) => c.promos.filter((p) => daysUntil(p.endDate) >= 0).forEach((p) => ev('promo-' + p.id, `🏷️ Termina promo: ${p.title} (${c.alias})`, p.endDate, null)));
    L.push('END:VCALENDAR');
    return L.join('\r\n');
  }

  /* ---------- Avisos al abrir la app (respaldo local si no hay push) ---------- */
  async function checkNotifications(force) {
    if (meta.dev.push || !meta.dev.notify || !('Notification' in window) || Notification.permission !== 'granted') return;
    const reg = await navigator.serviceWorker?.getRegistration?.().catch(() => null);
    const t = todayISO(); let changed = false;
    const show = (tag, title, body) => {
      if (state.notified[tag] === t && !force) return;
      state.notified[tag] = t; changed = true;
      const opts = { body, tag, icon: 'icon-192.png', badge: 'icon-192.png' };
      try { reg ? reg.showNotification(title, opts) : new Notification(title, opts); } catch { /* ignorar */ }
    };
    for (const e of upcoming()) {
      const d = daysUntil(e.date);
      if (d <= state.settings.alertDays) show(`${e.kind}-${e.id}-${e.date}`, e.title, d < 0 ? 'Pago vencido' : d === 0 ? 'Vence hoy' : `Vence en ${d} ${d === 1 ? 'día' : 'días'}`);
    }
    for (const p of promosSoon(3)) if (p.d >= 0) show(`promo-${p.promo.id}`, 'Promoción por terminar', `${p.promo.title} · ${p.card.alias}`);
    const cutoff = iso(addDays(today0(), -45));
    for (const k of Object.keys(state.notified)) if (state.notified[k] < cutoff) { delete state.notified[k]; changed = true; }
    if (changed) writeLocal();
  }

  /* ---------- Datos de ejemplo ---------- */
  function loadDemo() {
    const t = today0(); const d = (n) => iso(addDays(t, n));
    const day = (n) => addDays(t, n).getDate();
    state.cards.push(
      { id: uid(), alias: 'Oro', bank: 'Banco Ejemplo', last4: '4821', cutDay: day(-8), payDay: day(4), limit: 60000, balance: 18450, noInterest: 9200, minPay: 1150, color: 0, promos: [{ id: uid(), title: '12 MSI en electrónica', endDate: d(6), note: 'Compra mínima $3,000' }] },
      { id: uid(), alias: 'Departamental', bank: 'Tienda Ejemplo', last4: '1037', cutDay: day(10), payDay: day(5), limit: 25000, balance: 4300, noInterest: 4300, minPay: 450, color: 2, promos: [] },
    );
    state.cards.forEach((c) => { c.lastPaid = prevOccurrence(c.payDay); });
    state.bills.push(
      { id: uid(), type: 'luz', name: 'CFE casa', amount: 860, dueDate: d(2), dueDay: day(2), recur: 2, done: false },
      { id: uid(), type: 'agua', name: 'Agua', amount: 310, dueDate: d(12), dueDay: day(12), recur: 2, done: false },
      { id: uid(), type: 'internet', name: 'Internet', amount: 549, dueDate: d(-1), dueDay: day(-1), recur: 1, done: false },
      { id: uid(), type: 'celular', name: 'Celular', amount: 299, dueDate: d(18), dueDay: day(18), recur: 1, done: false },
      { id: uid(), type: 'gas', name: 'Gas', amount: 650, dueDate: d(21), dueDay: day(21), recur: 1, done: false },
    );
    state.debts.push({ id: uid(), name: 'Crédito auto', lender: 'Financiera Ejemplo', balance: 142000, original: 260000, monthly: 6800, payDay: day(9), lastPaid: prevOccurrence(day(9)) });
    const back = (n) => Math.min(n, t.getDate() - 1);
    const card0 = 'card:' + state.cards[0].id;
    addMove({ type: 'ingreso', amount: 18500, category: 'Sueldo', date: d(-back(10)), note: 'Quincena', method: 'cash' });
    addMove({ type: 'gasto', amount: 2340, category: 'Súper y despensa', date: d(-back(3)), note: 'Súper semanal', method: card0 });
    addMove({ type: 'gasto', amount: 680, category: 'Comida fuera', date: d(-back(2)), note: 'Comida familiar', method: card0 });
    addMove({ type: 'gasto', amount: 900, category: 'Transporte y gasolina', date: d(-back(5)), note: 'Gasolina', method: 'cash' });
    addMove({ type: 'gasto', amount: 450, category: 'Entretenimiento', date: d(-back(1)), note: 'Cine', method: 'cash' });
    state.cards[0].balance = 18450;
  }

  /* ---------- Pantallas de acceso ---------- */
  const gate = (inner) => `<div class="gate"><img src="icon-192.png" alt="">${inner}</div>`;
  function gateForm(id, fields, submit, extra = '') {
    return `<form id="${id}" novalidate>${fields.map(fieldHTML).join('')}<p class="form-err" hidden></p><button class="btn primary block" type="submit">${esc(submit)}</button>${extra}</form>`;
  }
  function bindGateForm(id, fields, handler) {
    const f = $('#' + id); const err = $('.form-err', f); const btn = $('button[type=submit]', f);
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      const { vals, err: e1 } = readForm(f, fields);
      const show = (m) => { err.textContent = m; err.hidden = false; };
      if (e1) return show(e1);
      const label = btn.textContent; btn.disabled = true; btn.textContent = 'Un momento…'; err.hidden = true;
      try { const r = await handler(vals); if (typeof r === 'string') show(r); }
      catch (ex) { show(ex instanceof CloudError ? ex.message : 'Ocurrió un error. Intenta de nuevo.'); }
      finally { if (document.body.contains(btn)) { btn.disabled = false; btn.textContent = label; } }
    });
    return f;
  }
  const pinFields = (label = `Crea un PIN de ${PIN_LEN} números`) => [
    { name: 'p1', label, type: 'pin', required: true, help: 'Con él abres la app y se cifran tus datos en este teléfono.' },
    { name: 'p2', label: 'Repite tu PIN', type: 'pin', required: true },
  ];
  const pinError = (v) => (v.p1 !== v.p2 ? 'Los PIN no coinciden.' : weakPin(v.p1) ? 'Ese PIN es muy fácil de adivinar. Elige otro.' : null);

  async function createLocalVault(pin) {
    dkBytes = rand(32); dkKey = await aesImport(dkBytes);
    const salt = rand(16);
    meta = defaultMeta();
    meta.pin = { salt: toB64(salt), ...(await encBytes(await pbkdf2Key(pin, salt), dkBytes)) };
    if (pendingCloud) {
      const pc = pendingCloud; pendingCloud = null;
      await attachCloud({ email: pc.email, userId: pc.userId, session: pc.session, ck: pc.ck, rev: pc.rev });
    }
    saveMeta(); snapshotIndex(); await writeLocal();
  }

  function renderOnboarding() {
    const fields = [{ name: 'name', label: '¿Cómo te llamas?', placeholder: 'Tu nombre', max: 30 }, ...pinFields()];
    app.innerHTML = gate(`<h1>Bienvenido a ${APP}</h1>
      <p>Tus tarjetas, servicios, gastos y deudas en un solo lugar, con avisos antes de cada pago.</p>
      ${gateForm('onb', fields, 'Empezar', CLOUD ? '<button class="btn ghost block" type="button" id="haveAcct">Ya tengo cuenta: recuperar mis datos</button>' : '')}
      <p class="note">🔒 Sin anuncios y sin pedir datos bancarios. Tus datos se cifran en tu teléfono.</p>`);
    bindGateForm('onb', fields, async (v) => {
      const pe = pinError(v); if (pe) return pe;
      state = defaultState(); state.profile.name = v.name || '';
      await createLocalVault(v.p1); afterUnlock(); setTimeout(offerBio, 600);
    });
    $('#haveAcct')?.addEventListener('click', renderRestore);
  }

  function renderRestore() {
    const fields = [{ name: 'email', label: 'Correo electrónico', type: 'email', required: true }, ...pwFields(false)];
    app.innerHTML = gate(`<h1>Recuperar mis datos</h1><p>Entra con la cuenta que creaste en ${APP}.</p>
      ${gateForm('rst', fields, 'Entrar', '<button class="btn ghost block" type="button" id="forgot">Olvidé mi contraseña</button><button class="btn ghost block" type="button" id="back">Volver</button>')}`);
    bindGateForm('rst', fields, async (v) => {
      const s = await cloudSignIn(v.email, v.pw);
      const vault = await getVault(s.userId, s.session.access);
      if (!vault) return 'Esta cuenta todavía no tiene datos respaldados.';
      let ck;
      try { ck = await decBytes(await pbkdf2Key(v.pw, fromB64(vault.salt_pw)), vault.wrap_pw); } catch { return 'No se pudo abrir tu respaldo.'; }
      state = migrate(await decJSON(await aesImport(ck), vault.data));
      pendingCloud = { email: s.email, userId: s.userId, session: s.session, ck, rev: vault.rev };
      renderNewPin('¡Listo! Encontramos tus datos. Ahora crea un PIN para este teléfono.');
    });
    $('#forgot').addEventListener('click', () => forgotPassword($('#f_email').value.trim()));
    $('#back').addEventListener('click', renderOnboarding);
  }

  function renderNewPin(msg) {
    const fields = pinFields();
    app.innerHTML = gate(`<h1>Crea tu PIN</h1><p>${esc(msg)}</p>${gateForm('npin', fields, 'Continuar')}`);
    bindGateForm('npin', fields, async (v) => {
      const pe = pinError(v); if (pe) return pe;
      await createLocalVault(v.p1);
      if (legacy) { localStorage.removeItem(OLD_DATA); localStorage.removeItem(OLD_META); legacy = null; }
      afterUnlock(); setTimeout(offerBio, 600);
    });
  }

  // Enlace "olvidé mi contraseña" (llega con #access_token…&type=recovery)
  function renderRecovery(sess) {
    const fields = [{ name: 'code', label: 'Código de recuperación', required: true, max: 40, autocap: false, placeholder: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX' }, ...pwFields(true, 'Nueva contraseña')];
    app.innerHTML = gate(`<h1>Nueva contraseña</h1><p>Escribe el código de recuperación que guardaste al crear tu cuenta.</p>
      ${gateForm('rec', fields, 'Guardar nueva contraseña', '<button class="btn ghost block" type="button" id="cancel">Cancelar</button>')}`);
    bindGateForm('rec', fields, async (v) => {
      const pe = pwError(v); if (pe) return pe;
      const user = await sbFetch('/auth/v1/user', { token: sess.access });
      const vault = await getVault(user.id, sess.access);
      if (!vault) return 'No se encontró respaldo para esta cuenta.';
      let ck;
      try { ck = await decBytes(await pbkdf2Key(normCode(v.code), fromB64(vault.salt_rec), 100000), vault.wrap_rec); } catch { return 'El código de recuperación no es correcto.'; }
      const salt = rand(16);
      await sbFetch(`/rest/v1/vaults?user_id=eq.${encodeURIComponent(user.id)}`, { method: 'PATCH', token: sess.access, body: { salt_pw: toB64(salt), wrap_pw: await encBytes(await pbkdf2Key(v.pw, salt), ck) } });
      await sbFetch('/auth/v1/user', { method: 'PUT', token: sess.access, body: { password: await authSecretOf(user.email, v.pw) } });
      if (meta?.pin) {
        if (meta.cloud?.userId === user.id) { meta.cloud.session = sess; saveMeta(); }
        bootMsg = 'Contraseña cambiada ✔. Entra con tu PIN.'; renderLock(); return;
      }
      state = migrate(await decJSON(await aesImport(ck), vault.data));
      pendingCloud = { email: user.email, userId: user.id, session: sess, ck, rev: vault.rev };
      renderNewPin('Contraseña cambiada ✔. Ahora crea un PIN para este teléfono.');
    });
    $('#cancel').addEventListener('click', () => { if (meta?.pin) renderLock(); else renderOnboarding(); });
  }

  function renderLock() {
    let entry = '';
    const showBio = !!meta?.bio;
    app.innerHTML = gate(`<h1>${APP}</h1><p>Escribe tu PIN para entrar</p>
      <div class="dots" aria-hidden="true">${'<i></i>'.repeat(PIN_LEN)}</div>
      <div class="lock-msg" role="alert"></div>
      <div class="pad-keys">${[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => `<button class="key" data-k="${n}">${n}</button>`).join('')}${showBio ? `<button class="key ghost" id="bioKey" aria-label="Usar ${BIO}">${icon('finger')}</button>` : '<span></span>'}<button class="key" data-k="0">0</button><button class="key ghost" data-k="del" aria-label="Borrar">Borrar</button></div>
      ${showBio ? `<button class="btn soft" id="bioBtn">${icon('finger')} Entrar con ${BIO}</button>` : ''}
      <button class="btn ghost" id="forgotPin">Olvidé mi PIN</button>`);
    const dots = $$('.dots i'); const msg = $('.lock-msg'); let busy = false;
    if (bootMsg) { msg.textContent = ''; toast(bootMsg); bootMsg = ''; }
    const paint = () => dots.forEach((d, i) => d.classList.toggle('on', i < entry.length));
    const press = async (k) => {
      if (busy) return;
      const wait = (meta.lockUntil || 0) - Date.now();
      if (wait > 0) { msg.textContent = `Demasiados intentos. Espera ${Math.ceil(wait / 1000)} segundos.`; return; }
      if (k === 'del') { entry = entry.slice(0, -1); paint(); return; }
      if (entry.length >= PIN_LEN) return;
      entry += k; paint();
      if (entry.length === PIN_LEN) {
        busy = true; msg.textContent = 'Verificando…';
        const ok = await tryUnlockPin(entry);
        busy = false;
        if (!ok) {
          entry = ''; paint(); const box = $('.dots'); box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake');
          const w = (meta.lockUntil || 0) - Date.now();
          msg.textContent = w > 0 ? `PIN incorrecto. Espera ${Math.ceil(w / 1000)} segundos.` : `PIN incorrecto (${meta.fails} de 5 intentos).`;
        }
      }
    };
    $$('[data-k]').forEach((b) => b.addEventListener('click', () => press(b.dataset.k)));
    document.onkeydown = (e) => { if (state) return; if (/^\d$/.test(e.key)) press(e.key); else if (e.key === 'Backspace') press('del'); };
    const bio = async () => {
      if (busy) return; busy = true; msg.textContent = '';
      try {
        const out = await bioAssert(fromB64(meta.bio.credId), fromB64(meta.bio.prfSalt));
        const raw = await decBytes(await hkdfKey(out, 'bio-kek'), meta.bio);
        await openWithDK(raw);
      } catch (e) { if (e?.name !== 'NotAllowedError') msg.textContent = `No se pudo usar ${BIO}. Usa tu PIN.`; }
      busy = false;
    };
    $('#bioBtn')?.addEventListener('click', bio);
    $('#bioKey')?.addEventListener('click', bio);
    $('#forgotPin').addEventListener('click', async () => {
      const txt = meta.cloud
        ? 'Sin el PIN no se pueden abrir los datos de este teléfono. Puedes borrarlos aquí y recuperarlos de tu cuenta en la nube. ¿Borrar este teléfono y recuperar desde la nube?'
        : 'Sin el PIN no es posible abrir tus datos (no tienes cuenta en la nube). Puedes borrar todo y empezar de nuevo, o restaurar un archivo de respaldo. ¿Borrar todo?';
      if (await confirmBox(txt, meta.cloud ? 'Borrar y recuperar' : 'Borrar todo')) {
        localStorage.removeItem(K_DATA); localStorage.removeItem(K_META); location.reload();
      }
    });
    if (showBio && !isApple) setTimeout(() => { if (!state && document.visibilityState === 'visible') bio(); }, 400);
  }

  async function openWithDK(raw) {
    const k = await aesImport(raw);
    const data = await decJSON(k, readJSON(K_DATA));
    dkBytes = raw; dkKey = k; state = migrate(data);
    if (meta.cloud?.ck) { try { ckBytes = await decBytes(dkKey, meta.cloud.ck); ckKey = await aesImport(ckBytes); } catch { meta.cloud = null; } }
    meta.fails = 0; meta.lockUntil = 0; saveMeta();
    snapshotIndex(); afterUnlock();
  }
  async function tryUnlockPin(pin) {
    try {
      if (legacy) {
        const old = await decJSON(await pbkdf2Key(pin, fromB64(legacy.meta.salt)), legacy.data);
        state = migrate(old);
        await createLocalVault(pin);
        localStorage.removeItem(OLD_DATA); localStorage.removeItem(OLD_META); legacy = null;
        afterUnlock(); toast(`¡Bienvenido a ${APP} 2! Tus datos se actualizaron.`); return true;
      }
      const raw = await decBytes(await pbkdf2Key(pin, fromB64(meta.pin.salt)), meta.pin);
      await openWithDK(raw); return true;
    } catch {
      const m = meta;
      m.fails = (m.fails || 0) + 1;
      if (m.fails >= 5) m.lockUntil = Date.now() + 30000 * 2 ** Math.min(m.fails - 5, 6);
      if (!legacy) saveMeta();
      return false;
    }
  }
  function afterUnlock() {
    document.onkeydown = null;
    view = 'inicio'; monthCursor = null; lastActive = Date.now();
    render(); checkNotifications(false);
    if (ckKey) syncNow();
    if (bootMsg) { toast(bootMsg); bootMsg = ''; }
  }
  function lock() {
    if (!meta?.pin || !state) return;
    closeSheet(); $$('dialog.confirm').forEach((d) => d.remove());
    clearTimeout(syncTimer);
    state = null; dkBytes = null; dkKey = null; ckBytes = null; ckKey = null; lastIdx = {};
    renderLock();
  }

  /* ---------- Eventos globales ---------- */
  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-act]'); if (!b || !state) return;
    const fn = ACTIONS[b.dataset.act]; if (!fn) return;
    if (sheet.open && !sheet.contains(b)) return;
    if (sheet.open && sheet.contains(b)) closeSheet();
    fn(b.dataset.id);
  });
  document.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.row[data-act]')) { e.preventDefault(); e.target.click(); } });
  ['pointerdown', 'keydown', 'touchstart'].forEach((ev) => document.addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true }));
  setInterval(() => { if (meta?.pin && state && Date.now() - lastActive > IDLE_LOCK_MS) lock(); }, 15000);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { hiddenAt = Date.now(); if (state && ckKey && meta.sync.dirty) syncNow(); }
    else if (meta?.pin && state && hiddenAt && Date.now() - hiddenAt > BG_LOCK_MS) lock();
    else if (state && !sheet.open) { render(); checkNotifications(false); if (ckKey) scheduleSync(300); }
  });
  window.addEventListener('online', () => { if (state && ckKey) scheduleSync(500); });

  /* ---------- Arranque ---------- */
  async function boot() {
    if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
    if (navigator.storage?.persist) navigator.storage.persist().catch(() => {});
    if (!window.crypto?.subtle) { app.innerHTML = gate('<h1>Abre la app desde una dirección segura</h1><p>Esta app necesita https para proteger tus datos.</p>'); return; }

    // Enlaces que llegan desde correos de la cuenta
    if (location.hash.length > 1) {
      const hp = new URLSearchParams(location.hash.slice(1));
      history.replaceState(null, '', location.pathname + location.search);
      if (hp.get('error_description')) bootMsg = 'El enlace venció o ya se usó. Pide uno nuevo.';
      else if (hp.get('access_token')) {
        const sess = { access: hp.get('access_token'), refresh: hp.get('refresh_token'), expiresAt: Date.now() + (Number(hp.get('expires_in')) || 3600) * 1000 };
        if (hp.get('type') === 'recovery' && CLOUD) { renderRecovery(sess); return; }
        bootMsg = 'Correo confirmado ✔. Entra y ve a Ajustes → Ya tengo cuenta: iniciar sesión.';
      }
    }

    const data = readJSON(K_DATA);
    if (meta?.pin && data) { renderLock(); return; }

    // Migración desde la versión 1 (Al Corriente)
    const om = readJSON(OLD_META), od = readJSON(OLD_DATA);
    if (om && od) {
      meta = null;
      if (om.pin && om.salt && od.iv) { legacy = { meta: om, data: od, fails: 0, lockUntil: 0 }; meta = { ...defaultMeta(), fails: 0 }; renderLock(); return; }
      if (od.data) { legacy = { meta: om, data: od }; state = migrate(od.data); renderNewPin(`${APP} ahora protege tus datos con PIN. Crea uno para continuar.`); return; }
    }
    meta = null;
    renderOnboarding();
    if (bootMsg) { toast(bootMsg); bootMsg = ''; }
  }
  boot();
})();
