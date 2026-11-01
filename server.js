const express = require('express'), http = require('http'), fs = require('fs'), path = require('path');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), { Server } = require('socket.io');
const app = express(), srv = http.createServer(app), io = new Server(srv);
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const FILE = path.join(process.env.DATA_DIR || __dirname, 'users.json');
const MAX_MEMBERS = 6;
let users = {};
try { users = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
const save = () => { try { fs.writeFileSync(FILE, JSON.stringify(users)); } catch (e) { console.error(e.message); } };
// Persistent storage: if DATABASE_URL is set, accounts live in Postgres (survive restarts)
const pool = process.env.DATABASE_URL ? new (require('pg').Pool)({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;
async function init() {
  if (!pool) return console.warn('DATABASE_URL not set: accounts are stored in a temporary file');
  await pool.query('create table if not exists users(key text primary key, name text not null, hash text not null)');
  await pool.query('alter table users add column if not exists avatar text');
  (await pool.query('select key,name,hash,avatar from users')).rows.forEach(r => users[r.key] = { name: r.name, hash: r.hash, avatar: r.avatar || '' });
  console.log('loaded ' + Object.keys(users).length + ' users from database');
}

app.use(express.json({ limit: '400kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const okName = u => typeof u === 'string' && /^[\w\u0600-\u06FF.\-]{3,20}$/.test(u);
const okPass = p => typeof p === 'string' && p.length >= 4 && p.length <= 64;

const authReq = (req, res, next) => {
  try {
    const { u } = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const rec = users[u.toLowerCase()]; if (!rec) throw 0;
    req.key = u.toLowerCase(); req.rec = rec; next();
  } catch { res.status(401).json({ error: 'auth' }); }
};
app.get('/api/me', authReq, (req, res) => res.json({ username: req.rec.name, avatar: req.rec.avatar || '' }));

app.post('/api/profile', authReq, async (req, res) => {
  const { currentPassword, newUsername, newPassword, avatar } = req.body || {};
  const rec = req.rec, key = req.key;
  let name = rec.name, hash = rec.hash, av = rec.avatar || '';
  const wantsName = typeof newUsername === 'string' && newUsername && newUsername !== rec.name;
  if (wantsName || newPassword) {
    if (!bcrypt.compareSync(String(currentPassword || ''), rec.hash)) return res.status(401).json({ error: 'رمز فعلی اشتباه است.' });
  }
  if (wantsName) {
    if (!okName(newUsername)) return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۲۰ حرف (فارسی، انگلیسی، عدد، _ . -) باشد.' });
    if (newUsername.toLowerCase() !== key && users[newUsername.toLowerCase()]) return res.status(409).json({ error: 'این نام کاربری قبلاً گرفته شده.' });
    name = newUsername;
  }
  if (newPassword) {
    if (!okPass(newPassword)) return res.status(400).json({ error: 'رمز جدید باید حداقل ۴ کاراکتر باشد.' });
    hash = bcrypt.hashSync(newPassword, 10);
  }
  if (typeof avatar === 'string') {
    if (avatar === '') av = '';
    else if (avatar.length < 200000 && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(avatar)) av = avatar;
    else return res.status(400).json({ error: 'عکس نامعتبر است.' });
  }
  const nk = name.toLowerCase();
  try {
    if (pool) await pool.query('update users set key=$1,name=$2,hash=$3,avatar=$4 where key=$5', [nk, name, hash, av, key]);
    if (nk !== key) delete users[key];
    users[nk] = { name, hash, avatar: av }; if (!pool) save();
    if (name !== rec.name) { rooms.forEach(r => { if (r.owner === rec.name) r.owner = name; }); push(); }
    res.json({ token: jwt.sign({ u: name }, SECRET, { expiresIn: '30d' }), username: name, avatar: av });
  } catch (e) { console.error(e); res.status(500).json({ error: 'خطای سرور، دوباره تلاش کن.' }); }
});

app.get('/health', (_, res) => res.send('ok'));

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!okName(username)) return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۲۰ حرف (فارسی، انگلیسی، عدد، _ . -) باشد.' });
  if (!okPass(password)) return res.status(400).json({ error: 'رمز عبور باید حداقل ۴ کاراکتر باشد.' });
  const key = username.toLowerCase();
  if (users[key]) return res.status(409).json({ error: 'این نام کاربری قبلاً گرفته شده.' });
  const u = { name: username, hash: bcrypt.hashSync(password, 10) };
  try {
    if (pool) {
      const r = await pool.query('insert into users(key,name,hash) values($1,$2,$3) on conflict do nothing', [key, u.name, u.hash]);
      if (!r.rowCount) return res.status(409).json({ error: 'این نام کاربری قبلاً گرفته شده.' });
    }
    users[key] = u; if (!pool) save();
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'خطای سرور، دوباره تلاش کن.' }); }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = typeof username === 'string' && users[username.toLowerCase()];
  if (!u || !bcrypt.compareSync(String(password || ''), u.hash))
    return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
  res.json({ token: jwt.sign({ u: u.name }, SECRET, { expiresIn: '30d' }), username: u.name });
});

// Optional TURN server (helps when direct connection fails)
app.get('/api/ice', (_, res) => {
  const ice = [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun.cloudflare.com:3478' }];
  if (process.env.TURN_URL) ice.push({ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  res.json(ice);
});

// ---- Rooms (in memory) ----
const rooms = new Map();
const pub = () => [...rooms.values()].map(r => ({ id: r.id, name: r.name, locked: !!r.hash, count: r.members.size, owner: r.owner, ask: !!r.ask, max: r.max }));
const avOf = n => (users[String(n).toLowerCase()] || {}).avatar || '';
const push = () => io.emit('rooms', pub());

io.use((s, next) => {
  try {
    const { u } = jwt.verify(s.handshake.auth.token, SECRET);
    if (!users[u.toLowerCase()]) return next(new Error('auth'));
    s.user = users[u.toLowerCase()].name; next();
  } catch { next(new Error('auth')); }
});

io.on('connection', s => {
  s.roomId = null;
  const leave = () => {
    const r = rooms.get(s.roomId);
    if (r) { r.members.delete(s.id); s.to(r.id).emit('peer-left', s.id); s.leave(r.id); }
    s.roomId = null; push();
  };

  s.on('rooms', (...a) => { const ack = a.find(x => typeof x === 'function'); if (ack) ack(pub()); });

  s.on('create', ({ name, password, max }, ack) => {
    name = String(name || '').trim().slice(0, 30);
    if (name.length < 2) return ack({ error: 'نام روم باید حداقل ۲ حرف باشد.' });
    if ([...rooms.values()].some(r => r.name.toLowerCase() === name.toLowerCase())) return ack({ error: 'روم دیگری با این نام وجود دارد.' });
    const id = Math.random().toString(36).slice(2, 9);
    rooms.set(id, { id, name, owner: s.user, hash: password ? bcrypt.hashSync(String(password), 8) : null, members: new Map(), msgs: [], max: Math.min(10, Math.max(2, parseInt(max) || 6)) });
    push(); ack({ ok: true, id });
  });

  s.on('join', ({ id, password }, ack) => {
    const r = rooms.get(id);
    if (!r) return ack({ error: 'این روم دیگر وجود ندارد.' });
    const knocked = !!(r.allowed && r.allowed.delete(s.id));
    if (r.hash && !knocked && !bcrypt.compareSync(String(password || ''), r.hash)) return ack({ error: 'رمز روم اشتباه است.' });
    if (r.members.size >= r.max && !r.members.has(s.id)) return ack({ error: 'ظرفیت روم پر است.' });
    if (s.roomId) leave();
    const av = n => (users[n.toLowerCase()] || {}).avatar || '';
    const peers = [...r.members].map(([sid, name]) => ({ id: sid, name, avatar: av(name), mic: (io.sockets.sockets.get(sid) || {}).mic !== false }));
    r.members.set(s.id, s.user); s.roomId = id; s.mic = true; s.join(id);
    s.to(id).emit('peer-joined', { id: s.id, name: s.user, avatar: av(s.user), mic: true });
    push(); ack({ ok: true, name: r.name, owner: r.owner, peers, ask: !!r.ask, msgs: r.msgs });
  });

  s.on('signal', ({ to, data }) => io.to(to).emit('signal', { from: s.id, data }));
  s.on('state', d => { s.mic = !!(d && d.mic); if (s.roomId) s.to(s.roomId).emit('state', { id: s.id, mic: s.mic }); });
  const ownRoom = id => { const r = rooms.get(id); return r && r.owner === s.user ? r : null; };
  s.on('chat', t => {
    const r = rooms.get(s.roomId); t = String(t || '').trim().slice(0, 500); if (!r || !t) return;
    const m = { id: Math.random().toString(36).slice(2, 9), user: s.user, avatar: avOf(s.user), text: t, ts: Date.now() };
    r.msgs.push(m); if (r.msgs.length > 200) r.msgs.shift(); io.to(r.id).emit('chat', m);
  });
  s.on('chat-edit', ({ id, text } = {}) => {
    const r = rooms.get(s.roomId), m = r && r.msgs.find(x => x.id === id); text = String(text || '').trim().slice(0, 500);
    if (m && m.user === s.user && text) { m.text = text; io.to(r.id).emit('chat-edit', { id, text }); }
  });
  s.on('chat-del', id => {
    const r = rooms.get(s.roomId), i = r ? r.msgs.findIndex(x => x.id === id && x.user === s.user) : -1;
    if (i >= 0) { r.msgs.splice(i, 1); io.to(r.id).emit('chat-del', id); }
  });
  s.on('ask', ({ id, on } = {}) => { const r = ownRoom(id); if (r) { r.ask = !!on; push(); } });
  s.on('knock', (id, ack) => {
    const r = rooms.get(id); if (typeof ack !== 'function') return;
    if (!r || !r.ask) return ack({ error: 'این روم ورود با اجازه ندارد.' });
    let sent = 0;
    for (const x of io.sockets.sockets.values()) if (x.user === r.owner) { x.emit('knock', { rid: r.id, room: r.name, from: s.user, sid: s.id }); sent++; }
    ack(sent ? { ok: true } : { error: 'صاحب روم الان آنلاین نیست.' });
  });
  s.on('knock-reply', ({ rid, sid, ok } = {}) => {
    const r = ownRoom(rid); if (!r) return;
    if (ok) (r.allowed = r.allowed || new Set()).add(sid);
    io.to(sid).emit('knock-result', { rid, ok: !!ok, room: r.name });
  });
  s.on('leave', leave);

  s.on('delete', (id, ack) => {
    const r = rooms.get(id);
    if (!r || r.owner !== s.user) return ack && ack({ error: 'فقط صاحب روم می‌تواند آن را حذف کند.' });
    io.to(id).emit('room-deleted');
    for (const sid of r.members.keys()) { const x = io.sockets.sockets.get(sid); if (x) { x.leave(id); x.roomId = null; } }
    rooms.delete(id); push(); ack && ack({ ok: true });
  });

  s.on('disconnect', leave);
});

// delete chat messages older than 15 minutes
setInterval(() => {
  const lim = Date.now() - 15 * 60000;
  rooms.forEach(r => { const old = r.msgs.filter(m => m.ts < lim); if (old.length) { r.msgs = r.msgs.filter(m => m.ts >= lim); old.forEach(m => io.to(r.id).emit('chat-del', m.id)); } });
}, 15000);

process.on('uncaughtException', e => console.error('uncaught', e));
process.on('unhandledRejection', e => console.error('unhandled', e));

init().then(() => srv.listen(process.env.PORT || 3000, () => console.log('running'))).catch(e => { console.error(e); process.exit(1); });
