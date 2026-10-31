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
  (await pool.query('select key,name,hash from users')).rows.forEach(r => users[r.key] = { name: r.name, hash: r.hash });
  console.log('loaded ' + Object.keys(users).length + ' users from database');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const okName = u => typeof u === 'string' && /^[\w\u0600-\u06FF.\-]{3,20}$/.test(u);
const okPass = p => typeof p === 'string' && p.length >= 4 && p.length <= 64;

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
const pub = () => [...rooms.values()].map(r => ({ id: r.id, name: r.name, locked: !!r.hash, count: r.members.size, owner: r.owner }));
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

  s.on('create', ({ name, password }, ack) => {
    name = String(name || '').trim().slice(0, 30);
    if (name.length < 2) return ack({ error: 'نام روم باید حداقل ۲ حرف باشد.' });
    if ([...rooms.values()].some(r => r.name.toLowerCase() === name.toLowerCase())) return ack({ error: 'روم دیگری با این نام وجود دارد.' });
    const id = Math.random().toString(36).slice(2, 9);
    rooms.set(id, { id, name, owner: s.user, hash: password ? bcrypt.hashSync(String(password), 8) : null, members: new Map() });
    push(); ack({ ok: true, id });
  });

  s.on('join', ({ id, password }, ack) => {
    const r = rooms.get(id);
    if (!r) return ack({ error: 'این روم دیگر وجود ندارد.' });
    if (r.hash && !bcrypt.compareSync(String(password || ''), r.hash)) return ack({ error: 'رمز روم اشتباه است.' });
    if (r.members.size >= MAX_MEMBERS && !r.members.has(s.id)) return ack({ error: 'ظرفیت روم پر است.' });
    if (s.roomId) leave();
    const peers = [...r.members].map(([sid, name]) => ({ id: sid, name }));
    r.members.set(s.id, s.user); s.roomId = id; s.join(id);
    s.to(id).emit('peer-joined', { id: s.id, name: s.user });
    push(); ack({ ok: true, name: r.name, owner: r.owner, peers });
  });

  s.on('signal', ({ to, data }) => io.to(to).emit('signal', { from: s.id, data }));
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

process.on('uncaughtException', e => console.error('uncaught', e));
process.on('unhandledRejection', e => console.error('unhandled', e));

init().then(() => srv.listen(process.env.PORT || 3000, () => console.log('running'))).catch(e => { console.error(e); process.exit(1); });
