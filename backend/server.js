import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});
const JWT_SECRET = 'almal_secret_key_2026';

app.use(cors());
app.use(express.json({ limit: '100mb' }));

// ============ إنشاء الجداول ============
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, name TEXT, email TEXT UNIQUE, phone TEXT,
        age INTEGER, gender TEXT, password_hash TEXT, created_at TEXT
      );
      CREATE TABLE IF NOT EXISTS specialists (
        id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password_hash TEXT,
        type TEXT, title TEXT, avatar TEXT, specialization TEXT
      );
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY, user_id INTEGER, user_name TEXT, content TEXT,
        method TEXT, voice_data TEXT, file_data TEXT, file_name TEXT, file_type TEXT,
        status TEXT DEFAULT 'pending', specialist_response TEXT, created_at TEXT
      );
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY, sender_type TEXT, sender_id INTEGER, receiver_id INTEGER,
        message TEXT, is_read INTEGER DEFAULT 0, created_at TEXT
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY, patient_id INTEGER, patient_name TEXT,
        specialist_id INTEGER, specialist_name TEXT, session_date TEXT,
        session_time TEXT, meet_link TEXT, status TEXT, created_at TEXT
      );
      CREATE TABLE IF NOT EXISTS ratings (
        id SERIAL PRIMARY KEY, patient_id INTEGER, specialist_id INTEGER,
        specialist_name TEXT, score INTEGER, comment TEXT, created_at TEXT
      );
      CREATE TABLE IF NOT EXISTS test_results (
        id SERIAL PRIMARY KEY, test_id TEXT, test_name TEXT,
        patient_id INTEGER, patient_name TEXT, specialist_id INTEGER,
        total_score INTEGER, max_score INTEGER, level TEXT, details TEXT, created_at TEXT
      );
    `);

    // إضافة المختصين
    const specialists = [
      { id: 1, name: 'سعيدان شيماء', email: 'chaimaasaidane45@gmail.com', type: 'psychologist', title: 'أخصائي نفسي', avatar: '🧠', specialization: 'علاج القلق والاكتئاب' },
      { id: 2, name: 'كراتو سعاد', email: 'Krattousouad46@gmail.com', type: 'social', title: 'أخصائي اجتماعي', avatar: '🤝', specialization: 'الدعم الأسري' },
      { id: 3, name: 'مقري بشرى', email: 'bouchra.mokri05@gmail.com', type: 'work', title: 'مختصة العمل', avatar: '💼', specialization: 'التوجيه المهني' }
    ];
    for (const s of specialists) {
      const hash = bcrypt.hashSync('12345', 10);
      await pool.query(
        `INSERT INTO specialists (id, name, email, password_hash, type, title, avatar, specialization)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING`,
        [s.id, s.name, s.email, hash, s.type, s.title, s.avatar, s.specialization]
      );
    }
    console.log('✅ Database initialized successfully');
  } catch (err) {
    console.error('❌ DB Init Error:', err);
    throw err;
  }
}

// ============ Middleware للمصادقة ============
function auth(roles = ['patient', 'specialist']) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'unauthorized' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (!roles.includes(payload.role)) return res.status(403).json({ error: 'forbidden' });
      req.auth = payload;
      next();
    } catch { res.status(401).json({ error: 'invalid token' }); }
  };
}

// ============ المصادقة ============
app.post('/api/register', async (req, res) => {
  const { name, email, phone, age, gender, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, age, gender, password_hash, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [name, email, phone, age, gender, hash, new Date().toISOString()]
    );
    res.json({ id: result.rows[0].id });
  } catch (e) {
    res.status(400).json({ error: 'البريد موجود بالفعل' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (!user || !await bcrypt.compare(password, user.password_hash))
    return res.status(401).json({ error: 'بيانات خاطئة' });
  const token = jwt.sign({ id: user.id, role: 'patient', name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, age: user.age, gender: user.gender, phone: user.phone } });
});

app.post('/api/specialist/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM specialists WHERE email=$1', [email]);
  const spec = result.rows[0];
  if (!spec || !await bcrypt.compare(password, spec.password_hash))
    return res.status(401).json({ error: 'بيانات خاطئة' });
  const token = jwt.sign({ id: spec.id, role: 'specialist', name: spec.name }, JWT_SECRET, { expiresIn: '7d' });
  const { password_hash, ...safeSpec } = spec;
  res.json({ token, specialist: safeSpec });
});

// ============ الاستشارات ============
app.post('/api/consultations', auth(['patient']), async (req, res) => {
  const { content, method, voice_data, file_data, file_name, file_type } = req.body;
  const result = await pool.query(
    `INSERT INTO consultations (user_id,user_name,content,method,voice_data,file_data,file_name,file_type,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
    [req.auth.id, req.auth.name, content, method, voice_data, file_data, file_name, file_type, new Date().toISOString()]
  );
  res.json({ id: result.rows[0].id });
});

app.get('/api/consultations', auth(['specialist']), async (req, res) => {
  const result = await pool.query('SELECT * FROM consultations ORDER BY id DESC');
  res.json(result.rows);
});

app.get('/api/my-consultations', auth(['patient']), async (req, res) => {
  const result = await pool.query('SELECT * FROM consultations WHERE user_id=$1 ORDER BY id DESC', [req.auth.id]);
  res.json(result.rows);
});

app.put('/api/consultations/:id/respond', auth(['specialist']), async (req, res) => {
  await pool.query('UPDATE consultations SET specialist_response=$1, status=$2 WHERE id=$3',
    [req.body.response, 'resolved', req.params.id]);
  res.json({ ok: true });
});

// ============ الرسائل ============
app.post('/api/messages', auth(), async (req, res) => {
  const { receiver_id, message } = req.body;
  await pool.query(
    `INSERT INTO messages (sender_type,sender_id,receiver_id,message,created_at)
     VALUES ($1,$2,$3,$4,$5)`,
    [req.auth.role, req.auth.id, receiver_id, message, new Date().toISOString()]
  );
  res.json({ ok: true });
});

app.get('/api/messages/:otherId', auth(), async (req, res) => {
  const me = req.auth.id;
  const other = parseInt(req.params.otherId);
  const result = await pool.query(
    `SELECT * FROM messages 
     WHERE (sender_id=$1 AND receiver_id=$2) OR (sender_id=$3 AND receiver_id=$4)
     ORDER BY id ASC`,
    [me, other, other, me]
  );
  res.json(result.rows);
});

// ============ الجلسات ============
app.post('/api/sessions', auth(['specialist']), async (req, res) => {
  const { patient_id, patient_name, session_date, session_time, meet_link } = req.body;
  await pool.query(
    `INSERT INTO sessions (patient_id,patient_name,specialist_id,specialist_name,session_date,session_time,meet_link,status,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [patient_id, patient_name, req.auth.id, req.auth.name, session_date, session_time, meet_link, 'scheduled', new Date().toISOString()]
  );
  res.json({ ok: true });
});

app.get('/api/sessions/my', auth(['patient']), async (req, res) => {
  const result = await pool.query('SELECT * FROM sessions WHERE patient_id=$1', [req.auth.id]);
  res.json(result.rows);
});

app.get('/api/sessions/specialist', auth(['specialist']), async (req, res) => {
  const result = await pool.query('SELECT * FROM sessions WHERE specialist_id=$1', [req.auth.id]);
  res.json(result.rows);
});

// ============ التقييمات ============
app.post('/api/ratings', auth(['patient']), async (req, res) => {
  const { specialist_id, specialist_name, score, comment } = req.body;
  await pool.query(
    `INSERT INTO ratings (patient_id,specialist_id,specialist_name,score,comment,created_at)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [req.auth.id, specialist_id, specialist_name, score, comment, new Date().toISOString()]
  );
  res.json({ ok: true });
});

app.get('/api/ratings/avg/:specId', async (req, res) => {
  const result = await pool.query('SELECT AVG(score) a, COUNT(*) c FROM ratings WHERE specialist_id=$1', [req.params.specId]);
  res.json({ avg: result.rows[0].a || 0, count: parseInt(result.rows[0].c) });
});

app.get('/api/my-ratings', auth(['patient']), async (req, res) => {
  const result = await pool.query('SELECT * FROM ratings WHERE patient_id=$1', [req.auth.id]);
  res.json(result.rows);
});

// ============ المرضى ============
app.get('/api/patients', auth(['specialist']), async (req, res) => {
  const result = await pool.query('SELECT id,name,email,phone,age,gender FROM users');
  res.json(result.rows);
});

// ============ نتائج الاختبارات ============
app.post('/api/test-results', auth(), async (req, res) => {
  const { test_id, test_name, patient_id, patient_name, total_score, max_score, level, details } = req.body;
  const spec_id = req.auth.role === 'specialist' ? req.auth.id : null;
  const pat_id = req.auth.role === 'patient' ? req.auth.id : patient_id;
  const pat_name = req.auth.role === 'patient' ? req.auth.name : patient_name;
  
  await pool.query(
    `INSERT INTO test_results (test_id,test_name,patient_id,patient_name,specialist_id,total_score,max_score,level,details,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [test_id, test_name, pat_id, pat_name, spec_id, total_score, max_score, level, JSON.stringify(details || []), new Date().toISOString()]
  );
  res.json({ ok: true });
});

app.get('/api/test-results/my', auth(['patient']), async (req, res) => {
  const result = await pool.query('SELECT * FROM test_results WHERE patient_id=$1 ORDER BY id DESC', [req.auth.id]);
  res.json(result.rows);
});

app.get('/api/test-results/all', auth(['specialist']), async (req, res) => {
  const result = await pool.query('SELECT * FROM test_results ORDER BY id DESC');
  res.json(result.rows);
});

// ============ الصفحة الرئيسية ============
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Almal Backend API (PostgreSQL) is running ✅' });
});

// ============ التشغيل ============
const PORT = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('❌ Failed to start server:', err.message);
  process.exit(1);
});