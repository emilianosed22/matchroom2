import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import http from "http";
import { Server } from "socket.io";
import { initDb, run, get, all } from "./db.js";
import multer from "multer";
import path from "path";
import fs from "fs";

const app = express();
initDb();

/* ================== CONFIG ================== */
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
// 🔥 en Render pon: PUBLIC_URL = https://matchroom.onrender.com
const PUBLIC_URL = process.env.PUBLIC_URL || null;

// ✅ CORS: pon aquí tu GitHub Pages (o deja * mientras pruebas)
const ALLOWED_ORIGINS = [
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  // 👉 cámbialo por tu github pages real:
  // "https://TUUSUARIO.github.io",
  // "https://TUUSUARIO.github.io/TUREPO",
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // postman / curl
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, true); // ✅ deja true si quieres que funcione sin pelearte (modo demo)
    // return cb(new Error("Not allowed by CORS"), false);
  },
  credentials: true
}));

app.use(express.json());

/* ================== UPLOADS (AVATAR) ================== */
const ROOT_DIR = path.resolve();
const UPLOAD_DIR = path.join(ROOT_DIR, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// sirve fotos: https://TU_BACKEND/uploads/archivo.jpg
app.use("/uploads", express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safeExt = ext || ".jpg";
    cb(null, `avatar_${req.user?.id || "x"}_${Date.now()}${safeExt}`);
  }
});

function fileFilter(req, file, cb) {
  if (!file.mimetype?.startsWith("image/")) return cb(new Error("Solo imágenes"));
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 3 * 1024 * 1024 } // 3MB
});

/* ================== AUTH MIDDLEWARE ================== */
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, email }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* ================== AUTH ================== */
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email y password requeridos" });

  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await run("INSERT INTO users(email, password_hash) VALUES(?,?)", [email, hash]);
    await run("INSERT INTO profiles(user_id, verificado) VALUES(?,0)", [r.lastID]);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Email ya existe" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email y password requeridos" });

  const user = await get("SELECT * FROM users WHERE email = ?", [email]);
  if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Credenciales inválidas" });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

/* ================== PROFILE ================== */
app.get("/api/profile/me", auth, async (req, res) => {
  const p = await get("SELECT * FROM profiles WHERE user_id = ?", [req.user.id]);
  res.json(p || {});
});

app.put("/api/profile/me", auth, async (req, res) => {
  const { nombre, pais, ciudad, uni, presupuesto, estilo, hobbies, descripcion, verificado } = req.body || {};

  await run(
    `UPDATE profiles SET
      nombre=?, pais=?, ciudad=?, uni=?,
      presupuesto=?, estilo=?, hobbies=?, descripcion=?,
      verificado=?, updated_at=datetime('now')
     WHERE user_id=?`,
    [
      nombre || null,
      pais || null,
      ciudad || null,
      uni || null,
      presupuesto ? Number(presupuesto) : null,
      estilo || null,
      hobbies || null,
      descripcion || null,
      verificado ? 1 : 0,
      req.user.id
    ]
  );

  res.json({ ok: true });
});

// ✅ subir avatar (Render + localhost)
app.post("/api/profile/avatar", auth, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Falta archivo avatar" });

    const baseUrl = PUBLIC_URL || `${req.protocol}://${req.get("host")}`;
    const avatarUrl = `${baseUrl}/uploads/${req.file.filename}`;

    await run(
      "UPDATE profiles SET avatar_url=?, updated_at=datetime('now') WHERE user_id=?",
      [avatarUrl, req.user.id]
    );

    res.json({ ok: true, avatar_url: avatarUrl });
  } catch (e) {
    res.status(400).json({ error: e?.message || "Error subiendo avatar" });
  }
});

/* ================== ROOMIES ================== */
function compatScore(me, other) {
  let score = 50;
  if (me?.estilo && other?.estilo && me.estilo === other.estilo) score += 25;
  if (me?.presupuesto && other?.presupuesto) {
    const diff = Math.abs(me.presupuesto - other.presupuesto);
    score += Math.max(0, 25 - Math.round(diff / 20));
  }
  return Math.min(100, Math.max(0, score));
}

app.get("/api/roomies", auth, async (req, res) => {
  const { city, maxBudget, style } = req.query;

  const me = await get("SELECT * FROM profiles WHERE user_id = ?", [req.user.id]);

  let sql = `SELECT p.* FROM profiles p WHERE p.user_id != ?`;
  const params = [req.user.id];

  if (city) { sql += " AND p.ciudad = ?"; params.push(city); }
  if (style) { sql += " AND p.estilo = ?"; params.push(style); }
  if (maxBudget) { sql += " AND p.presupuesto <= ?"; params.push(Number(maxBudget)); }

  const rows = await all(sql, params);

  res.json(rows.map(r => ({
    user_id: r.user_id,
    nombre: r.nombre,
    ciudad: r.ciudad,
    uni: r.uni,
    presupuesto: r.presupuesto,
    estilo: r.estilo,
    hobbies: r.hobbies,
    descripcion: r.descripcion,
    avatar_url: r.avatar_url, // ✅
    verificado: !!r.verificado,
    compat: compatScore(me, r)
  })));
});

/* ================== FAVORITES ================== */
app.get("/api/favorites", auth, async (req, res) => {
  const rows = await all("SELECT favorite_user_id FROM favorites WHERE user_id=?", [req.user.id]);
  res.json(rows.map(r => r.favorite_user_id));
});

app.post("/api/favorites/:targetId", auth, async (req, res) => {
  const targetId = Number(req.params.targetId);
  await run("INSERT OR IGNORE INTO favorites(user_id,favorite_user_id) VALUES(?,?)", [req.user.id, targetId]);
  res.json({ ok: true });
});

app.delete("/api/favorites/:targetId", auth, async (req, res) => {
  const targetId = Number(req.params.targetId);
  await run("DELETE FROM favorites WHERE user_id=? AND favorite_user_id=?", [req.user.id, targetId]);
  res.json({ ok: true });
});

/* ================== REVIEWS ================== */
app.get("/api/reviews/:targetId", auth, async (req, res) => {
  const targetId = Number(req.params.targetId);

  const rows = await all(
    `SELECT r.id, r.rating, r.comment, r.created_at, p.nombre as author_name
     FROM reviews r
     JOIN profiles p ON p.user_id = r.author_id
     WHERE r.target_user_id = ?
     ORDER BY r.created_at DESC`,
    [targetId]
  );

  res.json(rows);
});

app.post("/api/reviews/:targetId", auth, async (req, res) => {
  const targetId = Number(req.params.targetId);
  const { rating, comment } = req.body || {};
  if (!rating || !comment) return res.status(400).json({ error: "rating y comment requeridos" });

  await run(
    "INSERT INTO reviews(author_id, target_user_id, rating, comment) VALUES(?,?,?,?)",
    [req.user.id, targetId, Number(rating), String(comment)]
  );

  res.json({ ok: true });
});

/* ================== SOCKET.IO (CHAT + HISTORIAL) ================== */
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload;
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});

function dmRoom(a, b) {
  return `dm:${Math.min(a, b)}:${Math.max(a, b)}`;
}

io.on("connection", (socket) => {
  const me = Number(socket.user.id);

  socket.join(`user:${me}`);

  socket.on("dm:join", async ({ otherUserId }) => {
    const other = Number(otherUserId);
    if (!other) return;

    socket.join(dmRoom(me, other));

    const a = Math.min(me, other);
    const b = Math.max(me, other);

    const rows = await all(
      `SELECT from_id as "from", to_id as "to", text, ts
       FROM messages
       WHERE a_id=? AND b_id=?
       ORDER BY ts ASC
       LIMIT 200`,
      [a, b]
    );

    socket.emit("dm:history", { otherUserId: other, rows });
  });

  socket.on("dm:send", async ({ to, text }) => {
    const other = Number(to);
    const cleanText = String(text || "").trim();
    if (!other || !cleanText) return;

    const msg = { from: me, to: other, text: cleanText, ts: Date.now() };

    const a = Math.min(me, other);
    const b = Math.max(me, other);

    await run(
      `INSERT INTO messages(a_id,b_id,from_id,to_id,text,ts)
       VALUES(?,?,?,?,?,?)`,
      [a, b, msg.from, msg.to, msg.text, msg.ts]
    );

    io.to(dmRoom(me, other)).emit("dm:message", msg);
    io.to(`user:${other}`).emit("dm:message", msg);
    io.to(`user:${me}`).emit("dm:message", msg);
  });
});

/* ================== START ================== */
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log("✅ API + Socket en " + (PUBLIC_URL || `http://localhost:${PORT}`));
  console.log("✅ Socket client: " + (PUBLIC_URL || `http://localhost:${PORT}`) + "/socket.io/socket.io.js");
});
