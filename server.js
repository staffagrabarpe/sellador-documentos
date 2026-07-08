require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const Database = require('better-sqlite3');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const { customAlphabet } = require('nanoid');

const app = express();
const PORT = process.env.PORT || 3000;
// BASE_URL debe ser la URL publica final (ej: https://sellos.tudominio.com)
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DOCS_DIR = path.join(DATA_DIR, 'documents');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(DOCS_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'db.sqlite'));
db.exec(`
CREATE TABLE IF NOT EXISTS documents (
  code TEXT PRIMARY KEY,
  original_name TEXT,
  password_hash TEXT,
  doc_hash TEXT,
  created_at TEXT
)`);

const upload = multer({
  dest: UPLOADS_DIR,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'application/pdf') {
      return cb(new Error('Solo se permiten archivos PDF'));
    }
    cb(null, true);
  }
});

const genCode = customAlphabet('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 8);
const genPassword = customAlphabet('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789', 10);

app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'cambia-este-secreto-en-produccion',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 10 * 60 * 1000, sameSite: 'lax' } // 10 minutos
}));
app.use(express.urlencoded({ extended: true }));

// Limita intentos de contrasena para evitar fuerza bruta
const validarLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiados intentos, intenta de nuevo en unos minutos.'
});

function layout(title, body) {
  return `<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#1a1a1a;background:#fafafa}
  h1{font-size:1.4rem}
  input[type=file], input[type=password], input[type=text]{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:6px;font-size:1rem}
  button{background:#111;color:#fff;border:none;padding:10px 18px;border-radius:6px;cursor:pointer;font-size:1rem}
  button:hover{background:#333}
  .card{border:1px solid #ddd;border-radius:10px;padding:20px;margin-top:16px;background:#fff}
  .ok{color:#0a7d2e}
  .err{color:#b00020}
  .mono{font-family:monospace;background:#f4f4f4;padding:4px 8px;border-radius:6px;display:inline-block}
  iframe{width:100%;height:80vh;border:1px solid #ddd;border-radius:8px;margin-top:12px}
  a{color:#0645ad}
</style>
</head><body>${body}</body></html>`;
}

app.get('/', (req, res) => {
  res.send(layout('Sellar documento', `
    <h1>📄 Sellar y validar documentos</h1>
    <p>Sube un PDF. El sistema generará un código único, una contraseña y estampará un sello con QR de verificación.</p>
    <form action="/upload" method="post" enctype="multipart/form-data" class="card">
      <input type="file" name="file" accept="application/pdf" required>
      <button type="submit">Sellar documento</button>
    </form>
  `));
});

app.post('/upload', (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      return res.status(400).send(layout('Error', `<h1 class="err">❌ ${err.message}</h1><p><a href="/">Volver</a></p>`));
    }
    try {
      if (!req.file) return res.status(400).send('No se subió ningún archivo');

      const code = genCode();
      const password = genPassword();
      const passwordHash = bcrypt.hashSync(password, 10);

      const originalBuffer = fs.readFileSync(req.file.path);
      const docHash = crypto.createHash('sha256').update(originalBuffer).digest('hex');

      const verifyUrl = `${BASE_URL}/validar/${code}`;
      const qrBuffer = await QRCode.toBuffer(verifyUrl, { margin: 1, width: 300 });

      const pdfDoc = await PDFDocument.load(originalBuffer);
      const qrImage = await pdfDoc.embedPng(qrBuffer);
      const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
      const pages = pdfDoc.getPages();
      const lastPage = pages[pages.length - 1];
      const { width } = lastPage.getSize();

      const qrSize = 70;
      const margin = 20;
      lastPage.drawImage(qrImage, {
        x: width - qrSize - margin,
        y: margin,
        width: qrSize,
        height: qrSize
      });
      lastPage.drawText(`Codigo: ${code}`, {
        x: width - qrSize - margin,
        y: margin - 12,
        size: 8,
        font,
        color: rgb(0.2, 0.2, 0.2)
      });
      lastPage.drawText(`Verificar en: ${verifyUrl}`, {
        x: margin,
        y: margin,
        size: 7,
        font,
        color: rgb(0.4, 0.4, 0.4)
      });

      const sealedBytes = await pdfDoc.save();
      fs.writeFileSync(path.join(DOCS_DIR, `${code}.pdf`), sealedBytes);
      fs.unlinkSync(req.file.path);

      db.prepare(`INSERT INTO documents (code, original_name, password_hash, doc_hash, created_at) VALUES (?, ?, ?, ?, ?)`)
        .run(code, req.file.originalname, passwordHash, docHash, new Date().toISOString());

      res.send(layout('Documento sellado', `
        <h1 class="ok">✅ Documento sellado correctamente</h1>
        <div class="card">
          <p><b>Código:</b> <span class="mono">${code}</span></p>
          <p><b>Contraseña:</b> <span class="mono">${password}</span></p>
          <p style="color:#b00020"><b>⚠️ Guarda esta contraseña ahora, no se volverá a mostrar en el sistema.</b></p>
          <p><a href="/documento-sellado/${code}" download>⬇️ Descargar documento sellado (con QR)</a></p>
          <p><a href="${verifyUrl}">🔗 Enlace de verificación: ${verifyUrl}</a></p>
        </div>
        <p><a href="/">Sellar otro documento</a></p>
      `));
    } catch (e) {
      console.error(e);
      res.status(500).send('Error al procesar el documento: ' + e.message);
    }
  });
});

app.get('/documento-sellado/:code', (req, res) => {
  const file = path.join(DOCS_DIR, `${req.params.code}.pdf`);
  if (!fs.existsSync(file)) return res.status(404).send('No encontrado');
  res.download(file, `documento-sellado-${req.params.code}.pdf`);
});

app.get('/validar/:code', (req, res) => {
  const { code } = req.params;
  const row = db.prepare('SELECT * FROM documents WHERE code = ?').get(code);
  if (!row) {
    return res.send(layout('No encontrado', `<h1 class="err">❌ Código no encontrado</h1><p><a href="/">Volver</a></p>`));
  }
  res.send(layout('Validar documento', `
    <h1>🔐 Validar documento</h1>
    <p>Código: <span class="mono">${code}</span></p>
    <form action="/validar/${code}" method="post" class="card">
      <input type="password" name="password" placeholder="Contraseña" required autofocus>
      <button type="submit">Ver documento auténtico</button>
    </form>
  `));
});

app.post('/validar/:code', validarLimiter, (req, res) => {
  const { code } = req.params;
  const { password } = req.body;
  const row = db.prepare('SELECT * FROM documents WHERE code = ?').get(code);
  if (!row || !bcrypt.compareSync(password || '', row.password_hash)) {
    return res.send(layout('Contraseña incorrecta', `
      <h1 class="err">❌ Contraseña incorrecta</h1>
      <p><a href="/validar/${code}">Intentar de nuevo</a></p>
    `));
  }
  req.session.authorized = req.session.authorized || {};
  req.session.authorized[code] = true;

  res.send(layout('Documento válido', `
    <h1 class="ok">✅ Documento auténtico verificado</h1>
    <p>Código: <span class="mono">${code}</span> — Sellado el: ${new Date(row.created_at).toLocaleString('es-PE')}</p>
    <iframe src="/ver/${code}"></iframe>
  `));
});

app.get('/ver/:code', (req, res) => {
  const { code } = req.params;
  if (!req.session.authorized || !req.session.authorized[code]) {
    return res.status(403).send('No autorizado. Valida primero con la contraseña.');
  }
  const file = path.join(DOCS_DIR, `${code}.pdf`);
  if (!fs.existsSync(file)) return res.status(404).send('No encontrado');
  res.setHeader('Content-Disposition', 'inline');
  res.sendFile(file);
});

app.listen(PORT, () => console.log(`Servidor escuchando en el puerto ${PORT}`));
