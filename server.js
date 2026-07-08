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
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const DISPLAY_DOMAIN = BASE_URL.replace(/^https?:\/\//, '').replace(/\/$/, '');

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
  password_plain TEXT,
  doc_hash TEXT,
  seal_position TEXT,
  seal_size TEXT,
  created_at TEXT
)`);
try { db.exec(`ALTER TABLE documents ADD COLUMN seal_position TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE documents ADD COLUMN seal_size TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE documents ADD COLUMN password_plain TEXT`); } catch (e) {}
// Nota: password_plain se guarda solo para poder estampar la contrasena visible en el propio
// documento sellado (es la unica forma de que quede impresa). password_hash sigue siendo lo
// que se usa para validar el login en /validar.

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
  cookie: { maxAge: 10 * 60 * 1000, sameSite: 'lax' }
}));
app.use(express.urlencoded({ extended: true }));

const validarLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiados intentos, intenta de nuevo en unos minutos.'
});

// ---- Configuracion de tamanos del sello (QR + bloque de texto a la derecha) ----
const SIZE_CONFIG = {
  small:  { qr: 45, textWidth: 130, font: 6 },
  medium: { qr: 65, textWidth: 165, font: 7 },
  large:  { qr: 90, textWidth: 200, font: 8 }
};
const GAP_PT = 8;
const MARGIN_PT = 20;

function computeBoxPosition(positionCode, pageWidth, pageHeight, blockWidth, blockHeight, marginPt) {
  const w = blockWidth, h = blockHeight, m = marginPt;
  const positions = {
    'top-left':       { x: m,                      y: pageHeight - m - h },
    'top-center':     { x: (pageWidth - w) / 2,     y: pageHeight - m - h },
    'top-right':      { x: pageWidth - m - w,       y: pageHeight - m - h },
    'middle-left':    { x: m,                       y: (pageHeight - h) / 2 },
    'middle-center':  { x: (pageWidth - w) / 2,      y: (pageHeight - h) / 2 },
    'middle-right':   { x: pageWidth - m - w,        y: (pageHeight - h) / 2 },
    'bottom-left':    { x: m,                        y: m },
    'bottom-center':  { x: (pageWidth - w) / 2,       y: m },
    'bottom-right':   { x: pageWidth - m - w,         y: m }
  };
  return positions[positionCode] || positions['bottom-right'];
}

function wrapText(text, font, fontSize, maxWidth) {
  const words = text.split(' ');
  const lines = [];
  let current = '';
  for (const w of words) {
    const test = current ? current + ' ' + w : w;
    if (font.widthOfTextAtSize(test, fontSize) > maxWidth && current) {
      lines.push(current);
      current = w;
    } else {
      current = test;
    }
  }
  if (current) lines.push(current);
  return lines;
}

// ---- Plantilla base ----
function layout(title, body, wide) {
  return `<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  :root{
    --primary:#4f46e5; --primary-dark:#3730a3; --bg:#f4f5fb; --card:#ffffff;
    --ok:#0a7d2e; --err:#c0272d; --text:#1f2430; --muted:#6b7280; --border:#e4e6ef;
  }
  *{box-sizing:border-box}
  body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);color:var(--text)}
  .wrap{max-width:${wide ? '900px' : '620px'};margin:0 auto;padding:32px 18px 60px}
  header.brand{display:flex;align-items:center;gap:10px;padding:18px 0 8px}
  header.brand .logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--primary),var(--primary-dark));display:flex;align-items:center;justify-content:center;font-size:20px}
  header.brand span{font-weight:700;font-size:1.15rem;letter-spacing:-0.02em}
  h1{font-size:1.5rem;margin:18px 0 6px;letter-spacing:-0.02em}
  p.lead{color:var(--muted);margin-top:0}
  .card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px;margin-top:18px;box-shadow:0 1px 3px rgba(20,20,50,.04)}
  input[type=file], input[type=password], input[type=text]{
    width:100%;padding:11px 12px;margin:6px 0 14px;border:1px solid var(--border);
    border-radius:8px;font-size:.98rem;background:#fbfbfe
  }
  input[type=password]:focus, input[type=text]:focus{outline:2px solid var(--primary);border-color:var(--primary)}
  button, .btn{
    background:var(--primary);color:#fff;border:none;padding:11px 20px;border-radius:9px;
    cursor:pointer;font-size:.98rem;font-weight:600;transition:.15s;display:inline-block;text-decoration:none
  }
  button:hover, .btn:hover{background:var(--primary-dark)}
  .btn.secondary{background:#fff;color:var(--primary);border:1px solid var(--primary)}
  .ok{color:var(--ok)}
  .err{color:var(--err)}
  .mono{font-family:'SFMono-Regular',Consolas,monospace;background:#f1f1f8;padding:5px 10px;border-radius:6px;display:inline-block;font-size:.95rem;letter-spacing:.03em}
  iframe{width:100%;height:75vh;border:1px solid var(--border);border-radius:10px;margin-top:14px}
  a{color:var(--primary)}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .muted{color:var(--muted);font-size:.9rem}
  .badge{display:inline-block;background:#eef0fd;color:var(--primary-dark);border-radius:20px;padding:3px 12px;font-size:.8rem;font-weight:600}
  footer{margin-top:36px;text-align:center;color:var(--muted);font-size:.82rem}
  .seal-config{display:flex;gap:24px;flex-wrap:wrap;margin-top:6px}
  .preview-box{flex:1;min-width:260px}
  #pdf-canvas-wrap{position:relative;border:1px solid var(--border);border-radius:10px;overflow:hidden;background:#fff;display:none}
  #pdf-canvas{display:block}
  #seal-overlay{
    position:absolute;border:2px dashed var(--primary);background:rgba(79,70,229,.12);
    border-radius:4px;display:none;align-items:center;justify-content:center;font-size:9px;color:var(--primary-dark);pointer-events:none;text-align:center;line-height:1.1
  }
  .controls{flex:1;min-width:240px}
  .grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;max-width:220px}
  .grid3 label{border:1px solid var(--border);border-radius:8px;aspect-ratio:1;display:flex;align-items:center;justify-content:center;cursor:pointer;background:#fbfbfe;font-size:18px;user-select:none}
  .grid3 input{display:none}
  .grid3 input:checked + label{background:var(--primary);border-color:var(--primary);color:#fff}
  .sizes{display:flex;gap:8px;margin-top:12px}
  .sizes label{border:1px solid var(--border);border-radius:20px;padding:6px 16px;cursor:pointer;font-size:.9rem;background:#fbfbfe}
  .sizes input{display:none}
  .sizes input:checked + label{background:var(--primary);color:#fff;border-color:var(--primary)}
  label.field-label{font-weight:600;font-size:.85rem;color:var(--muted);display:block;margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}
</style>
</head><body><div class="wrap">
<header class="brand"><div class="logo">🔏</div><span>SelloDoc</span></header>
${body}
<footer>Sellado y verificación de documentos</footer>
</div></body></html>`;
}

// ---------- Pagina principal ----------
app.get('/', (req, res) => {
  res.send(layout('Sellar documento', `
    <h1>📄 Sellar un documento</h1>
    <p class="lead">Sube un PDF, elige dónde y de qué tamaño va el sello, y previsualízalo antes de generarlo.</p>
    <form action="/upload" method="post" enctype="multipart/form-data" class="card" id="sealForm">
      <label class="field-label">Archivo PDF</label>
      <input type="file" name="file" id="fileInput" accept="application/pdf" required>

      <div class="seal-config">
        <div class="preview-box">
          <label class="field-label">Previsualización (primera página)</label>
          <div id="pdf-canvas-wrap">
            <canvas id="pdf-canvas"></canvas>
            <div id="seal-overlay">QR + código<br>+ clave</div>
          </div>
          <p class="muted" id="preview-hint">Selecciona un archivo para ver la previsualización.</p>
        </div>
        <div class="controls">
          <label class="field-label">Posición del sello</label>
          <div class="grid3">
            <input type="radio" name="sealPositionRadio" id="p-tl" value="top-left"><label for="p-tl">↖</label>
            <input type="radio" name="sealPositionRadio" id="p-tc" value="top-center"><label for="p-tc">↑</label>
            <input type="radio" name="sealPositionRadio" id="p-tr" value="top-right"><label for="p-tr">↗</label>
            <input type="radio" name="sealPositionRadio" id="p-ml" value="middle-left"><label for="p-ml">←</label>
            <input type="radio" name="sealPositionRadio" id="p-mc" value="middle-center"><label for="p-mc">•</label>
            <input type="radio" name="sealPositionRadio" id="p-mr" value="middle-right"><label for="p-mr">→</label>
            <input type="radio" name="sealPositionRadio" id="p-bl" value="bottom-left"><label for="p-bl">↙</label>
            <input type="radio" name="sealPositionRadio" id="p-bc" value="bottom-center"><label for="p-bc">↓</label>
            <input type="radio" name="sealPositionRadio" id="p-br" value="bottom-right" checked><label for="p-br">↘</label>
          </div>

          <label class="field-label" style="margin-top:18px">Tamaño del sello</label>
          <div class="sizes">
            <input type="radio" name="sealSizeRadio" id="s-s" value="small"><label for="s-s">Pequeño</label>
            <input type="radio" name="sealSizeRadio" id="s-m" value="medium" checked><label for="s-m">Mediano</label>
            <input type="radio" name="sealSizeRadio" id="s-l" value="large"><label for="s-l">Grande</label>
          </div>

          <p class="muted" style="margin-top:14px">El sello lleva el QR a la izquierda y, a la derecha, el enlace de verificación, el código y la contraseña. Se coloca en <b>todas las páginas</b>.</p>
        </div>
      </div>

      <input type="hidden" name="sealPosition" id="sealPosition" value="bottom-right">
      <input type="hidden" name="sealSize" id="sealSize" value="medium">

      <div style="margin-top:20px"><button type="submit">Sellar documento</button></div>
    </form>

    <script src="https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js"></script>
    <script>
      pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';

      const SIZE_CONFIG = {
        small:  { qr: 45, textWidth: 130 },
        medium: { qr: 65, textWidth: 165 },
        large:  { qr: 90, textWidth: 200 }
      };
      const GAP_PT = 8;
      const MARGIN_PT = 20;

      function computeBoxPosition(positionCode, pageWidth, pageHeight, blockWidth, blockHeight, marginPt) {
        const w = blockWidth, h = blockHeight, m = marginPt;
        const positions = {
          'top-left':       { x: m,                     y: pageHeight - m - h },
          'top-center':     { x: (pageWidth - w) / 2,    y: pageHeight - m - h },
          'top-right':      { x: pageWidth - m - w,      y: pageHeight - m - h },
          'middle-left':    { x: m,                      y: (pageHeight - h) / 2 },
          'middle-center':  { x: (pageWidth - w) / 2,     y: (pageHeight - h) / 2 },
          'middle-right':   { x: pageWidth - m - w,       y: (pageHeight - h) / 2 },
          'bottom-left':    { x: m,                       y: m },
          'bottom-center':  { x: (pageWidth - w) / 2,      y: m },
          'bottom-right':   { x: pageWidth - m - w,        y: m }
        };
        return positions[positionCode] || positions['bottom-right'];
      }

      let currentPageSize = null;
      const canvas = document.getElementById('pdf-canvas');
      const wrap = document.getElementById('pdf-canvas-wrap');
      const overlay = document.getElementById('seal-overlay');
      const hint = document.getElementById('preview-hint');

      function getSelectedPosition() {
        const el = document.querySelector('input[name="sealPositionRadio"]:checked');
        return el ? el.value : 'bottom-right';
      }
      function getSelectedSize() {
        const el = document.querySelector('input[name="sealSizeRadio"]:checked');
        return el ? el.value : 'medium';
      }

      function updateOverlay() {
        if (!currentPageSize) return;
        const position = getSelectedPosition();
        const size = getSelectedSize();
        document.getElementById('sealPosition').value = position;
        document.getElementById('sealSize').value = size;

        const cfg = SIZE_CONFIG[size];
        const blockWidth = cfg.qr + GAP_PT + cfg.textWidth;
        const blockHeight = cfg.qr;

        const scale = canvas.width / currentPageSize.width;
        const box = computeBoxPosition(position, currentPageSize.width, currentPageSize.height, blockWidth, blockHeight, MARGIN_PT);

        const leftPx = box.x * scale;
        const topPx = (currentPageSize.height - box.y - blockHeight) * scale;
        const widthPx = blockWidth * scale;
        const heightPx = blockHeight * scale;

        overlay.style.left = leftPx + 'px';
        overlay.style.top = topPx + 'px';
        overlay.style.width = widthPx + 'px';
        overlay.style.height = heightPx + 'px';
        overlay.style.display = 'flex';
      }

      document.querySelectorAll('input[name="sealPositionRadio"], input[name="sealSizeRadio"]').forEach(el => {
        el.addEventListener('change', updateOverlay);
      });

      document.getElementById('fileInput').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        hint.textContent = 'Cargando previsualización...';
        try {
          const buf = await file.arrayBuffer();
          const pdf = await pdfjsLib.getDocument({ data: buf }).promise;
          const page = await pdf.getPage(1);
          const viewport = page.getViewport({ scale: 1 });
          currentPageSize = { width: viewport.width, height: viewport.height };

          // Ancho disponible real del contenedor (evita distorsion en paginas horizontales)
          const availableWidth = document.querySelector('.preview-box').clientWidth || 480;
          const displayScale = Math.min(availableWidth / viewport.width, 1.5);
          const scaledViewport = page.getViewport({ scale: displayScale });

          canvas.width = Math.round(scaledViewport.width);
          canvas.height = Math.round(scaledViewport.height);
          const ctx = canvas.getContext('2d');
          await page.render({ canvasContext: ctx, viewport: scaledViewport }).promise;

          wrap.style.display = 'block';
          hint.textContent = 'Así se verá aproximadamente el sello (el contenido real del QR y los textos se generan al enviar el formulario).';
          updateOverlay();
        } catch (err) {
          console.error(err);
          hint.textContent = 'No se pudo generar la previsualización, pero igual puedes sellar el documento.';
        }
      });
    </script>
  `, true));
});

// ---------- Procesar subida y sellar TODAS las paginas ----------
app.post('/upload', (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      return res.status(400).send(layout('Error', `<h1 class="err">❌ ${err.message}</h1><p><a href="/">Volver</a></p>`));
    }
    try {
      if (!req.file) return res.status(400).send('No se subió ningún archivo');

      const sealPosition = req.body.sealPosition || 'bottom-right';
      const sealSize = SIZE_CONFIG[req.body.sealSize] ? req.body.sealSize : 'medium';
      const cfg = SIZE_CONFIG[sealSize];

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
      const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
      const pages = pdfDoc.getPages();

      // Texto del sello (a la derecha del QR)
      const lines1 = wrapText('Puede verificar la copia auténtica de este documento en:', font, cfg.font, cfg.textWidth);
      const lines2 = wrapText(DISPLAY_DOMAIN, fontBold, cfg.font, cfg.textWidth);
      const lines3 = wrapText(`Use la clave ${password} y el código ${code}, por favor.`, font, cfg.font, cfg.textWidth);

      const lineGap = cfg.font * 1.35;
      const allLines = [
        ...lines1.map(t => ({ text: t, bold: false })),
        ...lines2.map(t => ({ text: t, bold: true })),
        ...lines3.map(t => ({ text: t, bold: false }))
      ];
      const totalTextHeight = allLines.length * lineGap;
      const blockHeight = Math.max(cfg.qr, totalTextHeight + 4);
      const blockWidth = cfg.qr + GAP_PT + cfg.textWidth;

      for (const page of pages) {
        const { width, height } = page.getSize();
        const box = computeBoxPosition(sealPosition, width, height, blockWidth, blockHeight, MARGIN_PT);

        const qrY = box.y + (blockHeight - cfg.qr) / 2;
        page.drawImage(qrImage, { x: box.x, y: qrY, width: cfg.qr, height: cfg.qr });

        let textY = box.y + (blockHeight - totalTextHeight) / 2 + totalTextHeight - cfg.font;
        const textX = box.x + cfg.qr + GAP_PT;
        for (const line of allLines) {
          page.drawText(line.text, {
            x: textX,
            y: textY,
            size: cfg.font,
            font: line.bold ? fontBold : font,
            color: rgb(0.15, 0.15, 0.15)
          });
          textY -= lineGap;
        }
      }

      const sealedBytes = await pdfDoc.save();
      fs.writeFileSync(path.join(DOCS_DIR, `${code}.pdf`), sealedBytes);
      fs.unlinkSync(req.file.path);

      db.prepare(`INSERT INTO documents (code, original_name, password_hash, password_plain, doc_hash, seal_position, seal_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(code, req.file.originalname, passwordHash, password, docHash, sealPosition, sealSize, new Date().toISOString());

      res.send(layout('Documento sellado', `
        <h1 class="ok">✅ Documento sellado correctamente</h1>
        <div class="card">
          <p><span class="badge">Código</span> <span class="mono">${code}</span></p>
          <p><span class="badge">Contraseña</span> <span class="mono">${password}</span></p>
          <p class="muted">Ambos ya quedaron impresos junto al QR en todas las páginas del documento.</p>
          <div class="row" style="margin-top:16px">
            <a class="btn" href="/documento-sellado/${code}" download>⬇️ Descargar PDF sellado</a>
            <a class="btn secondary" href="${verifyUrl}">🔗 Ver enlace de verificación</a>
          </div>
        </div>
        <p style="margin-top:18px"><a href="/">← Sellar otro documento</a></p>
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

// ---------- Validacion: codigo editable, precargado si viene por QR ----------
function renderValidateForm(codePrefill, errorMsg) {
  return layout('Validar documento', `
    <h1>🔐 Validar documento</h1>
    <p class="lead">Ingresa el código y la contraseña que aparecen junto al QR del documento.</p>
    ${errorMsg ? `<p class="err">❌ ${errorMsg}</p>` : ''}
    <form action="/validar" method="post" class="card">
      <label class="field-label">Código</label>
      <input type="text" name="code" placeholder="Código" value="${codePrefill ? codePrefill.replace(/"/g,'') : ''}" required autocomplete="off" style="text-transform:uppercase">
      <label class="field-label">Contraseña</label>
      <input type="password" name="password" placeholder="Contraseña" required>
      <button type="submit">Ver documento auténtico</button>
    </form>
  `);
}

app.get('/validar', (req, res) => {
  res.send(renderValidateForm(''));
});

app.get('/validar/:code', (req, res) => {
  res.send(renderValidateForm(req.params.code));
});

app.post('/validar', validarLimiter, (req, res) => {
  const code = (req.body.code || '').trim().toUpperCase();
  const { password } = req.body;
  const row = db.prepare('SELECT * FROM documents WHERE code = ?').get(code);
  if (!row || !bcrypt.compareSync(password || '', row.password_hash)) {
    return res.send(renderValidateForm(code, 'Código o contraseña incorrectos.'));
  }
  req.session.authorized = req.session.authorized || {};
  req.session.authorized[code] = true;

  res.send(layout('Documento válido', `
    <h1 class="ok">✅ Documento auténtico verificado</h1>
    <p class="muted">Código: <span class="mono">${code}</span> — Sellado el ${new Date(row.created_at).toLocaleString('es-PE')}</p>
    <iframe src="/ver/${code}"></iframe>
  `, true));
});

app.get('/ver/:code', (req, res) => {
  const { code } = req.params;
  if (!req.session.authorized || !req.session.authorized[code]) {
    return res.status(403).send('No autorizado. Valida primero con el código y la contraseña.');
  }
  const file = path.join(DOCS_DIR, `${code}.pdf`);
  if (!fs.existsSync(file)) return res.status(404).send('No encontrado');
  res.setHeader('Content-Disposition', 'inline');
  res.sendFile(file);
});

app.listen(PORT, () => console.log(`Servidor escuchando en el puerto ${PORT}`));
