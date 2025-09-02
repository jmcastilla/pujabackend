// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const multer = require('multer');
const { parse } = require('csv-parse/sync');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10 MB
});

const app = express();
app.use(cors({
  origin: ['http://offertapp.co','http://146.190.75.181'],
  methods: ['GET','POST','PUT','DELETE','OPTIONS','PATCH'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true
}));
app.use(express.json());

// Pool de MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME, // manager
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  rowsAsArray: false,
  charset: 'utf8mb4',
});

// -----------------------------
// Helpers de autenticación
// -----------------------------
function signToken(user) {
  // user: { id, name, email }
  return jwt.sign(
    { id: user.id, name: user.name, email: user.email, tipo:user.tipo },
    process.env.JWT_SECRET,
    { expiresIn: '12h' }
  );
}

async function findUserByEmail(email) {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      'SELECT idusuarios, name, email, passhash, tipo FROM usuarios WHERE email = ? AND activo=1 LIMIT 1',
      [email]
    );
    return rows[0] || null;
  } finally {
    conn.release();
  }
}

async function createUser({ name, email, password, tipo, empresa }) {
  const passhash = await bcrypt.hash(password, 10);
  const conn = await pool.getConnection();
  try {
    const [res] = await conn.query(
      'INSERT INTO usuarios (name, email, passhash, tipo, empresa) VALUES (?, ?, ?, ?, ?)',
      [name, email, passhash, tipo, empresa]
    );
    return { id: res.insertId, name, email, tipo };
  } finally {
    conn.release();
  }
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization || '';
  console.log(auth);
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: 'No token' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { id, name, email }
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Token inválido' });
  }
}

// -----------------------------
// Auth endpoints (JWT)
// -----------------------------

// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, tipo, empresa } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ ok: false, error: 'Faltan campos' });
    }

    const existing = await findUserByEmail(String(email).toLowerCase());
    if (existing) return res.status(409).json({ ok: false, error: 'Email ya registrado' });

    const user = await createUser({ name, email: String(email).toLowerCase(), password, tipo, empresa });
    const token = signToken(user);
    return res.status(201).json({ ok: true, token, user });
  } catch (e) {
    console.error('[auth] register error:', e);
    return res.status(500).json({ ok: false, error: 'Error en registro' });
  }
});

// PUT /api/proveedores/:id  (solo admin tipo 1)
app.put('/api/proveedores/:id', verifyToken, async (req, res) => {
  if (!req.user || String(req.user.tipo) !== '1') {
    return res.status(403).json({ ok:false, error:'No autorizado' });
  }
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ ok:false, error:'id inválido' });

  const { name, email, empresa, password } = req.body || {};
  if (!name || !email || !empresa) return res.status(400).json({ ok:false, error:'Faltan campos' });

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // Actualiza datos básicos
    await conn.query(
      `UPDATE puja.usuarios
         SET name = ?, email = ?, empresa = ?
       WHERE idusuarios = ?`,
      [name, String(email).toLowerCase(), empresa, id]
    );

    // Opcional: resetear password si se envía
    if (password) {
      // asume que usas una función para hashear
      const hash = await hashPassword(password);
      await conn.query(
        `UPDATE puja.usuarios SET passhash = ? WHERE idusuarios = ?`,
        [hash, id]
      );
    }

    await conn.commit();
    return res.json({ ok:true });
  } catch (e) {
    try { await conn?.rollback(); } catch {}
    console.error('[api] PUT /api/proveedores/:id', e);
    return res.status(500).json({ ok:false, error: e.message || String(e) });
  } finally {
    conn?.release();
  }
});

// PATCH /api/proveedores/:id/inactivar  (solo admin tipo 1)
app.patch('/api/proveedores/:id/inactivar', verifyToken, async (req, res) => {
  if (!req.user || String(req.user.tipo) !== '1') {
    return res.status(403).json({ ok:false, error:'No autorizado' });
  }
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ ok:false, error:'id inválido' });

  let conn;
  try {
    conn = await pool.getConnection();
    const [r] = await conn.query(
      `UPDATE puja.usuarios SET activo = 0 WHERE idusuarios = ? AND activo = 1`,
      [id]
    );
    if ((r.affectedRows || 0) === 0) {
      return res.status(404).json({ ok:false, error:'No se encontró activo o ya estaba inactivo' });
    }
    return res.json({ ok:true, affected: r.affectedRows });
  } catch (e) {
    console.error('[api] PATCH /api/proveedores/:id/inactivar', e);
    return res.status(500).json({ ok:false, error: e.message || String(e) });
  } finally {
    conn?.release();
  }
});


// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Datos inválidos' });
    }

    const user = await findUserByEmail(String(email).toLowerCase());
    if (!user) return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });

    const ok = await bcrypt.compare(password, user.passhash);
    if (!ok) return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });

    const { id, name } = user;
    const token = signToken({ id: user.idusuarios, name, email: user.email, tipo: user.tipo });
    return res.json({ ok: true, token, user: { id: user.idusuarios, name, email: user.email, tipo:user.tipo } });
  } catch (e) {
    console.error('[auth] login error:', e);
    return res.status(500).json({ ok: false, error: 'Error en login' });
  }
});

// Perfil (protegida)
app.get('/api/auth/me', verifyToken, async (req, res) => {
  return res.json({ ok: true, user: req.user });
});

// -----------------------------
// Endpoints existentes (datos)
// -----------------------------

// requerimientos
app.get('/api/requerimientos', verifyToken, async (req, res) => {
  console.log(req.user);
  var selectSql="";
  if(req.user.tipo === 2){
    selectSql = `
      SELECT idrequerimientos, sku, ean, producto, cantidad, fecha, laboratorio,
      CASE
      WHEN EXISTS (
        SELECT 1
        FROM puja.ofertas
        WHERE fkrequerimientos = idrequerimientos and fkusuario=${req.user.id}
      ) THEN 'Si'
      ELSE 'No'
      END AS tiene_ofertas
      FROM requerimientos
      WHERE activo = 1
      ORDER BY producto
      LIMIT 1000000
    `;
  }else{
    selectSql = `
      SELECT idrequerimientos, sku, ean, producto, cantidad, fecha, laboratorio,
      CASE
      WHEN EXISTS (
        SELECT 1
        FROM puja.ofertas
        WHERE fkrequerimientos = idrequerimientos
      ) THEN 'Si'
      ELSE 'No'
      END AS tiene_ofertas
      FROM requerimientos
      WHERE activo = 1
      ORDER BY producto
      LIMIT 1000000
    `;
  }
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(selectSql);
      res.json({ ok: true, rows });
    } finally { conn.release(); }
  } catch (e) {
    console.error('[api] Error /api/requerimientos:', e);
    res.status(500).json({ ok:false, error:e.message || String(e) });
  }
});

app.post('/api/uploadcsv', verifyToken, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ ok: false, error: 'No se recibió archivo (campo "file").' });
  }

  let records;
  try {
    records = parse(req.file.buffer.toString('utf8'), {
      columns: true,            // usa la primera fila como cabeceras
      skip_empty_lines: true,
      trim: true
    });
  } catch (err) {
    return res.status(400).json({ ok: false, error: 'CSV invalido: ' + (err.message || String(err)) });
  }

  // Validación mínima de cabeceras
  const requiredHeaders = ['sku', 'ean', 'producto', 'laboratorio', 'cantidad', 'precio'];
  const hasAll = requiredHeaders.every(h => Object.prototype.hasOwnProperty.call(records[0] || {}, h));
  if (!hasAll) {
    return res.status(400).json({ ok: false, error: `Cabeceras requeridas: ${requiredHeaders.join(', ')}` });
  }

  // Normalizar y validar filas
  const rowsToInsert = [];
  const errors = [];
  let line = 1; // considerando que columns:true no incluye la fila de cabecera

  for (const r of records) {
    line++;

    const sku = String(r.sku || '').trim();
    const ean = String(r.ean || '').trim();
    const producto = String(r.producto || '').trim();
    const laboratorio = String(r.laboratorio || '').trim();
    const precio = String(r.precio || '').trim();

    // cantidad: entero >= 0
    const cantidadRaw = String(r.cantidad ?? '').replace(/,/g, '.').trim();
    const cantidad = Number.isFinite(Number(cantidadRaw)) ? parseInt(Number(cantidadRaw), 10) : NaN;

    if (!sku || !producto || !laboratorio || !Number.isInteger(cantidad) || cantidad < 0) {
      errors.push({ line, error: 'Datos inválidos', row: r });
      continue;
    }

    rowsToInsert.push([sku, ean, producto, laboratorio, cantidad, precio]);
  }

  if (rowsToInsert.length === 0) {
    return res.status(400).json({ ok: false, error: 'No hay filas válidas para insertar', errors });
  }

  const insertSqlBase = `
    INSERT INTO requerimientos
      (sku, ean, producto, laboratorio, cantidad, precio)
    VALUES
  `;

  // función para insertar por lotes y evitar queries gigantes
  async function bulkInsert(conn, values, chunkSize = 500) {
    let inserted = 0;
    for (let i = 0; i < values.length; i += chunkSize) {
      const chunk = values.slice(i, i + chunkSize);

      // placeholders: (?,?,?,?,?,NOW(),1) por cada fila
      const placeholders = chunk.map(() => '(?,?,?,?,?,?)').join(',');
      const flatParams = chunk.flatMap(v => [
        v[0], // sku
        v[1], // ean
        v[2], // producto
        v[3], // laboratorio
        v[4], // cantidad
        v[5], // precio
      ]);

      const sql = insertSqlBase + placeholders;
      const [result] = await conn.query(sql, flatParams);
      inserted += result.affectedRows || 0;
    }
    return inserted;
  }

  // Inserción en transacción
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    const inserted = await bulkInsert(conn, rowsToInsert, 500);

    await conn.commit();
    return res.json({ ok: true, inserted, errors });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch {}
    }
    console.error('[api] Error upload-csv:', err);
    return res.status(500).json({ ok: false, error: err.message || String(err) });
  } finally {
    if (conn) conn.release();
  }
});

// POST /api/pujas
// Body: { idrequerimientos:number, sku?:string, cantidad:number, precio:number }
app.post('/api/pujas', verifyToken, async (req, res) => {
  // Solo tipo 2 (proveedor) puede crear/actualizar pujas
  if (!req.user || String(req.user.tipo) !== '2') {
    return res.status(403).json({ ok: false, error: 'No autorizado para pujar' });
  }

  const { idrequerimientos, cantidad, precio, observaciones } = req.body || {};

  // Validaciones básicas
  const idReq = parseInt(idrequerimientos, 10);
  const qty = parseInt(cantidad, 10);
  const p = Number(precio);
  const obs = observaciones;

  if (!Number.isInteger(idReq) || idReq <= 0) {
    return res.status(400).json({ ok: false, error: 'idrequerimientos inválido' });
  }
  if (!Number.isInteger(qty) || qty <= 0) {
    return res.status(400).json({ ok: false, error: 'cantidad debe ser entero > 0' });
  }
  if (!Number.isFinite(p) || p <= 0) {
    return res.status(400).json({ ok: false, error: 'precio debe ser numérico > 0' });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // 1) Verificar que el requerimiento exista y esté activo
    const [reqRows] = await conn.query(
      `SELECT idrequerimientos, sku, producto, cantidad, activo
       FROM requerimientos
       WHERE idrequerimientos = ?`,
      [idReq]
    );

    const reqRow = reqRows?.[0];
    if (!reqRow) {
      await conn.rollback();
      return res.status(404).json({ ok: false, error: 'Requerimiento no existe' });
    }
    if (reqRow.activo !== 1) {
      await conn.rollback();
      return res.status(400).json({ ok: false, error: 'Requerimiento inactivo' });
    }

    // (Opcional) Validar que no supere requerido
    // if (qty > reqRow.cantidad) {
    //   await conn.rollback();
    //   return res.status(400).json({ ok: false, error: 'Cantidad ofertada supera el requerido' });
    // }

    // Datos del usuario proveedor
    const proveedorId = req.user.id;

    // 2) Insertar o actualizar puja del mismo proveedor para el mismo requerimiento
    const sql = `
      INSERT INTO ofertas (fkrequerimientos, fkusuario, cantidad, precio, observaciones)
      VALUES (?, ?, ?, ?, ?)
    `;
    const params = [idReq, proveedorId, qty, p, observaciones];

    const [result] = await conn.query(sql, params);
    await conn.commit();

    // Si fue insert: result.insertId; si fue update: no cambia insertId
    const idpuja = result.insertId || null;

    return res.json({
      ok: true,
      idpuja,
      updated: result.affectedRows === 2,  // en MySQL, ON DUPLICATE KEY suele dar 2 cuando actualiza
      message: result.affectedRows === 2 ? 'Puja actualizada' : 'Puja creada'
    });
  } catch (e) {
    if (conn) {
      try { await conn.rollback(); } catch {}
    }
    console.error('[api] POST /api/pujas error:', e);
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  } finally {
    if (conn) conn.release();
  }
});


// GET /api/requerimientos/:id/pujas
app.get('/api/requerimientos/:id/pujas', verifyToken, async (req, res) => {
  const idReq = parseInt(req.params.id, 10);
  console.log(idReq+"----");
  if (!Number.isInteger(idReq) || idReq <= 0) {
    return res.status(400).json({ ok: false, error: 'id inválido' });
  }
  let conn;
  try {
    conn = await pool.getConnection();
    const [rows] = await conn.query(
      `SELECT o.idofertas, r.sku, r.producto, r.cantidad as cantidadr, o.cantidad as cantidado, o.precio as precioo, u.empresa, r.precio as preciop FROM puja.ofertas as o
      inner join puja.requerimientos as r on r.idrequerimientos = o.fkrequerimientos
      inner join puja.usuarios as u on u.idusuarios = o.fkusuario
      WHERE r.idrequerimientos = ?`,
      [idReq]
    );
    return res.json({ ok: true, rows });
  } catch (e) {
    console.error('[api] GET /api/requerimientos/:id/pujas error:', e);
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  } finally {
    if (conn) conn.release();
  }
});

// Inactivar requerimiento
app.patch('/api/requerimientos/:id/inactivar', verifyToken, async (req, res) => {
  if (!req.user || String(req.user.tipo) !== '1') {
    return res.status(403).json({ ok: false, error: 'No autorizado' });
  }

  const idReq = parseInt(req.params.id, 10);
  if (!Number.isInteger(idReq) || idReq <= 0) {
    return res.status(400).json({ ok: false, error: 'id inválido' });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    const [result] = await conn.query(
      `UPDATE puja.requerimientos
         SET activo = 0
       WHERE idrequerimientos = ? AND activo = 1`,
      [idReq]
    );

    if ((result.affectedRows || 0) === 0) {
      return res.status(404).json({ ok: false, error: 'No se encontró activo o ya estaba inactivo' });
    }

    return res.json({ ok: true, affected: result.affectedRows });
  } catch (e) {
    console.error('[api] PATCH /api/requerimientos/:id/inactivar error:', e);
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  } finally {
    if (conn) conn.release();
  }
});

// requerimientos
app.get('/api/proveedores', verifyToken, async (req, res) => {

  console.log(req.user);
  const selectSql = `
    SELECT idusuarios, name, email, empresa FROM puja.usuarios
    WHERE activo = 1
    ORDER BY idusuarios
    LIMIT 1000000
  `;
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(selectSql);
      res.json({ ok: true, rows });
    } finally { conn.release(); }
  } catch (e) {
    console.error('[api] Error /api/proveedores:', e);
    res.status(500).json({ ok:false, error:e.message || String(e) });
  }
});

app.get('/api/pujasactivas', verifyToken, async (req, res) => {

  const selectSql = `
  SELECT r.idrequerimientos, r.sku, r.ean, r.producto, r.laboratorio, r.cantidad as cantidadr, r.precio as preciop, o.cantidad as cantidado, o.precio as precioo, u.empresa, o.observaciones FROM puja.ofertas as o
  inner join puja.requerimientos as r on r.idrequerimientos= o.fkrequerimientos
  inner join puja.usuarios as u on u.idusuarios= o.fkusuario
  where r.activo=1 limit 10000
  `;
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(selectSql);
      res.json({ ok: true, rows });
    } finally { conn.release(); }
  } catch (e) {
    console.error('[api] Error /api/pujasactivas:', e);
    res.status(500).json({ ok:false, error:e.message || String(e) });
  }
});



const PORT = Number(process.env.PORT || 3002);
app.listen(PORT, () => {
  console.log(`API lista en http://localhost:${PORT}`);
});
