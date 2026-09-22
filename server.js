
const express = require("express");
const mysql = require("mysql2"); // Se recomienda mysql2 en lugar de mysql
const bodyParser = require("body-parser");
const cors = require("cors");
const QRCode = require("qrcode");
const path = require("path");
const fs = require("fs");
const PDFDocument = require("pdfkit");
const XLSX = require("xlsx");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();

// --- CONFIGURACIÓN DE ENTORNO ---
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "clave_secreta_inventario";

app.use(bodyParser.json());
app.use(cors());

// --- CARPETAS (Gestión de persistencia) ---
const CARPETA_QR = path.join(__dirname, "codigos_qr");
const CARPETA_REPORTES = path.join(__dirname, "reportes_exportados");
const CARPETA_UPLOADS = path.join(__dirname, "uploads");

[CARPETA_QR, CARPETA_REPORTES, CARPETA_UPLOADS].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// --- STORAGE MULTER ---
const storageMateriales = multer.diskStorage({
  destination: (req, file, cb) => cb(null, CARPETA_UPLOADS),
  filename: (req, file, cb) => {
    const extension = path.extname(file.originalname) || ".jpg";
    cb(null, `material_${Date.now()}${extension}`);
  }
});
const upload = multer({ storage: storageMateriales });

// --- LOGGING ---
app.use((req, res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.originalUrl}`);
  next();
});

app.use("/uploads", express.static(CARPETA_UPLOADS));

// --- CONEXIÓN A BASE DE DATOS (Ajustada para Railway) ---
const conexion = mysql.createConnection({
  host: process.env.MYSQLHOST || "localhost",
  port: process.env.MYSQLPORT || 3306,
  user: process.env.MYSQLUSER || "root",
  password: process.env.MYSQLPASSWORD || "",
  database: process.env.MYSQLDATABASE || "inventario_db"
});
conexion.connect(err => {
  if (err) {
    console.error("Error conectando a BD:", err);
  } else {
    console.log("Conectado a la base de datos MySQL");
  }
});

// --- MIDDLEWARES DE SEGURIDAD ---
function verificarToken(req, res, next) {
  const header = req.headers["authorization"];
  const token = header && header.split(" ")[1];
  if (!token) return res.status(401).json({ status: "fail", mensaje: "Token no proporcionado" });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ status: "fail", mensaje: "Token inválido" });
    req.usuario = decoded;
    next();
  });
}

function soloAdmin(req, res, next) {
  if (req.usuario?.rol !== "admin") {
    return res.status(403).json({ status: "fail", mensaje: "Acceso solo para administradores" });
  }
  next();
}

// ---------------------------------------------------------------------------
// AUTENTICACIÓN (registro / login con bcrypt + JWT)
// ---------------------------------------------------------------------------
app.get("/", (req, res) => res.send("Bienvenido a Inventario API (Producción)"));

app.post("/registro", (req, res) => {
  const { nombre, correo, password, rol } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  const sql = "INSERT INTO usuarios (nombre, correo, password, rol) VALUES (?, ?, ?, ?)";
  conexion.query(sql, [nombre, correo, hashedPassword, rol || "maestro"], (err, result) => {
    if (err) return res.json({ status: "error", mensaje: "El correo ya existe" });
    res.json({ status: "ok", mensaje: "Usuario registrado" });
  });
});

app.post("/login", (req, res) => {
  const { correo, password } = req.body;
  const sql = "SELECT * FROM usuarios WHERE correo = ?";
  conexion.query(sql, [correo], (err, result) => {
    if (err || result.length === 0) return res.json({ status: "error", mensaje: "Usuario no encontrado" });
    const usuario = result[0];
    if (!bcrypt.compareSync(password, usuario.password)) return res.json({ status: "error", mensaje: "Contraseña incorrecta" });
    const token = jwt.sign({ id: usuario.id, rol: usuario.rol, nombre: usuario.nombre }, SECRET, { expiresIn: "8h" });
    res.json({ status: "ok", token, rol: usuario.rol });
  });
});

// Middleware que protege rutas: exige "Authorization: Bearer <token>"
// válido y deja los datos del usuario en req.usuario = { id, rol, nombre }.
function verificarToken(req, res, next) {
  const header = req.headers["authorization"];
  const token = header && header.split(" ")[1]; // "Bearer <token>"

  if (!token) {
    return res.status(401).json({ status: "fail", mensaje: "Token no proporcionado" });
  }

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ status: "fail", mensaje: "Token inválido o expirado" });
    }
    req.usuario = decoded; // { id, rol, nombre }
    next();
  });
}

// Middleware adicional: solo deja pasar si el rol del token es "admin".
// Debe usarse SIEMPRE después de verificarToken.
function soloAdmin(req, res, next) {
  if (!req.usuario || req.usuario.rol !== "admin") {
    return res.status(403).json({ status: "fail", mensaje: "Acceso solo para administradores" });
  }
  next();
}

// ---------------------------------------------------------------------------
// USUARIOS
// ---------------------------------------------------------------------------

// Listar todos los usuarios (para la pantalla "Usuarios" de Gestión de
// Permisos, donde se activa/desactiva el acceso). Solo admin: expone
// nombre, correo y rol de todos los usuarios del sistema.
app.get("/usuarios", verificarToken, soloAdmin, (req, res) => {
  const sql = "SELECT id, nombre, correo, rol FROM usuarios";
  conexion.query(sql, (err, result) => {
    if (err) return res.json({ status: "error", mensaje: err });
    res.json(result);
  });
});

// Listar maestros (usuarios con rol "maestro"), para selectores en el
// frontend (ej. Gestión de Permisos). No se expone la contraseña.
app.get("/usuarios/maestros", verificarToken, (req, res) => {
  const sql = "SELECT id, nombre, correo FROM usuarios WHERE rol = 'maestro'";
  conexion.query(sql, (err, result) => {
    if (err) return res.json({ status: "error", mensaje: err });
    res.json(result);
  });
});

// ---------------------------------------------------------------------------
// MATERIALES
// ---------------------------------------------------------------------------

// Listar todos los materiales. Necesario para selectores del frontend
// (ej. Gestión de Permisos, registrar préstamo). Cualquier usuario logueado
// puede consultarlo, aunque solo un admin puede dar de alta materiales.
app.get("/materiales", verificarToken, (req, res) => {
  const sql = "SELECT * FROM materiales";
  conexion.query(sql, (err, result) => {
    if (err) return res.json({ status: "error", mensaje: err });
    res.json(result);
  });
});

// Solo un administrador puede dar de alta materiales nuevos.
// Acepta multipart/form-data con el campo "foto" (imagen del material).
// NOTA: no se recibe "id" desde el body; se deja que la base de datos
// lo autogenere (AUTO_INCREMENT) para evitar choques de llaves duplicadas.
app.post("/materiales", verificarToken, soloAdmin, upload.single("foto"), (req, res) => {
  const { nombre, cantidad, estado, categoria } = req.body;
  const foto = req.file ? req.file.filename : null;

  const sql = "INSERT INTO materiales (nombre, cantidad, estado, categoria, foto) VALUES (?, ?, ?, ?, ?)";
  conexion.query(sql, [nombre, cantidad, estado, categoria, foto], (err, result) => {
    if (err) {
      res.json({ status: "error", mensaje: err });
    } else {
      res.json({
        status: "ok",
        mensaje: "Material agregado con foto y categoría",
        id: result.insertId
      });
    }
  });
});

// Editar un material existente. Solo admin.
// Acepta multipart/form-data igual que el alta: si viene una nueva "foto"
// se reemplaza y se borra la anterior del disco; si no viene, se conserva
// la que ya tenía.
app.put("/materiales/:id", verificarToken, soloAdmin, upload.single("foto"), (req, res) => {
  const { id } = req.params;
  const { nombre, cantidad, estado, categoria } = req.body;

  const aplicarActualizacion = (nuevaFoto) => {
    let sql;
    let params;
    if (nuevaFoto) {
      sql = "UPDATE materiales SET nombre=?, cantidad=?, estado=?, categoria=?, foto=? WHERE id=?";
      params = [nombre, cantidad, estado, categoria, nuevaFoto, id];
    } else {
      sql = "UPDATE materiales SET nombre=?, cantidad=?, estado=?, categoria=? WHERE id=?";
      params = [nombre, cantidad, estado, categoria, id];
    }
    conexion.query(sql, params, (err, result) => {
      if (err) return res.json({ status: "error", mensaje: err });
      res.json({ status: "ok", mensaje: "Material actualizado" });
    });
  };

  if (req.file) {
    // Hay foto nueva: buscamos la foto anterior para borrarla del disco
    // y no dejar archivos huérfanos acumulándose en /uploads.
    conexion.query("SELECT foto FROM materiales WHERE id = ?", [id], (err, result) => {
      if (!err && result.length > 0 && result[0].foto) {
        fs.unlink(path.join(CARPETA_UPLOADS, result[0].foto), () => {});
      }
      aplicarActualizacion(req.file.filename);
    });
  } else {
    aplicarActualizacion(null);
  }
});

// Eliminar un material. Solo admin. También borra la foto del disco si
// tenía una asociada.
app.delete("/materiales/:id", verificarToken, soloAdmin, (req, res) => {
  const { id } = req.params;

  conexion.query("SELECT foto FROM materiales WHERE id = ?", [id], (errSelect, result) => {
    const fotoAnterior = !errSelect && result.length > 0 ? result[0].foto : null;

    conexion.query("DELETE FROM materiales WHERE id = ?", [id], (err, deleteResult) => {
      if (err) {
        // Si el material tiene préstamos asociados, MySQL rechaza el borrado
        // por la llave foránea. Se lo explicamos al usuario en vez de
        // devolver el error crudo de MySQL.
        if (err.code === "ER_ROW_IS_REFERENCED_2" || err.code === "ER_ROW_IS_REFERENCED") {
          return res.json({
            status: "error",
            mensaje: "No se puede eliminar: este material tiene préstamos registrados en el historial."
          });
        }
        return res.json({ status: "error", mensaje: err });
      }
      if (fotoAnterior) {
        fs.unlink(path.join(CARPETA_UPLOADS, fotoAnterior), () => {});
      }
      res.json({ status: "ok", mensaje: "Material eliminado" });
    });
  });
});

// Genera el código QR de un material. Requiere estar logueado (cualquier
// rol), porque de todas formas hace falta el token para luego prestar
// o devolver desde la app.
app.get("/materiales/:id/qr", verificarToken, async (req, res) => {
  try {
    const rutaArchivo = path.join(CARPETA_QR, `${req.params.id}.png`);
    await QRCode.toFile(rutaArchivo, req.params.id, {
      color: { dark: "#000000", light: "#FFFFFF" },
    });
    res.sendFile(rutaArchivo);
  } catch (err) {
    res.status(500).json({ status: "error", mensaje: err.message });
  }
});

// ---------------------------------------------------------------------------
// PRÉSTAMOS
// ---------------------------------------------------------------------------

// Listar préstamos (con el nombre del material vía JOIN)
app.get("/prestamos", (req, res) => {
  const sql = `
    SELECT p.id, m.nombre AS material, u.nombre AS docente,
           p.fecha_prestamo, p.fecha_devolucion
    FROM prestamos p
    JOIN materiales m ON p.material_id = m.id
    JOIN usuarios u ON p.docente_id = u.id
  `;
  conexion.query(sql, (err, result) => {
    if (err) return res.json({ status: "error", mensaje: err });
    res.json(result);
  });
});

// Registrar un nuevo préstamo.
//
// IMPORTANTE: el rol ya NO se toma de req.body.rol (cualquiera podía
// mandar "rol": "admin" a mano y saltarse la validación de permisos).
// Ahora se toma de req.usuario.rol, que viene del token verificado.
app.post("/prestamos", verificarToken, (req, res) => {
  const { material_id, docente_id, fecha_prestamo, maestro } = req.body;
  const rol = req.usuario.rol;

  if (!material_id || !docente_id || !fecha_prestamo || !maestro) {
    return res.json({ status: "fail", mensaje: "Faltan datos del préstamo" });
  }

  const registrar = () => {
    const sql = "INSERT INTO prestamos (material_id, docente_id, fecha_prestamo, maestro) VALUES (?, ?, ?, ?)";
    conexion.query(sql, [material_id, docente_id, fecha_prestamo, maestro], (err, result) => {
      if (err) {
        res.json({ status: "error", mensaje: err });
      } else {
        res.json({ status: "ok", mensaje: "Préstamo registrado" });
      }
    });
  };

  if (rol === "admin") {
    return registrar();
  }

  const sqlPermiso = "SELECT * FROM permisos WHERE maestro = ? AND material_id = ? AND puede_prestar = TRUE";
  conexion.query(sqlPermiso, [maestro, material_id], (err, result) => {
    if (err) {
      res.json({ status: "error", mensaje: err });
    } else if (result.length === 0) {
      res.json({ status: "fail", mensaje: "No tienes permiso para prestar este material" });
    } else {
      registrar();
    }
  });
});

// Actualizar préstamo (edición manual, ej. corregir fecha de devolución).
// Solo admin, para no dejar que cualquiera reescriba fechas a mano.
app.put("/prestamos/:id", verificarToken, soloAdmin, (req, res) => {
  const { fecha_devolucion } = req.body;
  const sql = "UPDATE prestamos SET fecha_devolucion = ? WHERE id = ?";
  conexion.query(sql, [fecha_devolucion, req.params.id], (err, result) => {
    if (err) {
      res.json({ status: "error", mensaje: err });
    } else {
      res.json({ status: "ok", mensaje: "Préstamo actualizado" });
    }
  });
});

// Marcar devolución por id de préstamo.
app.put("/prestamos/devolver/:id", verificarToken, (req, res) => {
  const { id } = req.params;
  const { maestro } = req.body;
  const rol = req.usuario.rol;

  const marcarDevuelto = () => {
    const sql = "UPDATE prestamos SET fecha_devolucion = NOW() WHERE id = ?";
    conexion.query(sql, [id], (err, result) => {
      if (err) {
        res.json({ status: "error", mensaje: err });
      } else {
        res.json({ status: "ok", mensaje: "Material devuelto" });
      }
    });
  };

  if (rol === "admin") {
    return marcarDevuelto();
  }

  if (!maestro) {
    return res.json({ status: "fail", mensaje: "Falta indicar el maestro" });
  }

  const sqlPrestamo = "SELECT material_id FROM prestamos WHERE id = ?";
  conexion.query(sqlPrestamo, [id], (err, prestamoResult) => {
    if (err) {
      return res.json({ status: "error", mensaje: err });
    }
    if (prestamoResult.length === 0) {
      return res.json({ status: "fail", mensaje: "Préstamo no encontrado" });
    }

    const materialId = prestamoResult[0].material_id;
    const sqlPermiso = "SELECT * FROM permisos WHERE maestro = ? AND material_id = ? AND puede_devolver = TRUE";
    conexion.query(sqlPermiso, [maestro, materialId], (err2, permisoResult) => {
      if (err2) {
        return res.json({ status: "error", mensaje: err2 });
      }
      if (permisoResult.length === 0) {
        return res.json({ status: "fail", mensaje: "No tienes permiso para devolver este material" });
      }
      marcarDevuelto();
    });
  });
});

// Marcar devolución por material_id (escaneo de QR, modo Entrega).
app.put("/prestamos/devolver/material/:material_id", verificarToken, (req, res) => {
  const { material_id } = req.params;
  const { maestro } = req.body;
  const rol = req.usuario.rol;

  const buscarPrestamoAbierto = (callback) => {
    const sql = `
      SELECT id FROM prestamos
      WHERE material_id = ? AND fecha_devolucion IS NULL
      ORDER BY fecha_prestamo DESC
      LIMIT 1
    `;
    conexion.query(sql, [material_id], (err, result) => {
      if (err) {
        return res.json({ status: "error", mensaje: err });
      }
      if (result.length === 0) {
        return res.json({ status: "fail", mensaje: "No hay un préstamo pendiente para este material" });
      }
      callback(result[0].id);
    });
  };

  const marcarDevuelto = (prestamoId) => {
    const sql = "UPDATE prestamos SET fecha_devolucion = NOW() WHERE id = ?";
    conexion.query(sql, [prestamoId], (err) => {
      if (err) {
        res.json({ status: "error", mensaje: err });
      } else {
        res.json({ status: "ok", mensaje: "Material devuelto" });
      }
    });
  };

  if (rol === "admin") {
    return buscarPrestamoAbierto((prestamoId) => marcarDevuelto(prestamoId));
  }

  if (!maestro) {
    return res.json({ status: "fail", mensaje: "Falta indicar el maestro" });
  }

  const sqlPermiso = "SELECT * FROM permisos WHERE maestro = ? AND material_id = ? AND puede_devolver = TRUE";
  conexion.query(sqlPermiso, [maestro, material_id], (err, permisoResult) => {
    if (err) {
      return res.json({ status: "error", mensaje: err });
    }
    if (permisoResult.length === 0) {
      return res.json({ status: "fail", mensaje: "No tienes permiso para devolver este material" });
    }
    buscarPrestamoAbierto((prestamoId) => marcarDevuelto(prestamoId));
  });
});

// ---------------------------------------------------------------------------
// HISTORIAL DETALLADO DE PRÉSTAMOS (Guía 17)
// ---------------------------------------------------------------------------

// Historial completo de préstamos y devoluciones, con filtros opcionales por
// maestro (nombre del docente), material (nombre) y rango de fechas de
// préstamo. Protegido con verificarToken + soloAdmin, igual que el resto de
// /reportes/*, porque es el administrador quien consulta el historial
// general de todos los maestros.
app.get("/historial", verificarToken, soloAdmin, (req, res) => {
  const { maestro, material, fecha_inicio, fecha_fin } = req.query;

  let sql = `
    SELECT p.id, m.nombre AS material, u.nombre AS docente,
           p.fecha_prestamo, p.fecha_devolucion
    FROM prestamos p
    JOIN materiales m ON p.material_id = m.id
    JOIN usuarios u ON p.docente_id = u.id
    WHERE 1 = 1
  `;
  const params = [];

  if (maestro) {
    sql += " AND u.nombre = ?";
    params.push(maestro);
  }
  if (material) {
    sql += " AND m.nombre = ?";
    params.push(material);
  }
  if (fecha_inicio && fecha_fin) {
    sql += " AND p.fecha_prestamo BETWEEN ? AND ?";
    params.push(fecha_inicio, fecha_fin);
  }

  sql += " ORDER BY p.fecha_prestamo DESC";

  conexion.query(sql, params, (err, result) => {
    if (err) return res.json({ status: "error", mensaje: err });
    res.json(result);
  });
});

// ---------------------------------------------------------------------------
// PERMISOS
// ---------------------------------------------------------------------------

// Asignar permisos es una acción administrativa: solo admin.
app.post("/permisos", verificarToken, soloAdmin, (req, res) => {
  const { maestro, material_id, puede_ver, puede_prestar, puede_devolver } = req.body;
  const sql = `
    INSERT INTO permisos (maestro, material_id, puede_ver, puede_prestar, puede_devolver)
    VALUES (?, ?, ?, ?, ?)
  `;
  conexion.query(sql, [maestro, material_id, puede_ver, puede_prestar, puede_devolver], (err, result) => {
    if (err) {
      res.json({ status: "error", mensaje: err });
    } else {
      res.json({ status: "ok", mensaje: "Permiso asignado" });
    }
  });
});

// ---------------------------------------------------------------------------
// NOTIFICACIONES
// ---------------------------------------------------------------------------

app.get("/notificaciones/:maestro", verificarToken, (req, res) => {
  const sql = `
    SELECT p.id, p.material_id, m.nombre AS material, p.fecha_prestamo, p.fecha_devolucion
    FROM prestamos p
    JOIN materiales m ON p.material_id = m.id
    WHERE p.maestro = ? AND p.fecha_devolucion IS NULL
  `;
  conexion.query(sql, [req.params.maestro], (err, result) => {
    if (err) {
      res.json({ status: "error", mensaje: err });
    } else {
      res.json(result);
    }
  });
});

// ---------------------------------------------------------------------------
// REPORTES (solo administradores)
// ---------------------------------------------------------------------------

app.get("/reportes/total", verificarToken, soloAdmin, (req, res) => {
  const sql = "SELECT COUNT(*) AS total FROM prestamos";
  conexion.query(sql, (err, result) => {
    if (err) res.json({ status: "error", mensaje: err });
    else res.json(result[0]);
  });
});

app.get("/reportes/pendientes", verificarToken, soloAdmin, (req, res) => {
  const sql = "SELECT COUNT(*) AS pendientes FROM prestamos WHERE fecha_devolucion IS NULL";
  conexion.query(sql, (err, result) => {
    if (err) res.json({ status: "error", mensaje: err });
    else res.json(result[0]);
  });
});

app.get("/reportes/devueltos", verificarToken, soloAdmin, (req, res) => {
  const sql = "SELECT COUNT(*) AS devueltos FROM prestamos WHERE fecha_devolucion IS NOT NULL";
  conexion.query(sql, (err, result) => {
    if (err) res.json({ status: "error", mensaje: err });
    else res.json(result[0]);
  });
});

// Exportar reportes a PDF.
// Uso: GET /reportes/pdf?maestro=juan&fecha_inicio=2026-09-17T00:00:00.000&fecha_fin=2026-09-23T00:00:00.000
// Header: Authorization: Bearer <token>
app.get("/reportes/pdf", verificarToken, soloAdmin, (req, res) => {
  const { maestro, material, fecha_inicio, fecha_fin } = req.query;

  let sql = `
    SELECT prestamos.id, materiales.nombre AS material,
           prestamos.fecha_prestamo, prestamos.fecha_devolucion, prestamos.maestro
    FROM prestamos
    INNER JOIN materiales ON prestamos.material_id = materiales.id
    WHERE 1 = 1
  `;
  const params = [];

  if (fecha_inicio) {
    sql += " AND prestamos.fecha_prestamo >= ?";
    params.push(fecha_inicio);
  }
  if (fecha_fin) {
    sql += " AND prestamos.fecha_prestamo <= ?";
    params.push(fecha_fin);
  }
  if (maestro) {
    sql += " AND prestamos.maestro = ?";
    params.push(maestro);
  }
  if (material) {
    sql += " AND materiales.nombre = ?";
    params.push(material);
  }

  sql += " ORDER BY prestamos.fecha_prestamo ASC";

  conexion.query(sql, params, (err, result) => {
    if (err) {
      return res.status(500).json({ status: "error", mensaje: err });
    }

    try {
      const nombreArchivo = `reporte_${Date.now()}.pdf`;
      const rutaArchivo = path.join(CARPETA_REPORTES, nombreArchivo);

      const doc = new PDFDocument({ margin: 40, size: "A4" });
      const stream = fs.createWriteStream(rutaArchivo);
      doc.pipe(stream);

      doc.fontSize(18).text("Reporte de Préstamos", { align: "center" });
      doc.moveDown();
      doc.fontSize(10).fillColor("#555555");
      if (fecha_inicio || fecha_fin) {
        doc.text(`Rango de fechas: ${fecha_inicio ? fecha_inicio.split("T")[0] : "sin definir"} a ${fecha_fin ? fecha_fin.split("T")[0] : "sin definir"}`);
      }
      if (maestro) {
        doc.text(`Maestro: ${maestro}`);
      }
      if (material) {
        doc.text(`Material: ${material}`);
      }
      doc.text(`Total de registros: ${result.length}`);
      doc.moveDown();
      doc.fillColor("#000000");

      const colX = { material: 40, prestamo: 220, devolucion: 330, maestro: 440 };
      const rowStart = doc.y;
      doc.fontSize(10).font("Helvetica-Bold");
      doc.text("Material", colX.material, rowStart);
      doc.text("Fecha préstamo", colX.prestamo, rowStart);
      doc.text("Fecha devolución", colX.devolucion, rowStart);
      doc.text("Maestro", colX.maestro, rowStart);
      doc.moveDown(0.5);
      doc.font("Helvetica");
      doc.moveTo(40, doc.y).lineTo(555, doc.y).strokeColor("#cccccc").stroke();
      doc.moveDown(0.3);

      if (result.length === 0) {
        doc.text("No hay registros en el rango seleccionado.", 40);
      } else {
        result.forEach((fila) => {
          const y = doc.y;
          const fechaPrestamo = fila.fecha_prestamo ? new Date(fila.fecha_prestamo).toLocaleDateString() : "-";
          const fechaDevolucion = fila.fecha_devolucion ? new Date(fila.fecha_devolucion).toLocaleDateString() : "Pendiente";

          doc.fontSize(9);
          doc.text(String(fila.material), colX.material, y, { width: 170 });
          doc.text(fechaPrestamo, colX.prestamo, y, { width: 100 });
          doc.text(fechaDevolucion, colX.devolucion, y, { width: 100 });
          doc.text(String(fila.maestro), colX.maestro, y, { width: 110 });

          doc.moveDown(0.8);

          if (doc.y > 760) {
            doc.addPage();
          }
        });
      }

      doc.end();

      stream.on("finish", () => {
        res.download(rutaArchivo, "reporte_prestamos.pdf", (errDescarga) => {
          fs.unlink(rutaArchivo, () => {});
          if (errDescarga) {
            console.error("Error al enviar el PDF:", errDescarga);
          }
        });
      });

      stream.on("error", (errStream) => {
        res.status(500).json({ status: "error", mensaje: errStream.message });
      });
    } catch (errPdf) {
      res.status(500).json({ status: "error", mensaje: errPdf.message });
    }
  });
});

// Exportar reportes a Excel (.xlsx).
// Uso: GET /reportes/exportar/excel?maestro=juan&desde=2026-09-17&hasta=2026-09-23
// Header: Authorization: Bearer <token>
app.get("/reportes/exportar/excel", verificarToken, soloAdmin, (req, res) => {
  const { maestro, material, desde, hasta } = req.query;

  if (!desde || !hasta) {
    return res.status(400).json({ status: "fail", mensaje: "Debes indicar las fechas 'desde' y 'hasta'" });
  }

  let sql = `
    SELECT prestamos.id, materiales.nombre AS material,
           prestamos.fecha_prestamo, prestamos.fecha_devolucion, prestamos.maestro
    FROM prestamos
    INNER JOIN materiales ON prestamos.material_id = materiales.id
    WHERE prestamos.fecha_prestamo >= ? AND prestamos.fecha_prestamo <= ?
  `;
  const params = [desde, hasta];

  if (maestro) {
    sql += " AND prestamos.maestro = ?";
    params.push(maestro);
  }
  if (material) {
    sql += " AND materiales.nombre = ?";
    params.push(material);
  }

  sql += " ORDER BY prestamos.fecha_prestamo ASC";

  conexion.query(sql, params, (err, result) => {
    if (err) {
      return res.status(500).json({ status: "error", mensaje: err });
    }

    try {
      const filas = result.map((fila) => ({
        Material: fila.material,
        "Fecha préstamo": fila.fecha_prestamo ? new Date(fila.fecha_prestamo).toLocaleDateString() : "-",
        "Fecha devolución": fila.fecha_devolucion ? new Date(fila.fecha_devolucion).toLocaleDateString() : "Pendiente",
        Maestro: fila.maestro
      }));

      const hoja = XLSX.utils.json_to_sheet(filas);

      hoja["!cols"] = [
        { wch: 30 },
        { wch: 16 },
        { wch: 16 },
        { wch: 20 }
      ];

      const libro = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(libro, hoja, "Préstamos");

      const buffer = XLSX.write(libro, { type: "buffer", bookType: "xlsx" });

      res.setHeader("Content-Disposition", "attachment; filename=reporte_prestamos.xlsx");
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
      res.send(buffer);
    } catch (errExcel) {
      res.status(500).json({ status: "error", mensaje: errExcel.message });
    }
  });
});

// ---------------------------------------------------------------------------
// DASHBOARD
// ---------------------------------------------------------------------------

app.get("/dashboard", (req, res) => {
  const sql = `
    SELECT
      (SELECT COUNT(*) FROM materiales) AS total_materiales,
      (SELECT COUNT(*) FROM prestamos WHERE fecha_devolucion IS NULL) AS prestados,
      (SELECT COUNT(*) FROM prestamos WHERE fecha_devolucion IS NOT NULL) AS devueltos,
      (SELECT COUNT(*) FROM materiales WHERE estado = 'dañado') AS danados
  `;
  conexion.query(sql, (err, result) => {
    if (err) {
      res.json({ status: "error", mensaje: err });
    } else {
      res.json(result[0]);
    }
  });
});

// ---------------------------------------------------------------------------
// 404 (nuevo) — SIEMPRE al final, después de registrar todas las rutas
// ---------------------------------------------------------------------------
// Si una petición llega hasta aquí es porque ninguna ruta de arriba coincidió
// con su método+path. Antes, Express devolvía una página HTML ("Cannot PUT
// /materiales/5"); ahora devuelve JSON y lo imprime en consola, para que sea
// obvio si el problema es de ruta (typo, IP vieja, servidor no reiniciado)
// en vez de un simple "Error del servidor: 404" sin contexto en la app.
app.use((req, res) => {
  res.status(404).json({ status: "error", mensaje: "Ruta no encontrada" });
});

// --- INICIO DEL SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
