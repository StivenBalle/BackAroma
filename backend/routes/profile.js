import express from "express";
import bcrypt from "bcrypt";
import multer from "multer";
import path from "path";
import fs from "fs";
import pool from "../database/db.js";
import { verifyToken } from "../middleware/jwt.js";
import logger from "../utils/logger.js";
import { fileURLToPath } from "url";
import inputProtect from "../middleware/inputProtect.js";
import { fileTypeFromFile } from "file-type";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const router = express.Router();

const BASE_URL =
  process.env.NODE_ENV === "production"
    ? "https://backendaromaserrania.onrender.com"
    : "http://localhost:3000";

// ====== MULTER CONFIG ======
const uploadDir = path.join(__dirname, "../../uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const validation = inputProtect.validateFilename(file.originalname);

    if (!validation.valid) {
      return cb(new Error(validation.reason));
    }

    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(validation.sanitized);
    const name = path.basename(validation.sanitized, ext);

    cb(null, `${name}-${uniqueSuffix}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowed = ["image/jpeg", "image/png"];
  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Solo se permiten imágenes JPEG o PNG"));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

router.use((req, res, next) => {
  if (req.body && typeof req.body === "object") {
    req.body = inputProtect.sanitizeObjectRecursivelyServer(req.body);
  }
  if (req.params && typeof req.params === "object") {
    req.params = inputProtect.sanitizeObjectRecursivelyServer(req.params);
  }
  next();
});

// POST /api/user/profile-image - Cargar imagen de perfil
router.post(
  "/profile-image",
  verifyToken,
  upload.single("profileImage"),
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      logger.log(`📥 POST /api/user/profile-image - userId: ${userId}`);

      if (!req.file) {
        return res
          .status(400)
          .json({ error: "No se proporcionó ninguna imagen" });
      }

      const filePath = path.join(uploadDir, req.file.filename);
      const ft = await fileTypeFromFile(filePath).catch(() => null);
      if (!ft || !["image/jpeg", "image/png"].includes(ft.mime)) {
        try {
          fs.unlinkSync(filePath);
        } catch (e) {
          /* noop */
        }
        logger.warn(
          `Archivo eliminado por mismatch MIME: ${req.file.filename}`
        );
        return res.status(400).json({ error: "Archivo no válido" });
      }

      const imagePath = `/uploads/${req.file.filename}`;

      const result = await pool.query(
        `UPDATE users SET image = $1 WHERE id = $2 RETURNING image`,
        [imagePath, userId]
      );

      if (!result.rows[0]) {
        try {
          fs.unlinkSync(filePath);
        } catch (e) {
          /* noop */
        }
        return res.status(404).json({ error: "Usuario no encontrado" });
      }

      const fullImageUrl = `${BASE_URL}${imagePath}`;
      logger.log("📤 Imagen de perfil cargada:", fullImageUrl);

      return res.json({
        message: "Imagen de perfil cargada correctamente",
        image: fullImageUrl,
      });
    } catch (err) {
      logger.error("❌ Error uploading profile image:", err.message || err);
      next(err);
    }
  }
);

// GET /api/user/profile - Obtener datos del perfil
router.get("/profile", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      `SELECT name, email, phone_number, role, image, auth_provider, address, created_at FROM users WHERE id = $1`,
      [userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];
    user.image = user.image ? `${BASE_URL}${user.image}` : null;

    res.json(user);
  } catch (err) {
    logger.error("❌ Error fetching profile:", err.message);
    next(err);
  }
});

// DELETE /api/user/delete-image - Eliminar imagen de perfil
router.delete("/delete-image", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(`SELECT image FROM users WHERE id = $1`, [
      userId,
    ]);

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const currentImage = result.rows[0].image;
    if (currentImage) {
      const filePath = path.join(__dirname, "../../", currentImage);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        logger.log(`📁 Archivo eliminado: ${filePath}`);
      }
    }

    await pool.query(`UPDATE users SET image = NULL WHERE id = $1`, [userId]);

    res.json({ message: "Imagen de perfil eliminada correctamente" });
  } catch (err) {
    logger.error("❌ Error deleting profile image:", err.message);
    next(err);
  }
});

// PUT /api/user/profile - Actualizar datos del perfil
router.put("/update", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const name = inputProtect.sanitizeString(req.body.name || "");
    const phone = inputProtect.sanitizeString(req.body.phone || null);

    if (!name) {
      return res.status(400).json({ error: "El nombre es requerido" });
    }

    const result = await pool.query(
      `UPDATE users SET name = $1, phone_number = $2 WHERE id = $3 RETURNING name, phone_number`,
      [name, phone || null, userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({
      message: "Perfil actualizado correctamente",
      ...result.rows[0],
    });
  } catch (err) {
    logger.error("❌ Error updating profile:", err.message);
    next(err);
  }
});

// PUT /api/user/shipping-address - Actualizar dirección de envío en users
router.put("/update/shipping-address", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { line1, city, country, postal_code, state } = req.body;

    if (!line1 || !city || !country) {
      return res
        .status(400)
        .json({ error: "Calle, ciudad y país son requeridos" });
    }

    const checkResult = await pool.query(
      `SELECT address FROM users WHERE id = $1`,
      [userId]
    );

    if (!checkResult.rows[0] || !checkResult.rows[0].address) {
      return res.status(400).json({
        error:
          "No hay dirección existente para actualizar. Usa POST para crear una nueva.",
      });
    }

    const newAddress = {
      line1: inputProtect.sanitizeString(line1),
      city: inputProtect.sanitizeString(city),
      country: inputProtect.sanitizeString(country),
      postal_code: inputProtect.sanitizeString(postal_code || ""),
      state: inputProtect.sanitizeString(state || ""),
    };

    const result = await pool.query(
      `UPDATE users SET address = $1 WHERE id = $2 RETURNING address`,
      [newAddress, userId]
    );

    res.json({
      message: "Dirección de envío actualizada correctamente",
      address: result.rows[0].address,
    });
  } catch (err) {
    logger.error("❌ Error updating shipping address:", err.message);
    next(err);
  }
});

// POST /api/user/shipping-address - Crear una nueva dirección de envío
router.post("/add/shipping-address", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { line1, city, country, postal_code, state } = req.body;

    if (!line1 || !city || !country) {
      return res
        .status(400)
        .json({ error: "Calle, ciudad y país son requeridos" });
    }

    const checkResult = await pool.query(
      `SELECT address FROM users WHERE id = $1`,
      [userId]
    );

    if (checkResult.rows[0] && checkResult.rows[0].address) {
      return res
        .status(400)
        .json({ error: "Ya existe una dirección. Usa PUT para actualizarla." });
    }

    const newAddress = {
      line1: inputProtect.sanitizeString(line1),
      city: inputProtect.sanitizeString(city),
      country: inputProtect.sanitizeString(country),
      postal_code: inputProtect.sanitizeString(postal_code || ""),
      state: inputProtect.sanitizeString(state || ""),
    };

    const result = await pool.query(
      `UPDATE users SET address = $1 WHERE id = $2 RETURNING address`,
      [newAddress, userId]
    );

    res.status(201).json({
      message: "Dirección de envío creada correctamente",
      address: result.rows[0].address,
    });
  } catch (err) {
    logger.error("❌ Error creating shipping address:", err.message);
    next(err);
  }
});

// GET /api/user/shipping-address - Obtener la dirección de envío del usuario
router.get("/shipping-address", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(`SELECT address FROM users WHERE id = $1`, [
      userId,
    ]);

    if (!result.rows[0] || !result.rows[0].address) {
      return res.json({ address: null });
    }

    res.json({ address: result.rows[0].address });
  } catch (err) {
    logger.error("❌ Error fetching shipping address:", err.message);
    next(err);
  }
});

// POST - Crear reseña
router.post("/reviews", verifyToken, async (req, res) => {
  try {
    const raw = req.body;
    const orderId = inputProtect.sanitizeNumeric(raw.orderId);
    const rating = inputProtect.sanitizeNumeric(raw.rating);
    const comment = inputProtect.sanitizeServerString(raw.comment || "", {
      maxLen: 1000,
    });
    const userId = req.user.id;

    if (!orderId || !rating || comment.trim() === "") {
      return res.status(400).json({ error: "Faltan campos obligatorios" });
    }

    if (!Number.isInteger(orderId) || orderId <= 0) {
      return res.status(400).json({ error: "orderId inválido" });
    }

    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: "rating debe estar entre 1 y 5" });
    }
    const checkReview = await pool.query(
      "SELECT id FROM reviews WHERE order_id = $1",
      [orderId]
    );
    if (checkReview.rows.length > 0) {
      return res
        .status(400)
        .json({ error: "Ya existe una reseña para este pedido" });
    }

    const checkOrder = await pool.query(
      "SELECT id FROM compras WHERE id = $1 AND user_id = $2",
      [orderId, userId]
    );
    if (checkOrder.rows.length === 0) {
      return res.status(403).json({ error: "No puedes reseñar este pedido" });
    }

    const result = await pool.query(
      `INSERT INTO reviews (user_id, order_id, rating, comment)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [userId, orderId, rating, comment]
    );

    res.json({ success: true, review: result.rows[0] });
  } catch (error) {
    logger.error("Error creando reseña:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// 🔹 Obtener todas las reseñas (para el Home)
router.get("/reviews", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        r.id,
        r.order_id,
        r.user_id,
        r.rating,
        r.comment,
        r.created_at,
        u.name,
        u.email,
        u.phone_number
      FROM reviews r
      INNER JOIN users u ON r.user_id = u.id
      ORDER BY r.created_at DESC LIMIT 20
    `);
    res.json({ reviews: result.rows });
  } catch (error) {
    logger.error("Error obteniendo reseñas:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// 🔹 Verificar si una orden ya tiene reseña
router.get("/reviews/order/:orderId", verifyToken, async (req, res) => {
  try {
    const orderId = parseInt(inputProtect.sanitizeString(req.params.orderId));
    const userId = req.user.id;
    if (!Number.isInteger(orderId) || orderId <= 0) {
      return res.status(400).json({ error: "orderId inválido" });
    }

    const result = await pool.query(
      "SELECT rating, comment FROM reviews WHERE order_id = $1 AND user_id = $2 LIMIT 1",
      [orderId, userId]
    );

    if (result.rows.length > 0) {
      return res.json({
        hasReview: true,
        review: result.rows[0],
      });
    }

    res.json({ hasReview: false });
  } catch (error) {
    logger.error("Error al obtener reseña:", error);
    res.status(500).json({ error: "Error al obtener reseña" });
  }
});

// Cambio de contraseña
router.put("/password", verifyToken, async (req, res) => {
  try {
    const currentPassword = inputProtect.sanitizeString(
      req.body.currentPassword || ""
    );
    const newPassword = inputProtect.sanitizeString(req.body.newPassword || "");
    const userId = req.user.id;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Se requieren la contraseña actual y la nueva contraseña",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: "La nueva contraseña debe tener al menos 8 caracteres",
      });
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?\":{}|<>])/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message:
          "La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial",
      });
    }

    const { rows } = await pool.query(
      "SELECT id, email, password FROM users WHERE id = $1",
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Usuario no encontrado",
      });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password
    );
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "La contraseña actual es incorrecta",
      });
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: "La nueva contraseña debe ser diferente a la actual",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [
      hashedPassword,
      userId,
    ]);

    try {
      await pool.query("UPDATE users SET updated_at = NOW() WHERE id = $1", [
        userId,
      ]);
    } catch (e) {
      logger.warn(
        "Columna updated_at no actualizada (posible ausencia):",
        e.message
      );
    }

    try {
      const ipAddress =
        req.headers["x-forwarded-for"] ||
        req.connection?.remoteAddress ||
        req.ip ||
        null;

      await pool.query(
        `INSERT INTO password_change_log (user_id, changed_at, ip_address)
         VALUES ($1, NOW(), $2)`,
        [userId, ipAddress]
      );
    } catch (auditErr) {
      logger.warn("No se pudo registrar el cambio de contraseña:", auditErr);
    }

    return res.status(200).json({
      success: true,
      message: "Contraseña actualizada exitosamente",
    });
  } catch (error) {
    logger.error("❌ Error al actualizar contraseña:", error);
    return res.status(500).json({
      success: false,
      message: "Error interno del servidor al actualizar la contraseña",
    });
  }
});

export default router;
