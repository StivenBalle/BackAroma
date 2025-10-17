import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import pool from "../db.js";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const router = express.Router();

const BASE_URL =
  process.env.NODE_ENV === "production"
    ? "https://backendaromaserrania.onrender.com"
    : "http://localhost:3000";

// Configuración de multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "../../uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${req.user.id}-${Date.now()}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  console.log("📥 Procesando archivo en multer:", file);
  const allowedTypes = ["image/jpeg", "image/png"];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Solo se permiten imágenes JPEG o PNG"), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

// POST /api/user/profile-image - Cargar imagen de perfil
router.post(
  "/profile-image",
  verifyToken,
  upload.single("profileImage"),
  async (req, res, next) => {
    try {
      const userId = req.user.id;
      console.log(
        `📥 POST /api/user/profile-image - userId: ${userId}, file:`,
        req.file
      );

      if (!req.file) {
        return res
          .status(400)
          .json({ error: "No se proporcionó ninguna imagen" });
      }

      const imagePath = `/uploads/${req.file.filename}`;
      const fullImageUrl = `${BASE_URL}${imagePath}`;

      const result = await pool.query(
        `UPDATE users 
         SET image = $1 
         WHERE id = $2 
         RETURNING image`,
        [imagePath, userId]
      );

      console.log("📤 Imagen de perfil cargada:", fullImageUrl);
      res.json({
        message: "Imagen de perfil cargada correctamente",
        image: fullImageUrl, // 👈 Devolvemos la URL completa
      });
    } catch (err) {
      console.error("❌ Error uploading profile image:", err.message);
      next(err);
    }
  }
);

// 🟡 GET /api/user/profile - Obtener datos del perfil
router.get("/profile", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      `SELECT name, email, phone_number, role, image, created_at FROM users WHERE id = $1`,
      [userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];

    // Si el usuario tiene imagen, generar URL completa
    user.image = user.image ? `${BASE_URL}${user.image}` : null;

    res.json(user);
  } catch (err) {
    console.error("❌ Error fetching profile:", err.message);
    next(err);
  }
});

// 🔴 DELETE /api/user/delete-image - Eliminar imagen de perfil
router.delete("/delete-image", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    console.log(`📥 DELETE /api/user/profile-image - userId: ${userId}`);

    // Obtener la ruta de la imagen actual
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
        console.log(`📁 Archivo eliminado: ${filePath}`);
      }
    }

    await pool.query(`UPDATE users SET image = NULL WHERE id = $1`, [userId]);

    res.json({ message: "Imagen de perfil eliminada correctamente" });
  } catch (err) {
    console.error("❌ Error deleting profile image:", err.message);
    next(err);
  }
});

// PUT /api/user/profile - Actualizar datos del perfil
router.put("/update", verifyToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { name, phone } = req.body;
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
    console.error("❌ Error updating profile:", err.message);
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

    // Verificar si el usuario ya tiene una dirección
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

    const newAddress = { line1, city, country, postal_code, state };

    const result = await pool.query(
      `UPDATE users SET address = $1 WHERE id = $2 RETURNING address`,
      [newAddress, userId]
    );

    res.json({
      message: "Dirección de envío actualizada correctamente",
      address: result.rows[0].address,
    });
  } catch (err) {
    console.error("❌ Error updating shipping address:", err.message);
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

    // Verificar si el usuario ya tiene una dirección
    const checkResult = await pool.query(
      `SELECT address FROM users WHERE id = $1`,
      [userId]
    );

    if (checkResult.rows[0] && checkResult.rows[0].address) {
      return res
        .status(400)
        .json({ error: "Ya existe una dirección. Usa PUT para actualizarla." });
    }

    const newAddress = { line1, city, country, postal_code, state };

    const result = await pool.query(
      `UPDATE users SET address = $1 WHERE id = $2 RETURNING address`,
      [newAddress, userId]
    );

    res.status(201).json({
      message: "Dirección de envío creada correctamente",
      address: result.rows[0].address,
    });
  } catch (err) {
    console.error("❌ Error creating shipping address:", err.message);
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
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({ address: result.rows[0].address });
  } catch (err) {
    console.error("❌ Error fetching shipping address:", err.message);
    next(err);
  }
});

export default router;
