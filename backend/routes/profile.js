import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { verifyToken } from "../middleware/jwt.js";
import { fileURLToPath } from "url";
import inputProtect from "../middleware/inputProtect.js";
import checkAccountLock from "../middleware/checkAccount.js";
import {
  changeUserPassword,
  createReviews,
  createUserAddress,
  deleteImageProfile,
  getAllReviewsHome,
  getDataProfile,
  getUserAddress,
  updateDataProfile,
  updateUserAddress,
  uploadImageProfile,
  verifyOrderWithReview,
} from "../controllers/userData.controller.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const router = express.Router();

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
/**
 * @swagger
 * /api/user/profile-image:
 *   post:
 *     summary: Subir imagen de perfil
 *     description: Sube una imagen JPEG/PNG como foto de perfil (máx 5MB aprox)
 *     tags: [Usuario - Perfil]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               profileImage:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Imagen subida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string }
 *                 image: { type: string, format: uri }
 *       400:
 *         description: No se envió archivo o formato inválido
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 */
router.post(
  "/profile-image",
  verifyToken,
  checkAccountLock,
  upload.single("profileImage"),
  uploadImageProfile
);

// GET /api/user/profile - Obtener datos del perfil
/**
 * @swagger
 * /api/user/profile:
 *   get:
 *     summary: Obtener datos del perfil del usuario autenticado
 *     tags: [Usuario - Perfil]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Datos del perfil
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 name: { type: string }
 *                 email: { type: string, format: email }
 *                 phone_number: { type: string, nullable: true }
 *                 role: { type: string, enum: [user, admin, viewer] }
 *                 image: { type: string, nullable: true }
 *                 auth_provider: { type: string, enum: [local, google] }
 *                 address: { type: object, nullable: true }
 *                 created_at: { type: string, format: date-time }
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 */
router.get("/profile", verifyToken, checkAccountLock, getDataProfile);

// DELETE /api/user/delete-image - Eliminar imagen de perfil
/**
 * @swagger
 * /api/user/profile:
 *   get:
 *     summary: Obtener datos del perfil del usuario autenticado
 *     tags: [Usuario - Perfil]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Datos del perfil
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 name: { type: string }
 *                 email: { type: string, format: email }
 *                 phone_number: { type: string, nullable: true }
 *                 role: { type: string, enum: [user, admin, viewer] }
 *                 image: { type: string, nullable: true }
 *                 auth_provider: { type: string, enum: [local, google] }
 *                 address: { type: object, nullable: true }
 *                 created_at: { type: string, format: date-time }
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 */
router.delete(
  "/delete-image",
  verifyToken,
  checkAccountLock,
  deleteImageProfile
);

// PUT /api/user/profile - Actualizar datos del perfil
/**
 * @swagger
 * /api/user/delete-image:
 *   delete:
 *     summary: Eliminar imagen de perfil
 *     tags: [Usuario - Perfil]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Imagen eliminada correctamente
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 */
router.put("/update", verifyToken, checkAccountLock, updateDataProfile);

// PUT /api/user/shipping-address - Actualizar dirección de envío en users
/**
 * @swagger
 * /api/user/shipping-address:
 *   get:
 *     summary: Obtener dirección de envío guardada
 *     tags: [Usuario - Dirección]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Dirección (o null si no existe)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 address:
 *                   type: object
 *                   nullable: true
 *                   properties:
 *                     line1: { type: string }
 *                     city: { type: string }
 *                     country: { type: string }
 *                     postal_code: { type: string, nullable: true }
 *                     state: { type: string, nullable: true }
 */
router.put(
  "/update/shipping-address",
  verifyToken,
  checkAccountLock,
  updateUserAddress
);

// POST /api/user/shipping-address - Crear una nueva dirección de envío
/**
 * @swagger
 * /api/user/add/shipping-address:
 *   post:
 *     summary: Crear nueva dirección de envío (solo si no existe)
 *     tags: [Usuario - Dirección]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - line1
 *               - city
 *               - country
 *             properties:
 *               line1: { type: string }
 *               city: { type: string }
 *               country: { type: string }
 *               postal_code: { type: string }
 *               state: { type: string }
 *     responses:
 *       201:
 *         description: Dirección creada
 *       400:
 *         description: Ya existe dirección (usa PUT para actualizar)
 */
router.post(
  "/add/shipping-address",
  verifyToken,
  checkAccountLock,
  createUserAddress
);

// GET /api/user/shipping-address - Obtener la dirección de envío del usuario
/**
 * @swagger
 * /api/user/update/shipping-address:
 *   put:
 *     summary: Actualizar dirección de envío existente
 *     tags: [Usuario - Dirección]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - line1
 *               - city
 *               - country
 *             properties:
 *               line1: { type: string }
 *               city: { type: string }
 *               country: { type: string }
 *               postal_code: { type: string }
 *               state: { type: string }
 *     responses:
 *       200:
 *         description: Dirección actualizada
 *       400:
 *         description: No existe dirección para actualizar (usa POST primero)
 */
router.get("/shipping-address", verifyToken, checkAccountLock, getUserAddress);

// POST - Crear reseña
/**
 * @swagger
 * /api/user/password:
 *   put:
 *     summary: Cambiar contraseña del usuario
 *     description: |
 *       Requiere contraseña actual.
 *       Nueva contraseña debe tener: 8+ caracteres, mayúscula, minúscula, número y símbolo.
 *       Se registra en log de auditoría.
 *     tags: [Usuario - Seguridad]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword: { type: string, format: password }
 *               newPassword: { type: string, format: password }
 *     responses:
 *       200:
 *         description: Contraseña cambiada exitosamente
 *       400:
 *         description: Contraseña débil o igual a la anterior
 *       401:
 *         description: Contraseña actual incorrecta
 */
router.post("/reviews", verifyToken, checkAccountLock, createReviews);

// Obtener todas las reseñas (para el Home)
/**
 * @swagger
 * /api/user/reviews/order/{orderId}:
 *   get:
 *     summary: Verificar si una orden ya tiene reseña
 *     tags: [Usuario - Reseñas]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: orderId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Estado de la reseña
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hasReview: { type: boolean }
 *                 review: { type: object, nullable: true }
 */
router.get("/reviews", getAllReviewsHome);

// Verificar si una orden ya tiene reseña
/**
 * @swagger
 * /api/user/reviews/order/{orderId}:
 *   get:
 *     summary: Verificar si una orden ya tiene reseña
 *     tags: [Usuario - Reseñas]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: orderId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Estado de la reseña
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hasReview: { type: boolean }
 *                 review: { type: object, nullable: true }
 */
router.get(
  "/reviews/order/:orderId",
  verifyToken,
  checkAccountLock,
  verifyOrderWithReview
);

// Cambio de contraseña
/**
 * @swagger
 * /api/user/password:
 *   put:
 *     summary: Cambiar contraseña del usuario
 *     description: |
 *       Requiere contraseña actual.
 *       Nueva contraseña debe tener: 8+ caracteres, mayúscula, minúscula, número y símbolo.
 *       Se registra en log de auditoría.
 *     tags: [Usuario - Seguridad]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword: { type: string, format: password }
 *               newPassword: { type: string, format: password }
 *     responses:
 *       200:
 *         description: Contraseña cambiada exitosamente
 *       400:
 *         description: Contraseña débil o igual a la anterior
 *       401:
 *         description: Contraseña actual incorrecta
 */
router.put("/password", verifyToken, checkAccountLock, changeUserPassword);

export default router;
