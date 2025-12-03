import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import { NODE_ENV } from "../utils/config.js";
import checkAccountLock from "../middleware/checkAccount.js";
import {
  getProfile,
  userLogin,
  updateUserPhone,
  userRegister,
} from "../controllers/authUser.controller.js";

const router = express.Router();

// LOGIN
/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Iniciar sesión con email y contraseña
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: "juan@example.com"
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login exitoso - se establece cookie de sesión
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string, example: "Login exitoso" }
 *                 user:
 *                   type: object
 *                   properties:
 *                     id: { type: integer }
 *                     name: { type: string }
 *                     email: { type: string }
 *                     role: { type: string, enum: [user, admin, viewer] }
 *       401:
 *         description: Credenciales inválidas o intentos agotados
 *       423:
 *         description: Cuenta bloqueada (temporal o permanente)
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - $ref: '#/components/schemas/Error423'
 *                 - type: object
 *                   properties:
 *                     code: { type: string, example: "ACCOUNT_PERMANENTLY_LOCKED" }
 *                     lock_reason: { type: string }
 *                     isPermanent: { type: boolean }
 */
router.post("/login", userLogin);

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: NODE_ENV === "development",
    sameSite: "none",
  });
  res.json({ message: "✅ Logout exitoso" });
});

// PERFIL
/**
 * @swagger
 * /api/auth/profile:
 *   get:
 *     summary: Obtener perfil del usuario autenticado
 *     description: Devuelve datos básicos del usuario logueado
 *     tags: [Autenticación]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Perfil del usuario
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id: { type: integer }
 *                 name: { type: string }
 *                 email: { type: string }
 *                 phone_number: { type: string, nullable: true }
 *                 role: { type: string, enum: [user, admin, viewer] }
 *                 image: { type: string, nullable: true }
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 */
router.get("/profile", verifyToken, checkAccountLock, getProfile);

// REGISTRO
/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Registrar nuevo usuario
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - phone_number
 *               - email
 *               - password
 *             properties:
 *               name: { type: string, example: "Juan Pérez" }
 *               phone_number: { type: string, example: "04129991234" }
 *               email: { type: string, format: email }
 *               password: { type: string, format: password, minLength: 8 }
 *     responses:
 *       201:
 *         description: Usuario creado y sesión iniciada
 *       400:
 *         description: Datos inválidos o email ya registrado
 */
router.post("/register", userRegister);

// ACTUALIZAR TELÉFONO
/**
 * @swagger
 * /api/auth/update-phone:
 *   put:
 *     summary: Actualizar número de teléfono
 *     tags: [Autenticación]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - phone_number
 *             properties:
 *               phone_number:
 *                 type: string
 *                 pattern: ^\d{7,15}$
 *                 example: "04129991234"
 *     responses:
 *       200:
 *         description: Teléfono actualizado
 *       400:
 *         description: Formato de teléfono inválido
 *       401:
 *         $ref: '#/components/schemas/Error401'
 */
router.put("/update-phone", verifyToken, checkAccountLock, updateUserPhone);

export default router;
