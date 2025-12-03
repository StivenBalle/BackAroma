import express from "express";
import { authUserWithGoogle } from "../controllers/authUser.controller.js";

const router = express.Router();

/**
 * @swagger
 * /api/auth/google:
 *   post:
 *     summary: Iniciar sesión o registrarse con Google
 *     description: Usa Google One Tap o Credential Manager
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - credential
 *               - nonce
 *             properties:
 *               credential: { type: string, description: "ID Token de Google" }
 *               nonce: { type: string }
 *     responses:
 *       200:
 *         description: Autenticación con Google exitosa
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string }
 *                 user:
 *                   type: object
 *                   properties:
 *                     id: { type: integer }
 *                     email: { type: string }
 *                     name: { type: string }
 *                     image: { type: string, format: uri }
 *                     role: { type: string }
 *                     auth_provider: { type: string, example: "google" }
 *       401:
 *         description: Token inválido o expirado
 */
router.post("/auth/google", authUserWithGoogle);

export default router;
