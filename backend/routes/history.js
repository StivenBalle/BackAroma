import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import checkAccountLock from "../middleware/checkAccount.js";
import { getHistorial } from "../controllers/userData.controller.js";

const router = express.Router();

/**
 * @swagger
 * /api/user/historial:
 *   get:
 *     summary: Historial de compras del usuario
 *     tags: [Usuario - Compras]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Lista de compras del usuario
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 compras:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id: { type: integer }
 *                       producto: { type: string }
 *                       precio: { type: number }
 *                       fecha: { type: string, format: date-time }
 *                       status: { type: string }
 */
router.get("/historial", verifyToken, checkAccountLock, getHistorial);

export default router;
