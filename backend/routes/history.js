import express from "express";
import pool from "../database/db.js";
import { verifyToken } from "../middleware/jwt.js";
import logger from "../utils/logger.js";
import inputProtect from "../middleware/inputProtect.js";
import checkAccountLock from "../middleware/checkAccount.js";

const router = express.Router();

router.get("/historial", verifyToken, checkAccountLock, async (req, res) => {
  try {
    const userId = inputProtect.sanitizeNumeric(req.user.id);

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ error: "ID de usuario inválido" });
    }

    const result = await pool.query(
      `SELECT 
         id, 
         producto, 
         precio::float AS precio, 
         fecha, 
         status 
       FROM compras 
       WHERE user_id = $1 
       ORDER BY fecha DESC`,
      [userId]
    );

    const cleanCompras = result.rows.map((c) => ({
      id: inputProtect.sanitizeNumeric(c.id),
      producto: inputProtect.escapeOutput(c.producto),
      precio: Number(c.precio.toFixed(2)),
      fecha: c.fecha,
      status: inputProtect.escapeOutput(c.status),
    }));

    logger.log(`📦 Historial enviado para user_id=${userId}`);
    res.json({ compras: cleanCompras });
  } catch (error) {
    logger.error("❌ Error obteniendo historial:", error.message);
    res
      .status(500)
      .json({ error: "Error interno del servidor al obtener historial" });
  }
});

export default router;
