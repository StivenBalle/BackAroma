import express from "express";
import pool from "../db.js"; // tu conexión a PostgreSQL
import { verifyToken } from "../middleware/jwt.js";

const router = express.Router();

router.get("/historial", verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, producto, precio::float as precio, fecha, status FROM compras WHERE user_id = $1 ORDER BY fecha DESC",
      [req.user.id]
    );
    console.log("Historial enviado:", JSON.stringify(result.rows, null, 2)); // Depuración
    res.json({ compras: result.rows });
  } catch (error) {
    console.error("❌ Error obteniendo historial:", error.message);
    res.status(500).json({ error: "No se pudo obtener el historial" });
  }
});

export default router;
