import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import pool from "../db.js";

const router = express.Router();

// Middleware para verificar admin
const requireAdmin = (req, res, next) => {
  console.log("Usuario en middleware:", req.user);
  if (req.user.role !== "admin") {
    return res
      .status(403)
      .json({ error: "Acceso denegado: Solo administradores" });
  }
  next();
};

router.get("/orders", verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        c.id, c.producto, c.precio::float as precio, c.fecha, c.status, c.phone, 
        c.shipping_address,
        u.name as user_name, u.email as user_email
      FROM compras c
      LEFT JOIN users u ON c.user_id = u.id
      ORDER BY c.fecha DESC
    `);
    console.log("Órdenes enviadas:", JSON.stringify(result.rows, null, 2)); // Depuración
    res.json({ orders: result.rows });
  } catch (error) {
    console.error("❌ Error fetching orders:", error.message);
    res.status(500).json({ error: "Error al cargar órdenes" });
  }
});

export default router;
