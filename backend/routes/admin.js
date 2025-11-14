import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import logger from "../utils/logger.js";
import pool from "../database/db.js";
import inputProtect from "../middleware/inputProtect.js";

const router = express.Router();

const BASE_URL =
  process.env.NODE_ENV === "production"
    ? "https://backendaromaserrania.onrender.com"
    : "http://localhost:3000";

// Middleware para verificar admin
const requireAdmin = (req, res, next) => {
  try {
    logger.log("Verificando rol:", req.user);
    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Acceso denegado: Solo administradores" });
    }
    next();
  } catch (err) {
    logger.error("❌ Error en requireAdmin:", err.message);
    res.status(500).json({ error: "Error interno en verificación de rol" });
  }
};

// Obtener todas las órdenes
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

    res.json({ orders: result.rows });
  } catch (error) {
    logger.error("❌ Error fetching orders:", error.message);
    res.status(500).json({ error: "Error al cargar órdenes" });
  }
});

// Buscar usuarios (por nombre o email)
router.get("/users", verifyToken, requireAdmin, async (req, res) => {
  try {
    let { search } = req.query;
    search = inputProtect.sanitizeString(search);

    let query = `
      SELECT id, name, email, role, image
      FROM users 
      WHERE role != 'inactive'
    `;
    const params = [];

    if (search) {
      query += ` AND (name ILIKE $1 OR email ILIKE $1)`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY name ASC`;
    const result = await pool.query(query, params);

    const users = result.rows.map((user) => ({
      ...user,
      name: inputProtect.escapeOutput(user.name),
      email: inputProtect.escapeOutput(user.email),
      image: user.image
        ? user.image.startsWith("http")
          ? user.image
          : `${BASE_URL}${user.image}`
        : null,
    }));

    res.json({ users });
  } catch (error) {
    logger.error("❌ Error fetching users:", error.message);
    res.status(500).json({ error: "Error al buscar usuarios" });
  }
});

// Eliminar usuario
router.delete("/users/:id", verifyToken, requireAdmin, async (req, res) => {
  try {
    const userId = inputProtect.sanitizeNumeric(req.params.id);

    if (userId === req.user.id) {
      return res
        .status(400)
        .json({ error: "No puedes eliminar tu propia cuenta" });
    }

    const adminCountResult = await pool.query(
      "SELECT COUNT(*) FROM users WHERE role = 'admin'"
    );
    const adminCount = parseInt(adminCountResult.rows[0].count, 10);

    const deletingUser = await pool.query(
      "SELECT role FROM users WHERE id = $1",
      [userId]
    );
    const deletingRole = deletingUser.rows[0]?.role;

    const isLastAdmin =
      deletingRole === "admin" && adminCount === 1 && req.user.role === "admin";

    if (isLastAdmin) {
      return res
        .status(400)
        .json({ error: "No puedes eliminar el último administrador" });
    }

    const result = await pool.query(
      "DELETE FROM users WHERE id = $1 RETURNING id",
      [userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    logger.log("✅ Usuario eliminado:", userId);
    res.json({ success: true });
  } catch (error) {
    logger.error("❌ Error deleting user:", error.message);
    res.status(500).json({ error: "Error al eliminar usuario" });
  }
});

// Perfil completo del usuario
router.get("/users/:userId", verifyToken, requireAdmin, async (req, res) => {
  try {
    const userId = inputProtect.sanitizeNumeric(req.params.userId);

    const result = await pool.query(
      `SELECT id, name, email, phone_number, role, image, auth_provider, address, created_at 
       FROM users WHERE id = $1`,
      [userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];
    user.name = inputProtect.escapeOutput(user.name);
    user.email = inputProtect.escapeOutput(user.email);

    if (user.image && !user.image.startsWith("http")) {
      user.image = `${BASE_URL}${user.image}`;
    }

    res.json(user);
  } catch (err) {
    logger.error("❌ Error fetching user profile:", err.message);
    res.status(500).json({ error: "Error al obtener perfil del usuario" });
  }
});

// Historial de compras de un usuario
router.get(
  "/users/:userId/historial",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const userId = inputProtect.sanitizeNumeric(req.params.userId);

      const result = await pool.query(
        `SELECT 
          c.id, c.producto, c.precio::float as precio, c.fecha, c.status, c.shipping_address
         FROM compras c
         WHERE c.user_id = $1
         ORDER BY c.fecha DESC`,
        [userId]
      );

      res.json({ compras: result.rows });
    } catch (err) {
      logger.error("❌ Error fetching user purchase history:", err.message);
      res.status(500).json({ error: "Error al obtener historial de usuario" });
    }
  }
);

// Cambiar rol de usuario
router.put("/users/:id/role", verifyToken, requireAdmin, async (req, res) => {
  try {
    const userId = inputProtect.sanitizeNumeric(req.params.id);
    const newRole = inputProtect.sanitizeString(req.body.role);

    if (!["admin", "user"].includes(newRole)) {
      return res
        .status(400)
        .json({ error: "Rol inválido. Debe ser 'admin' o 'user'" });
    }

    if (userId === req.user.id) {
      return res.status(400).json({ error: "No puedes cambiar tu propio rol" });
    }

    const result = await pool.query(
      "UPDATE users SET role = $1 WHERE id = $2 RETURNING id, name, email, role",
      [newRole, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    logger.error("❌ Error updating user role:", error.message);
    res.status(500).json({ error: "Error al cambiar rol" });
  }
});

// Ventas por mes
router.get(
  "/stats/sales-by-month",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT 
          TO_CHAR(fecha, 'YYYY-MM') AS mes,
          COUNT(*) AS total_compras,
          SUM(precio) AS total_ventas
        FROM compras
        GROUP BY mes
        ORDER BY mes ASC;
      `);
      res.json(result.rows);
    } catch (error) {
      logger.error("❌ Error al obtener ventas por mes:", error.message);
      res.status(500).json({ error: "Error al obtener ventas por mes" });
    }
  }
);

// Productos más vendidos
router.get(
  "/stats/top-products",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT 
          producto, COUNT(*) AS cantidad_vendida, SUM(precio) AS total_ventas
        FROM compras
        GROUP BY producto
        ORDER BY cantidad_vendida DESC
        LIMIT 5;
      `);
      res.json(result.rows);
    } catch (error) {
      logger.error(
        "❌ Error al obtener productos más vendidos:",
        error.message
      );
      res
        .status(500)
        .json({ error: "Error al obtener productos más vendidos" });
    }
  }
);

// Usuarios registrados por mes
router.get(
  "/stats/users-by-month",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT 
          TO_CHAR(created_at, 'YYYY-MM') AS mes,
          COUNT(*) AS nuevos_usuarios
        FROM users
        GROUP BY mes
        ORDER BY mes ASC;
      `);
      res.json(result.rows);
    } catch (error) {
      logger.error("❌ Error al obtener usuarios por mes:", error.message);
      res.status(500).json({ error: "Error al obtener usuarios por mes" });
    }
  }
);

// Cambiar estado de orden
router.patch(
  "/change-order/:id/status",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const id = inputProtect.sanitizeNumeric(req.params.id);
      const status = inputProtect.sanitizeString(req.body.status);

      const validStatuses = [
        "pendiente",
        "procesando",
        "enviado",
        "completado",
        "cancelado",
      ];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: "Estado no válido" });
      }

      const result = await pool.query(
        "UPDATE compras SET status = $1 WHERE id = $2",
        [status, id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({ error: "Pedido no encontrado" });
      }

      res.json({ success: true, status });
    } catch (error) {
      logger.error("❌ Error actualizando estado:", error.message);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);

export default router;
