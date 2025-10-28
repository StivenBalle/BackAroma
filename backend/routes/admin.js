import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import pool from "../db.js";

const router = express.Router();

const BASE_URL =
  process.env.NODE_ENV === "production"
    ? "https://backendaromaserrania.onrender.com"
    : "http://localhost:3000";

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

// 🔹 NUEVO ENDPOINT: Buscar usuarios (por nombre o email)
router.get("/users", verifyToken, requireAdmin, async (req, res) => {
  try {
    const { search } = req.query;
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
      image: user.image
        ? user.image.startsWith("http://") || user.image.startsWith("https://")
          ? user.image
          : `${BASE_URL}${user.image}`
        : null,
    }));

    console.log("Usuarios encontrados:", result.rows.length);
    res.json({ users });
  } catch (error) {
    console.error("❌ Error fetching users:", error.message);
    res.status(500).json({ error: "Error al buscar usuarios" });
  }
});

// 🔹 NUEVO ENDPOINT: Eliminar usuario
router.delete("/users/:id", verifyToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = parseInt(id);

    // Verificar que no sea el admin actual
    if (userId === req.user.id) {
      return res
        .status(400)
        .json({ error: "No puedes eliminar tu propia cuenta" });
    }

    // Opcional: Verificar si es el último admin (para no dejar la app sin admins)
    const adminCount = await pool.query(
      "SELECT COUNT(*) FROM users WHERE role = 'admin'"
    );
    const isLastAdmin =
      adminCount.rows[0].count === "1" && req.user.role === "admin";
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

    console.log("Usuario eliminado:", userId);
    res.json({ success: true });
  } catch (error) {
    console.error("❌ Error deleting user:", error.message);
    res.status(500).json({ error: "Error al eliminar usuario" });
  }
});

// 🔹 NUEVO ENDPOINT: Cambiar rol de usuario
router.put("/users/:id/role", verifyToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { role: newRole } = req.body;
    const userId = parseInt(id);

    // Validaciones
    if (!["admin", "user"].includes(newRole)) {
      return res
        .status(400)
        .json({ error: "Rol inválido. Debe ser 'admin' o 'user'" });
    }

    if (userId === req.user.id) {
      return res.status(400).json({ error: "No puedes cambiar tu propio rol" });
    }

    // Opcional: Si cambias a admin, verifica si ya hay muchos admins (límite arbitrario)
    if (newRole === "admin") {
      const adminCount = await pool.query(
        "SELECT COUNT(*) FROM users WHERE role = 'admin'"
      );
      if (parseInt(adminCount.rows[0].count) >= 5) {
        // Ejemplo: límite de 5 admins
        return res
          .status(400)
          .json({ error: "Límite de administradores alcanzado" });
      }
    }

    const result = await pool.query(
      "UPDATE users SET role = $1 WHERE id = $2 RETURNING id, name, email, role",
      [newRole, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    console.log("Rol cambiado para usuario:", userId, "Nuevo rol:", newRole);
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error("❌ Error updating user role:", error.message);
    res.status(500).json({ error: "Error al cambiar rol" });
  }
});

// Compras por mes
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
      console.error("Error al obtener ventas por mes:", error);
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
        producto, 
        COUNT(*) AS cantidad_vendida,
        SUM(precio) AS total_ventas
      FROM compras
      GROUP BY producto
      ORDER BY cantidad_vendida DESC
      LIMIT 5;
    `);
      res.json(result.rows);
    } catch (error) {
      console.error("Error al obtener productos más vendidos:", error);
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
      console.error("Error al obtener usuarios por mes:", error);
      res.status(500).json({ error: "Error al obtener usuarios por mes" });
    }
  }
);

export default router;
