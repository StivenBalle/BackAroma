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

// 🔹 NUEVO ENDPOINT: Buscar usuarios (por nombre o email)
router.get("/users", verifyToken, requireAdmin, async (req, res) => {
  try {
    const { search } = req.query;
    let query = `
      SELECT id, name, email, role 
      FROM users 
      WHERE role != 'inactive'  -- Opcional: excluye usuarios inactivos
    `;
    const params = [];

    if (search) {
      query += ` AND (name ILIKE $1 OR email ILIKE $1)`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY name ASC`;
    const result = await pool.query(query, params);
    console.log("Usuarios encontrados:", result.rows.length);
    res.json({ users: result.rows });
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

export default router;
