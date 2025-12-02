import pool from "../database/db.js";
import logger from "../utils/logger.js";
import inputProtect from "../middleware/inputProtect.js";

export const getStateOrder = async (req, res) => {
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
};

export const getUsersByMonths = async (req, res) => {
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
};

export const getTopProducts = async (req, res) => {
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
    logger.error("❌ Error al obtener productos más vendidos:", error.message);
    res.status(500).json({ error: "Error al obtener productos más vendidos" });
  }
};

export const getSaleByMonths = async (req, res) => {
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
};
