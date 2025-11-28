import express from "express";
import pool from "../database/db.js";
import { verifyToken } from "../middleware/jwt.js";
import { requireAdmin, requireAdminOrViewer } from "../middleware/roleCheck.js";
import checkAccountLock from "../middleware/checkAccount.js";

const router = express.Router();

router.get(
  "/",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        level,
        search,
        startDate,
        endDate,
      } = req.query;

      const offset = (page - 1) * limit;

      let whereConditions = [];
      let params = [];
      let paramIndex = 1;

      if (level && level !== "ALL") {
        whereConditions.push(`level = $${paramIndex}`);
        params.push(level);
        paramIndex++;
      }

      if (search) {
        whereConditions.push(`message ILIKE $${paramIndex}`);
        params.push(`%${search}%`);
        paramIndex++;
      }

      if (startDate) {
        whereConditions.push(`created_at >= $${paramIndex}`);
        params.push(startDate);
        paramIndex++;
      }

      if (endDate) {
        whereConditions.push(`created_at <= $${paramIndex}`);
        params.push(endDate);
        paramIndex++;
      }

      const whereClause =
        whereConditions.length > 0
          ? `WHERE ${whereConditions.join(" AND ")}`
          : "";

      const countQuery = `SELECT COUNT(*) FROM system_logs ${whereClause}`;
      const countResult = await pool.query(countQuery, params);
      const total = parseInt(countResult.rows[0].count);

      params.push(limit, offset);
      const logsQuery = `
      SELECT id, level, message, details, created_at
      FROM system_logs
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;

      const logsResult = await pool.query(logsQuery, params);

      res.json({
        logs: logsResult.rows,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / limit),
        },
      });
    } catch (error) {
      console.error("Error obteniendo logs:", error);
      res.status(500).json({ error: "Error al obtener logs" });
    }
  }
);

router.delete(
  "/",
  verifyToken,
  requireAdmin,
  checkAccountLock,
  async (req, res) => {
    try {
      const { days = 30 } = req.query;
      const daysInt = parseInt(days);

      const result = await pool.query(
        `DELETE FROM system_logs 
       WHERE created_at < NOW() - INTERVAL '1 day' * $1
       RETURNING id`,
        [daysInt]
      );

      res.json({
        message: "Logs eliminados correctamente",
        deleted: result.rowCount,
      });
    } catch (error) {
      console.error("Error eliminando logs:", error);
      res.status(500).json({ error: "Error al eliminar logs" });
    }
  }
);

export default router;
