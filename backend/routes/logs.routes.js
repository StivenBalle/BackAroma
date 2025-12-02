import express from "express";
import pool from "../database/db.js";
import { verifyToken } from "../middleware/jwt.js";
import { requireAdmin, requireAdminOrViewer } from "../middleware/roleCheck.js";
import checkAccountLock from "../middleware/checkAccount.js";
import logger from "../utils/logger.js";

const router = express.Router();

// GET /api/logs - Obtener logs con paginación del servidor
router.get(
  "/",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 15,
        level,
        search,
        startDate,
        endDate,
      } = req.query;

      const pageNum = Math.max(1, parseInt(page) || 1);
      const limitNum = Math.min(100, Math.max(1, parseInt(limit) || 15));
      const offset = (pageNum - 1) * limitNum;

      // Construir condiciones WHERE dinámicamente
      let whereConditions = [];
      let params = [];
      let paramIndex = 1;

      // Filtro por nivel
      if (level && level !== "ALL") {
        whereConditions.push(`level = $${paramIndex}`);
        params.push(level);
        paramIndex++;
      }

      // Búsqueda en mensaje y detalles
      if (search && search.trim()) {
        whereConditions.push(
          `(message ILIKE $${paramIndex} OR details::text ILIKE $${paramIndex})`
        );
        params.push(`%${search.trim()}%`);
        paramIndex++;
      }

      // Filtro por fecha de inicio
      if (startDate) {
        whereConditions.push(`created_at >= $${paramIndex}`);
        params.push(startDate);
        paramIndex++;
      }

      // Filtro por fecha de fin
      if (endDate) {
        whereConditions.push(`created_at <= $${paramIndex}`);
        params.push(endDate);
        paramIndex++;
      }

      const whereClause =
        whereConditions.length > 0
          ? `WHERE ${whereConditions.join(" AND ")}`
          : "";

      // 1. Obtener total de registros (para paginación)
      const countQuery = `SELECT COUNT(*) FROM system_logs ${whereClause}`;
      const countResult = await pool.query(countQuery, params);
      const total = parseInt(countResult.rows[0].count);

      // 2. Obtener logs paginados
      const paramsWithPagination = [...params, limitNum, offset];
      const logsQuery = `
        SELECT 
          id, 
          level, 
          message, 
          details, 
          created_at
        FROM system_logs
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
      `;

      const logsResult = await pool.query(logsQuery, paramsWithPagination);

      // 3. Obtener estadísticas generales (sin paginación)
      const statsQuery = `
        SELECT 
          COUNT(*) FILTER (WHERE level = 'ERROR') as total_errors,
          COUNT(*) FILTER (WHERE level = 'WARNING') as total_warnings,
          COUNT(*) FILTER (WHERE level = 'INFO') as total_info,
          COUNT(*) as total_logs
        FROM system_logs
      `;
      const statsResult = await pool.query(statsQuery);
      const stats = statsResult.rows[0];

      // Calcular total de páginas
      const totalPages = Math.ceil(total / limitNum);

      logger.log(`📊 Logs consultados: página ${pageNum}/${totalPages}`);

      res.json({
        success: true,
        logs: logsResult.rows,
        pagination: {
          total,
          page: pageNum,
          limit: limitNum,
          totalPages,
          hasNextPage: pageNum < totalPages,
          hasPreviousPage: pageNum > 1,
        },
        stats: {
          total_errors: parseInt(stats.total_errors || 0),
          total_warnings: parseInt(stats.total_warnings || 0),
          total_info: parseInt(stats.total_info || 0),
          total_logs: parseInt(stats.total_logs || 0),
        },
      });
    } catch (error) {
      logger.error("❌ Error obteniendo logs:", error);
      res.status(500).json({
        success: false,
        error: "Error al obtener logs",
      });
    }
  }
);

// DELETE /api/logs - Eliminar logs antiguos
router.delete(
  "/",
  verifyToken,
  requireAdmin,
  checkAccountLock,
  async (req, res) => {
    try {
      const { days = 30 } = req.query;
      const daysInt = Math.max(1, parseInt(days) || 30);

      const result = await pool.query(
        `DELETE FROM system_logs 
         WHERE created_at < NOW() - INTERVAL '1 day' * $1
         RETURNING id`,
        [daysInt]
      );

      logger.log(
        `🧹 Eliminados ${result.rowCount} logs de hace más de ${daysInt} días`
      );

      res.json({
        success: true,
        message: `Logs eliminados correctamente`,
        deleted: result.rowCount,
        days: daysInt,
      });
    } catch (error) {
      logger.error("❌ Error eliminando logs:", error);
      res.status(500).json({
        success: false,
        error: "Error al eliminar logs",
      });
    }
  }
);

export default router;
