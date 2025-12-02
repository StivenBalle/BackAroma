import pool from "../database/db.js";
import logger from "../utils/logger.js";
import inputProtect from "../middleware/inputProtect.js";

export const getUsersSecurity = async (req, res) => {
  try {
    const { search = "", filter = "all", page = 1 } = req.query;

    const limit = 10;
    const offset = (page - 1) * limit;
    const whereConditions = [];

    const params = [`%${search}%`, `%${search}%`];
    let paramIndex = 3;

    // LIMPIEZA AUTOMÁTICA: Limpiar bloqueos temporales expirados
    await pool.query(`
      UPDATE user_security
      SET is_locked = FALSE,
          locked_until = NULL,
          lock_reason = NULL,
          login_attempts = 0,
          updated_at = NOW()
      WHERE is_permanently_locked = FALSE
        AND locked_until IS NOT NULL 
        AND locked_until <= NOW()
    `);

    if (filter === "locked") {
      whereConditions.push(
        `s.is_permanently_locked = FALSE AND (s.is_locked = TRUE OR (s.locked_until IS NOT NULL AND s.locked_until > NOW()))`
      );
    }

    if (filter === "permanent") {
      whereConditions.push(`s.is_permanently_locked = TRUE`);
    }

    if (filter === "suspicious") {
      whereConditions.push(`s.login_attempts >= 2 AND s.login_attempts < 5`);
    }

    const searchCondition = `(u.name ILIKE $1 OR u.email ILIKE $2)`;
    const whereClause =
      whereConditions.length > 0 ? `AND ${whereConditions.join(" AND ")}` : "";

    const query = `
      SELECT 
        u.id,
        u.name,
        u.email,
        u.image,
        COALESCE(s.login_attempts, 0) AS login_attempts,
        COALESCE(s.is_locked, FALSE) AS is_locked,
        COALESCE(s.is_permanently_locked, FALSE) AS is_permanently_locked,
        s.locked_until,
        s.last_failed_login,
        s.lock_reason,
        CASE 
          WHEN s.locked_until > NOW() 
          THEN EXTRACT(EPOCH FROM (s.locked_until - NOW())) / 60
          ELSE 0
        END AS remaining_minutes
      FROM users u
      LEFT JOIN user_security s ON s.user_id = u.id
      WHERE ${searchCondition} ${whereClause}
      ORDER BY 
        s.is_permanently_locked DESC,
        (s.is_locked = TRUE OR s.locked_until > NOW()) DESC,
        s.login_attempts DESC,
        u.name ASC
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;

    params.push(limit, offset);
    const result = await pool.query(query, params);

    const countQuery = await pool.query(
      `SELECT COUNT(*)
       FROM users u
       LEFT JOIN user_security s ON s.user_id = u.id
       WHERE ${searchCondition} ${whereClause}`,
      [`%${search}%`, `%${search}%`]
    );

    const total = parseInt(countQuery.rows[0].count);
    const totalPages = Math.ceil(total / limit);
    const stats = await getStats();

    res.json({
      users: result.rows.map((row) => ({
        ...row,
        remaining_minutes: Math.max(0, Math.ceil(row.remaining_minutes)),
      })),
      stats,
      pagination: {
        page: Number(page),
        totalPages,
        total,
      },
    });
  } catch (err) {
    logger.error("Error getUsersSecurity:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
};

// Estadísticas mejoradas
const getStats = async () => {
  try {
    const result = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM user_security 
         WHERE is_permanently_locked = TRUE) as permanently_locked,
        
        (SELECT COUNT(*) FROM user_security 
         WHERE is_locked = TRUE OR (locked_until IS NOT NULL AND locked_until > NOW())) as locked_accounts,
        
        (SELECT COUNT(*) FROM user_security 
         WHERE login_attempts > 0 AND (is_locked = FALSE OR is_locked IS NULL) 
         AND is_permanently_locked = FALSE) as accounts_with_attempts,
        
        (SELECT COUNT(*) FROM user_security 
         WHERE last_failed_login::date = CURRENT_DATE) as failed_logins_today,
        
        (SELECT COUNT(*) FROM user_security 
         WHERE last_login::date = CURRENT_DATE) as successful_logins_today
    `);

    return {
      permanently_locked: Number(result.rows[0].permanently_locked) || 0,
      locked_accounts: Number(result.rows[0].locked_accounts) || 0,
      accounts_with_attempts:
        Number(result.rows[0].accounts_with_attempts) || 0,
      failed_logins_today: Number(result.rows[0].failed_logins_today) || 0,
      successful_logins_today:
        Number(result.rows[0].successful_logins_today) || 0,
    };
  } catch (err) {
    logger.error("Error en getStats:", err);
    return {
      permanently_locked: 0,
      locked_accounts: 0,
      accounts_with_attempts: 0,
      failed_logins_today: 0,
      successful_logins_today: 0,
    };
  }
};

// 🔒 Bloquear usuario (temporal o permanente)
export const lockUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { duration, reason, permanent = false } = req.body;

    if (!reason || reason.trim().length < 10) {
      return res.status(400).json({
        error: "La razón del bloqueo debe tener al menos 10 caracteres",
      });
    }

    if (permanent) {
      // Bloqueo PERMANENTE
      await pool.query(
        `INSERT INTO user_security (user_id, is_permanently_locked, lock_reason, updated_at)
         VALUES ($1, true, $2, NOW())
         ON CONFLICT (user_id) 
         DO UPDATE SET 
           is_permanently_locked = true,
           lock_reason = $2,
           is_locked = false,
           locked_until = NULL,
           updated_at = NOW()`,
        [id, reason]
      );

      logger.warn(
        `🔒 Usuario ${id} bloqueado PERMANENTEMENTE. Razón: ${reason}`
      );
    } else {
      // Bloqueo TEMPORAL
      const until = new Date(Date.now() + duration * 60000);

      await pool.query(
        `INSERT INTO user_security (user_id, is_locked, locked_until, lock_reason, updated_at)
         VALUES ($1, true, $2, $3, NOW())
         ON CONFLICT (user_id) 
         DO UPDATE SET 
           is_locked = true, 
           locked_until = $2, 
           lock_reason = $3,
           updated_at = NOW()`,
        [id, until, reason]
      );

      logger.warn(
        `⏱️ Usuario ${id} bloqueado por ${duration} minutos. Razón: ${reason}`
      );
    }

    res.json({ success: true, permanent });
  } catch (err) {
    logger.error("Error lockUser:", err);
    res.status(500).json({ error: "Error al bloquear usuario" });
  }
};

// 🔓 Desbloquear usuario (temporal o permanente)
export const unlockUser = async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query(
      `INSERT INTO user_security (user_id, login_attempts, is_locked, locked_until, lock_reason, is_permanently_locked, updated_at)
       VALUES ($1, 0, false, NULL, NULL, false, NOW())
       ON CONFLICT (user_id) 
       DO UPDATE SET 
         login_attempts = 0, 
         is_locked = false, 
         locked_until = NULL, 
         lock_reason = NULL,
         is_permanently_locked = false,
         updated_at = NOW()`,
      [id]
    );

    logger.log(`✅ Usuario ${id} desbloqueado completamente`);
    res.json({ success: true });
  } catch (err) {
    logger.error("Error unlockUser:", err);
    res.status(500).json({ error: "Error al desbloquear" });
  }
};

// Resetear intentos (sin cambiar bloqueos)
export const resetAttempts = async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      `INSERT INTO user_security (user_id, login_attempts, updated_at) 
       VALUES ($1, 0, NOW()) 
       ON CONFLICT (user_id) 
       DO UPDATE SET login_attempts = 0, updated_at = NOW()`,
      [id]
    );
    res.json({ success: true });
  } catch (err) {
    logger.error("Error resetAttempts:", err);
    res.status(500).json({ error: "Error" });
  }
};

export const getSecurityDetails = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await pool.query(
      "SELECT id, name, email FROM users WHERE id = $1",
      [id]
    );
    const sec = await pool.query(
      "SELECT * FROM user_security WHERE user_id = $1",
      [id]
    );

    res.json({
      user: user.rows[0],
      stats: {
        total_failed: sec.rows[0]?.login_attempts || 0,
        failed_today:
          sec.rows[0]?.last_failed_login?.toDateString() ===
          new Date().toDateString()
            ? sec.rows[0].login_attempts
            : 0,
        total_success: 0,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Error" });
  }
};

export const getSecurityStats = async (req, res) => {
  try {
    const stats = await getStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: "Error" });
  }
};

export const exportLogs = async (req, res) => {
  try {
    const logs = await pool.query(`
      SELECT u.name, u.email, s.login_attempts, s.is_locked, s.is_permanently_locked, 
             s.locked_until, s.last_failed_login, s.lock_reason
      FROM user_security s
      JOIN users u ON u.id = s.user_id
      ORDER BY s.is_permanently_locked DESC, s.last_failed_login DESC NULLS LAST
    `);

    let csv =
      "Nombre,Email,Intentos,Bloqueado Temp,Bloqueado Perm,Hasta,Último Fallido,Razón\n";
    logs.rows.forEach((row) => {
      csv += `"${row.name}","${row.email}",${row.login_attempts},${
        row.is_locked ? "Sí" : "No"
      },${row.is_permanently_locked ? "Sí" : "No"},${row.locked_until || ""},${
        row.last_failed_login || ""
      },"${row.lock_reason || ""}"\n`;
    });

    res.header("Content-Type", "text/csv");
    res.attachment("reporte-seguridad.csv");
    res.send(csv);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: "Error" });
  }
};

export const changeRolUser = async (req, res) => {
  try {
    const userId = inputProtect.sanitizeNumeric(req.params.id);
    const newRole = inputProtect.sanitizeString(req.body.role);

    const validRoles = ["user", "admin", "viewer"];
    if (!validRoles.includes(newRole)) {
      return res.status(400).json({ error: "Rol inválido" });
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
};

export const deleteUser = async (req, res) => {
  try {
    const userId = inputProtect.sanitizeNumeric(req.params.id);

    if (userId === req.user.id) {
      return res
        .status(400)
        .json({ error: "No puedes eliminar tu propia cuenta" });
    }

    if (req.user.role !== "admin") {
      return res
        .status(403)
        .json({ message: "Solo administradores pueden eliminar cuentas" });
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
};
