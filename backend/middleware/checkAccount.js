import pool from "../database/db.js";
import logger from "../utils/logger.js";

/**
 * Middleware que verifica si la cuenta del usuario está bloqueada
 * Se ejecuta en CADA petición autenticada
 */
export const checkAccountLock = async (req, res, next) => {
  try {
    if (!req.user || !req.user.id) {
      return next();
    }

    const userId = req.user.id;
    const result = await pool.query(
      `SELECT is_locked, locked_until, lock_reason, is_permanently_locked
       FROM user_security
       WHERE user_id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return next();
    }

    const security = result.rows[0];
    const now = new Date();

    if (security.is_permanently_locked) {
      logger.warn(
        `🚫 Usuario PERMANENTEMENTE bloqueado intentó acceder: ${userId}`
      );

      return res.status(423).json({
        error: "Cuenta bloqueada permanentemente",
        code: "ACCOUNT_PERMANENTLY_LOCKED",
        message:
          security.lock_reason ||
          "Tu cuenta ha sido bloqueada permanentemente. Contacta al administrador.",
        isPermanent: true,
        lock_reason: security.lock_reason,
      });
    }

    const isTemporarilyLocked =
      security.is_locked ||
      (security.locked_until && new Date(security.locked_until) > now);

    if (isTemporarilyLocked) {
      logger.warn(
        `🚫 Usuario temporalmente bloqueado intentó acceder: ${userId}`
      );

      // Calcular tiempo restante si aplica
      let remainingMin = 0;
      if (security.locked_until) {
        const diff = new Date(security.locked_until) - now;
        remainingMin = Math.max(1, Math.ceil(diff / 60000));
      }

      return res.status(423).json({
        error: "Cuenta bloqueada temporalmente",
        code: "ACCOUNT_LOCKED",
        message:
          security.lock_reason || "Tu cuenta ha sido bloqueada temporalmente",
        remainingMin,
        locked_until: security.locked_until,
        isPermanent: false,
        lock_reason: security.lock_reason,
      });
    }

    if (security.locked_until && new Date(security.locked_until) < now) {
      await pool.query(
        `UPDATE user_security 
         SET is_locked = false, 
             locked_until = NULL, 
             lock_reason = NULL,
             login_attempts = 0,
             updated_at = NOW()
         WHERE user_id = $1`,
        [userId]
      );
      logger.log(
        `✅ Bloqueo temporal expirado y limpiado para usuario: ${userId}`
      );
    }

    next();
  } catch (error) {
    logger.error("❌ Error en checkAccountLock:", error);
    next();
  }
};

export default checkAccountLock;
