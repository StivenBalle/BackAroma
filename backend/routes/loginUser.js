import bcrypt from "bcrypt";
import pool from "../database/db.js";
import inputProtect from "../middleware/inputProtect.js";
import logger from "../utils/logger.js";

async function loginUser(email, password) {
  return new Promise(async (resolve, reject) => {
    try {
      const emailClean = inputProtect.validateEmailServer(email);
      const passwordCheck =
        typeof password === "object"
          ? String(password.value || "")
          : typeof password === "string"
          ? password.trim()
          : "";

      if (!emailClean || !emailClean.includes("@")) {
        return reject(new Error("Email inválido"));
      }

      if (!passwordCheck || passwordCheck.length < 4) {
        logger.warn(`❌ Contraseña inválida o vacía: ${passwordCheck}`);
        return reject(new Error("Credenciales inválidas"));
      }

      const result = await pool.query(
        `SELECT 
          u.id, u.name, u.email, u.password, u.role,
          s.login_attempts, s.is_locked, s.locked_until, s.last_failed_login, s.last_login, s.is_permanently_locked, s.lock_reason
        FROM users u
        LEFT JOIN user_security s ON s.user_id = u.id
        WHERE LOWER(u.email) = $1
        LIMIT 1`,
        [emailClean]
      );

      if (result.rows.length === 0) {
        return reject(new Error("Credenciales inválidas"));
      }

      const user = result.rows[0];

      if (user.is_permanently_locked) {
        logger.warn(
          `🚫 Intento de login en cuenta PERMANENTEMENTE bloqueada: ${user.email}`
        );
        return reject({
          code: "ACCOUNT_PERMANENTLY_LOCKED",
          message:
            "Tu cuenta ha sido bloqueada permanentemente. Contacta con el administrador.",
          lock_reason: user.lock_reason,
          isPermanent: true,
        });
      }

      if (!user.login_attempts && user.login_attempts !== 0) {
        await pool.query(
          `INSERT INTO user_security (user_id, login_attempts, is_locked, last_login)
           VALUES ($1, 0, false, NULL)
           ON CONFLICT (user_id) DO NOTHING`,
          [user.id]
        );
        user.login_attempts = 0;
        user.is_locked = false;
        user.locked_until = null;
      }

      const now = new Date();

      if (user.locked_until && new Date(user.locked_until) < now) {
        await pool.query(
          `INSERT INTO user_security (user_id, login_attempts, is_locked, locked_until, lock_reason, last_failed_login)
     VALUES ($1, 0, false, NULL, NULL, NULL)
     ON CONFLICT (user_id) 
     DO UPDATE SET
       login_attempts = 0,
       is_locked = false,
       locked_until = NULL,
       lock_reason = NULL,
       last_failed_login = NULL,
       last_login = NULL,
       updated_at = NOW()`,
          [user.id]
        );

        user.login_attempts = 0;
        user.is_locked = false;
        user.locked_until = null;
        user.lock_reason = null;
        user.last_failed_login = null;
        user.last_login = null;
      }

      if (
        user.is_locked ||
        (user.locked_until && new Date(user.locked_until) > now)
      ) {
        const remainingMin = Math.ceil(
          (new Date(user.locked_until) - now) / 60000
        );
        logger.warn(
          `🚫 Intento de login en cuenta temporalmente bloqueada: ${user.email}`
        );
        return reject({
          code: "ACCOUNT_LOCKED",
          message: `Cuenta bloqueada. Intenta de nuevo en ${remainingMin} minuto${
            remainingMin > 1 ? "s" : ""
          }.`,
          remainingMin: remainingMin > 0 ? remainingMin : 1,
          lockedUntil: user.locked_until,
          lock_reason: user.lock_reason,
          isPermanent: false,
        });
      }
      const match = await bcrypt.compare(passwordCheck, user.password);
      const maxAttempts = 5;

      if (!match) {
        const attempts = (user.login_attempts || 0) + 1;
        const shouldLock = attempts >= maxAttempts;
        const lockedUntil = shouldLock
          ? new Date(Date.now() + 15 * 60 * 1000)
          : null;

        // Actualizar seguridad con upsert (INSERT + UPDATE)
        await pool.query(
          `INSERT INTO user_security (user_id, login_attempts, is_locked, locked_until, last_failed_login, lock_reason, updated_at)
           VALUES ($1, $2, $3, $4, NOW(), $5, NOW())
           ON CONFLICT (user_id) 
           DO UPDATE SET
             login_attempts = EXCLUDED.login_attempts,
             is_locked = EXCLUDED.is_locked,
             locked_until = EXCLUDED.locked_until,
             last_failed_login = EXCLUDED.last_failed_login,
             lock_reason = EXCLUDED.lock_reason,
             updated_at = NOW()`,
          [
            user.id,
            attempts,
            shouldLock,
            lockedUntil,
            shouldLock ? "Demasiados intentos fallidos" : null,
          ]
        );

        if (shouldLock) {
          return reject({
            code: "ACCOUNT_LOCKED",
            message:
              "Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos.",
            attempts,
            maxAttempts,
          });
        }

        const remaining = maxAttempts - attempts;
        return reject({
          code: "INVALID_PASSWORD",
          message: `Contraseña incorrecta. Te quedan ${remaining} intento${
            remaining > 1 ? "s" : ""
          }.`,
          attempts,
          remaining,
          maxAttempts,
        });
      }

      await pool.query(
        `INSERT INTO user_security (user_id, login_attempts, is_locked, locked_until, last_login, updated_at)
         VALUES ($1, 0, false, NULL, NOW(), NOW())
         ON CONFLICT (user_id) 
         DO UPDATE SET
           login_attempts = 0,
           is_locked = false,
           locked_until = NULL,
           last_failed_login = NULL,
           lock_reason = NULL,
           last_login = NOW(),
           updated_at = NOW()`,
        [user.id]
      );

      logger.log(`✅ Login exitoso: ${user.email}`);
      resolve({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      });
    } catch (error) {
      logger.error("❌ Error en loginUser:", error.message || error);
      reject(new Error("Error interno del servidor"));
    }
  });
}

export default loginUser;
