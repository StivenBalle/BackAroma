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

      const cleanEmail = emailClean;
      const cleanPassword = passwordCheck;

      const result = await pool.query(
        "SELECT id, name, email, password, role, login_attempts, locked_until FROM users WHERE email = $1 LIMIT 1",
        [cleanEmail]
      );

      if (result.rows.length === 0) {
        return reject(new Error("Usuario no encontrado"));
      }

      const user = result.rows[0];

      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        const remainingMs = new Date(user.locked_until) - new Date();
        const remainingMin = Math.ceil(remainingMs / 60000);
        return reject(
          new Error(
            `Cuenta bloqueada. Intenta de nuevo en ${remainingMin} min.`
          )
        );
      }

      const match = await bcrypt.compare(cleanPassword, user.password);
      if (!match) {
        const attempts = (user.login_attempts || 0) + 1;
        const lockedUntil =
          attempts >= 5 ? new Date(Date.now() + 15 * 60000) : null;

        await pool.query(
          "UPDATE users SET login_attempts = $1, locked_until = $2 WHERE id = $3",
          [attempts, lockedUntil, user.id]
        );

        logger.warn(
          `Intento fallido de login para ${cleanEmail}. Intentos: ${attempts}`
        );
        return reject(new Error("Contraseña incorrecta"));
      }

      await pool.query(
        "UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = $1",
        [user.id]
      );

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
