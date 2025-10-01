import bcrypt from "bcrypt";
import pool from "./db.js";

async function loginUser(email, password) {
  return new Promise((resolve, reject) => {
    if (!email.includes("@") || password.length < 4) {
      return reject(new Error("Credenciales inválidas"));
    }

    pool.query(
      "SELECT id, name, email, password, role FROM users WHERE email = $1",
      [email],
      async (err, result) => {
        if (err) {
          console.error("❌ Error en consulta de login:", err.message);
          return reject(err);
        }

        if (result.rows.length === 0) {
          return reject(new Error("Usuario no encontrado"));
        }

        try {
          const user = result.rows[0];
          const match = await bcrypt.compare(password, user.password);

          if (!match) {
            return reject(new Error("Contraseña incorrecta"));
          }

          resolve({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
          });
        } catch (error) {
          console.error("❌ Error en bcrypt:", error.message);
          reject(error);
        }
      }
    );
  });
}

export default loginUser;
