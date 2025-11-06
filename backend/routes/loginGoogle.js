import express from "express";
import { OAuth2Client } from "google-auth-library";
import { generateToken } from "../middleware/jwt.js";
import logger from "../utils/logger.js";
import pool from "../database/db.js";
import { GOOGLE_CLIENT_ID } from "../utils/config.js";

const router = express.Router();
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

router.post("/auth/google", async (req, res) => {
  const { credential, nonce } = req.body;

  if (!credential || !nonce) {
    return res.status(400).json({ error: "Credenciales inválidas." });
  }

  try {
    // ✅ Verificar token de Google
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: google_id, email, picture } = payload;

    // Tomar el nombre antes del '@'
    const name = email.split("@")[0];

    // ✅ Buscar si el usuario ya existe
    let userResult = await pool.query(
      "SELECT * FROM users WHERE google_id = $1 OR email = $2",
      [google_id, email]
    );
    let user = userResult.rows[0];

    if (!user) {
      // ✅ Registrar nuevo usuario Google
      userResult = await pool.query(
        `INSERT INTO users (google_id, email, name, image, role, phone_number, password, auth_provider)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, email, name, image, role, phone_number, auth_provider`,
        [google_id, email, name, picture, "user", null, null, "google"]
      );
      user = userResult.rows[0];
      logger.log("🆕 Usuario Google registrado:", user.email);
    } else {
      // ✅ Actualizar datos si ya existía
      await pool.query(
        `UPDATE users 
         SET google_id = $1, name = $2, image = $3, auth_provider = $4
         WHERE email = $5`,
        [google_id, name, picture, "google", email]
      );

      userResult = await pool.query(
        `SELECT id, email, name, image, role, phone_number, auth_provider 
         FROM users WHERE email = $1`,
        [email]
      );
      user = userResult.rows[0];
      logger.log("🔁 Usuario Google actualizado:", user.email);
    }

    // ✅ Generar token y enviar respuesta
    generateToken(user, res);
    res.json({ message: "✅ Google login exitoso", user });
  } catch (err) {
    logger.error("❌ Error en Google login:", err.message);
    res.status(401).json({ error: "Error al autenticar con Google" });
  }
});

export default router;
