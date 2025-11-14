import express from "express";
import { OAuth2Client } from "google-auth-library";
import { generateToken } from "../middleware/jwt.js";
import logger from "../utils/logger.js";
import pool from "../database/db.js";
import { GOOGLE_CLIENT_ID } from "../utils/config.js";
import inputProtect from "../middleware/inputProtect.js";

const router = express.Router();
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

router.post("/auth/google", async (req, res) => {
  try {
    const { credential, nonce } = req.body;

    const cleanCredential = inputProtect.sanitizeString(credential);
    const cleanNonce = inputProtect.sanitizeString(nonce);

    if (!cleanCredential || !cleanNonce) {
      return res.status(400).json({ error: "Credenciales inválidas" });
    }

    const ticket = await client.verifyIdToken({
      idToken: cleanCredential,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: google_id, email, picture } = payload;

    if (!email || !google_id) {
      return res.status(400).json({ error: "Datos del usuario incompletos" });
    }

    const cleanEmail = inputProtect.isValidEmail(email);
    const cleanName = inputProtect.sanitizeString(
      email.split("@")[0].replace(/[^\w\s]/gi, "")
    );
    const cleanPicture = inputProtect.validateUrl(picture)
      ? picture
      : "https://via.placeholder.com/150";

    const userResult = await pool.query(
      "SELECT * FROM users WHERE google_id = $1 OR email = $2 LIMIT 1",
      [google_id, cleanEmail]
    );

    let user = userResult.rows[0];
    if (!user) {
      const insertResult = await pool.query(
        `INSERT INTO users 
          (google_id, email, name, image, role, phone_number, password, auth_provider)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, email, name, image, role, phone_number, auth_provider`,
        [
          google_id,
          cleanEmail,
          cleanName,
          cleanPicture,
          "user",
          null,
          null,
          "google",
        ]
      );
      user = insertResult.rows[0];
      logger.log(`🆕 Usuario Google registrado: ${user.email}`);
    } else {
      await pool.query(
        `UPDATE users 
         SET google_id = $1, name = $2, image = $3, auth_provider = $4
         WHERE email = $5`,
        [google_id, cleanName, cleanPicture, "google", cleanEmail]
      );

      const updatedResult = await pool.query(
        `SELECT id, email, name, image, role, phone_number, auth_provider 
         FROM users WHERE email = $1 LIMIT 1`,
        [cleanEmail]
      );

      user = updatedResult.rows[0];
      logger.log(`🔁 Usuario Google actualizado: ${user.email}`);
    }
    generateToken(user, res);
    res.json({
      message: "✅ Inicio de sesión con Google exitoso",
      user,
    });
  } catch (err) {
    logger.error("❌ Error en autenticación Google:", err.message);
    return res.status(401).json({
      error: "Error al autenticar con Google. Token inválido o expirado.",
    });
  }
});

export default router;
