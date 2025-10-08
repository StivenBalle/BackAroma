import express from "express";
import { OAuth2Client } from "google-auth-library";
import { generateToken } from "../middleware/jwt.js";
import pool from "../db.js";
import { GOOGLE_CLIENT_ID } from "../config.js";

const router = express.Router();
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

router.post("/auth/google", async (req, res) => {
  const { credential } = req.body;

  if (!credential) {
    return res.status(400).json({ error: "Credencial de Google requerida" });
  }

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: google_id, email, name } = payload;

    let userResult = await pool.query(
      "SELECT * FROM users WHERE google_id = $1 OR email = $2",
      [google_id, email]
    );
    let user = userResult.rows[0];

    if (!user) {
      userResult = await pool.query(
        `INSERT INTO users (google_id, email, name, role, phone_number)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, name, role, phone_number`,
        [google_id, email, name, "user", null]
      );
      user = userResult.rows[0];
    } else {
      await pool.query(
        `UPDATE users SET google_id = $1, name = $2 WHERE email = $3`,
        [google_id, name, email]
      );
      userResult = await pool.query(
        `SELECT id, email, name, role, phone_number FROM users WHERE email = $1`,
        [email]
      );
      user = userResult.rows[0];
    }

    generateToken(user, res);
    res.json({ message: "✅ Google login exitoso", user });
  } catch (err) {
    console.error("❌ Error en Google login:", err.message);
    res.status(401).json({ error: "Error al autenticar con Google" });
  }
});

export default router;
