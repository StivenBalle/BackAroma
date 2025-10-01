import express from "express";
import bcrypt from "bcrypt";
import loginUser from "../loginUser.js";
import { generateToken, verifyToken } from "../middleware/jwt.js";
import { NODE_ENV } from "../config.js";
import pool from "../db.js";

const router = express.Router();

// Login route
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ error: "Email y contraseña son obligatorios." });
  }

  try {
    const user = await loginUser(email, password);
    generateToken(user, res);
    res.json({ message: "✅ Login exitoso", user });
  } catch (error) {
    console.error("❌ Error logging in:", error.message);
    res.status(401).json({ error: error.message });
  }
});

// Logout route
router.post("/logout", (req, res) => {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "none",
  });
  res.json({ message: "✅ Logout exitoso" });
});

// En src/backend/routes/auth.js, endpoint /api/auth/profile
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // Del token JWT
    const result = await pool.query(
      "SELECT id, name, email, phone_number, role FROM users WHERE id = $1",
      [userId]
    );
    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }
    console.log("Perfil enviado:", result.rows[0]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ Error fetching profile:", err.message);
    res.status(500).json({ error: "Error al obtener perfil" });
  }
});

// Register route (nueva)
router.post("/register", async (req, res) => {
  const { name, phone_number, email, password } = req.body;

  // Validar campos
  if (!name || !phone_number || !email || !password) {
    return res
      .status(400)
      .json({ error: "Todos los campos son obligatorios." });
  }

  if (!email.includes("@") || password.length < 4) {
    return res.status(400).json({ error: "Email o contraseña inválidos." });
  }

  try {
    // Verificar si el email ya está registrado
    const emailCheck = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (emailCheck.rows.length > 0) {
      return res.status(400).json({ error: "El email ya está registrado." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insertar el nuevo usuario
    const result = await pool.query(
      "INSERT INTO users (name, phone_number, email, password) VALUES ($1, $2, $3, $4) RETURNING id, name, email",
      [name, phone_number, email, hashedPassword]
    );

    const user = result.rows[0];

    // Generar token JWT
    generateToken(user, res);

    res.status(201).json({ message: "✅ Registro exitoso", user });
  } catch (error) {
    console.error("❌ Error en registro:", error.message);
    res.status(500).json({ error: "Error al registrar el usuario" });
  }
});

export default router;
