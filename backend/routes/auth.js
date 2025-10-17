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
    secure: NODE_ENV === "development",
    sameSite: "none",
  });
  res.json({ message: "✅ Logout exitoso" });
});

// Trae el perfil del usuario
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      "SELECT id, name, email, phone_number, role, image FROM users WHERE id = $1",
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

// Registro de usuario
router.post("/register", async (req, res) => {
  const { name, phone_number, email, password } = req.body;
  if (!name || !phone_number || !email || !password) {
    return res
      .status(400)
      .json({ error: "Todos los campos son obligatorios." });
  }
  if (!email.includes("@") || password.length < 4) {
    return res.status(400).json({ error: "Email o contraseña inválidos." });
  }

  try {
    // Verificar si ya existe un usuario con ese correo
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (existingUser.rows.length > 0)
      return res.status(400).json({ error: "El email ya está registrado." });

    const hashedPassword = await bcrypt.hash(password, 10);
    // Insertar nuevo usuario local
    const result = await pool.query(
      `INSERT INTO users (name, phone_number, email, password, role, auth_provider)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, role`,
      [name, phone_number, email, hashedPassword, "user", "local"]
    );
    const user = result.rows[0];
    generateToken(user, res);
    res.status(201).json({ message: "✅ Registro exitoso", user });
  } catch (error) {
    console.error("❌ Error en registro:", error.message);
    res.status(500).json({ error: "Error al registrar el usuario" });
  }
});

// Nueva ruta para actualizar teléfono
router.put("/update-phone", verifyToken, async (req, res) => {
  const { phone_number } = req.body;
  const userId = req.user.id;

  if (!phone_number || !/^\d{7,15}$/.test(phone_number)) {
    return res
      .status(400)
      .json({ error: "El teléfono debe tener entre 7 y 15 dígitos" });
  }

  try {
    const result = await pool.query(
      "UPDATE users SET phone_number = $1 WHERE id = $2 RETURNING id, name, email, phone_number, role",
      [phone_number, userId]
    );
    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }
    res.json({ message: "✅ Teléfono actualizado", user: result.rows[0] });
  } catch (err) {
    console.error("❌ Error updating phone:", err.message);
    res.status(500).json({ error: "Error al actualizar el teléfono" });
  }
});

export default router;
