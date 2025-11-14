import express from "express";
import bcrypt from "bcrypt";
import loginUser from "../routes/loginUser.js";
import { generateToken, verifyToken } from "../middleware/jwt.js";
import logger from "../utils/logger.js";
import { NODE_ENV } from "../utils/config.js";
import pool from "../database/db.js";
import inputProtect from "../middleware/inputProtect.js";

const router = express.Router();

// LOGIN
router.post("/login", async (req, res) => {
  let { email, password } = req.body;

  email = inputProtect.validateEmailServer(email);
  password = inputProtect.validatePasswordServer(password);

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
    logger.error("❌ Error logging in:", error);
    res.status(401).json({ error: "Credenciales inválidas" });
  }
});

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: NODE_ENV === "development",
    sameSite: "none",
  });
  res.json({ message: "✅ Logout exitoso" });
});

// PERFIL
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const userId = inputProtect.sanitizeNumeric(req.user.id);

    const result = await pool.query(
      "SELECT id, name, email, phone_number, role, image FROM users WHERE id = $1",
      [userId]
    );
    if (!result.rows[0]) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const cleanUser = {
      id: result.rows[0].id,
      name: inputProtect.escapeOutput(result.rows[0].name),
      email: inputProtect.escapeOutput(result.rows[0].email),
      phone_number: result.rows[0].phone_number,
      role: result.rows[0].role,
      image: result.rows[0].image,
    };

    logger.log(`Perfil enviado: ${cleanUser.email}`);
    res.json(cleanUser);
  } catch (err) {
    logger.error("❌ Error fetching profile:", err.message);
    res.status(500).json({ error: "Error al obtener perfil" });
  }
});

// REGISTRO
router.post("/register", async (req, res) => {
  const data = inputProtect.sanitizeObjectRecursivelyServer(req.body);
  inputProtect.preventSQLInjection(data.email);

  let { name, phone_number, email, password } = req.body;

  // Sanitización y validación
  name = inputProtect.sanitizeServerString(name);
  phone_number = inputProtect.sanitizeNumeric(phone_number);
  const isEmailValid = inputProtect.validateEmailServer(email);
  const passwordCheck = inputProtect.validatePasswordServer(password);

  // Verifica estructura de passwordCheck
  if (!passwordCheck.ok) {
    return res.status(400).json({ error: passwordCheck.reason });
  }
  const cleanPassword = passwordCheck.value || password.trim();

  if (!name || !phone_number || !isEmailValid) {
    return res
      .status(400)
      .json({ error: "Todos los campos son obligatorios." });
  }

  if (!name || !phone_number || !email || !password) {
    return res
      .status(400)
      .json({ error: "Todos los campos son obligatorios." });
  }
  if (!email.includes("@") || password.length < 8) {
    return res.status(400).json({
      error:
        "Email inválido o contraseña demasiado corta (mínimo 8 caracteres).",
    });
  }

  try {
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );
    if (existingUser.rows.length > 0)
      return res.status(400).json({ error: "El email ya está registrado." });

    const hashedPassword = await bcrypt.hash(cleanPassword, 12);

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
    logger.error("❌ Error en registro:", error.message);
    res.status(500).json({ error: "Error al registrar el usuario" });
  }
});

// ACTUALIZAR TELÉFONO
router.put("/update-phone", verifyToken, async (req, res) => {
  const rawPhone = req.body.phone_number;
  const userId = inputProtect.sanitizeNumeric(req.user.id);
  const phone_number = inputProtect.sanitizeNumeric(rawPhone);

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

    const user = result.rows[0];
    user.name = inputProtect.escapeOutput(user.name);
    user.email = inputProtect.escapeOutput(user.email);

    res.json({ message: "✅ Teléfono actualizado", user });
  } catch (err) {
    logger.error("❌ Error updating phone:", err.message);
    res.status(500).json({ error: "Error al actualizar el teléfono" });
  }
});

export default router;
