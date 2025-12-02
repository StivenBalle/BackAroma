import pool from "../database/db.js";
import logger from "../utils/logger.js";
import bcrypt from "bcrypt";
import path from "path";
import fs from "fs";
import { OAuth2Client } from "google-auth-library";
import { generateToken } from "../middleware/jwt.js";
import { GOOGLE_CLIENT_ID } from "../utils/config.js";
import inputProtect from "../middleware/inputProtect.js";
import loginUser from "../routes/loginUser.js";

const client = new OAuth2Client(GOOGLE_CLIENT_ID);

export const authUserWithGoogle = async (req, res) => {
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
};

export const userLogin = async (req, res) => {
  let { email, password } = req.body;

  email = inputProtect.validateEmailServer(email);
  password = typeof password === "string" ? password.trim() : "";

  if (!email || !password || password.length < 1) {
    return res
      .status(400)
      .json({ error: "Email y contraseña son obligatorios." });
  }

  try {
    const user = await loginUser(email, password);
    generateToken(user, res);
    return res.json({
      message: "Login exitoso",
      user,
    });
  } catch (error) {
    logger.warn("❌ Error logging in:", error);

    if (error.code === "ACCOUNT_PERMANENTLY_LOCKED") {
      return res.status(423).json({
        error: error.message || "Cuenta bloqueada permanentemente",
        code: error.code,
        lock_reason: error.lock_reason,
        isPermanent: true,
      });
    }

    if (error.code === "ACCOUNT_LOCKED") {
      return res.status(423).json({
        error: error.message || "Cuenta bloqueada",
        code: error.code,
        remainingMin: error.remainingMin || 15,
        lockedUntil: error.lockedUntil,
      });
    }

    if (error.code === "INVALID_PASSWORD") {
      return res.status(401).json({
        error: error.message,
        code: error.code,
        attempts: error.attempts,
        remaining: error.remaining,
        maxAttempts: error.maxAttempts || 5,
      });
    }

    return res.status(401).json({
      error: error.message || "Credenciales inválidas",
    });
  }
};

export const getProfile = async (req, res) => {
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
};

export const userRegister = async (req, res) => {
  const data = inputProtect.sanitizeObjectRecursivelyServer(req.body);
  inputProtect.preventSQLInjection(data.email);

  let { name, phone_number, email, password } = req.body;
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
};

export const updateUserPhone = async (req, res) => {
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
};
