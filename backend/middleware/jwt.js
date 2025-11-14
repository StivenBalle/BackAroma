import jwt from "jsonwebtoken";
import { JWT_SECRET, NODE_ENV } from "../utils/config.js";
import logger from "../utils/logger.js";
import pool from "../database/db.js";
import inputProtect from "../middleware/inputProtect.js";

/**
 * Middleware para verificar y validar el token JWT.
 * Incluye controles contra tokens manipulados o mal formados.
 */
export const verifyToken = async (req, res, next) => {
  try {
    let token =
      req.cookies?.access_token || req.headers.authorization?.split(" ")[1];

    token = inputProtect.sanitizeToken(token);
    logger.log("Token recibido (sanitizado):", token ? "Sí" : "No");

    if (!token) {
      return res.status(401).json({ error: "No autorizado" });
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: "cafe-aroma.com",
      ignoreExpiration: false,
    });

    if (!decoded || !decoded.id || !decoded.email) {
      logger.warn("Token decodificado pero con estructura inválida");
      return res.status(403).json({ error: "Token inválido" });
    }

    const result = await pool.query(
      "SELECT id, email, role FROM users WHERE id = $1",
      [decoded.id]
    );

    if (!result.rows[0]) {
      logger.warn("Usuario no encontrado para el token");
      return res.status(401).json({ error: "Usuario no encontrado" });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    logger.error("❌ Error verifying token:", err.message);

    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Sesión expirada" });
    } else if (err.name === "JsonWebTokenError") {
      return res.status(403).json({ error: "Token manipulado o inválido" });
    }

    return res
      .status(500)
      .json({ error: "Error interno en validación del token" });
  }
};

/**
 * Genera un token JWT seguro y lo envía como cookie HttpOnly.
 */
export function generateToken(user, res) {
  try {
    const payload = {
      id: user.id,
      name: inputProtect.escapeOutput(user.name),
      email: inputProtect.escapeOutput(user.email),
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
    };

    const secret = JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET no está definido");

    const options = {
      expiresIn: "1h",
      issuer: "cafe-aroma.com",
      audience: user.email,
    };

    const token = jwt.sign(payload, secret, options);

    res.cookie("access_token", token, {
      httpOnly: true,
      secure: NODE_ENV === "development",
      sameSite: NODE_ENV === "production" ? "none" : "lax",
      path: "/",
      maxAge: 1000 * 60 * 60,
    });

    return token;
  } catch (error) {
    logger.error("❌ Error generando token:", error.message);
    throw new Error("Error generando token de autenticación");
  }
}
