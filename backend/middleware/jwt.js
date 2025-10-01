import jwt from "jsonwebtoken";
import { JWT_SECRET, NODE_ENV } from "../config.js";
import pool from "../db.js";

export const verifyToken = async (req, res, next) => {
  const token =
    req.cookies.access_token || req.headers.authorization?.split(" ")[1];
  console.log("Token recibido:", token);
  if (!token) {
    return res.status(401).json({ error: "No autorizado" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("Decoded token:", decoded); // Depuración
    const result = await pool.query(
      "SELECT id, email, role FROM users WHERE id = $1",
      [decoded.id]
    );
    if (!result.rows[0]) {
      return res.status(401).json({ error: "Usuario no encontrado" });
    }
    req.user = result.rows[0]; // Incluye id, email, role
    next();
  } catch (err) {
    console.error("❌ Error verifying token:", err.message);
    return res.status(403).json({ error: "Token inválido" });
  }
};

export function generateToken(user, res) {
  const payload = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };

  const secret = JWT_SECRET;
  if (!secret)
    throw new Error("JWT_SECRET no está definido en variables de entorno");

  const options = {
    expiresIn: "1h",
    issuer: "cafe-aroma.com",
    audience: user.email,
  };

  const token = jwt.sign(payload, secret, options);

  // Guardar en cookie HTTP-only
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "none",
    maxAge: 1000 * 60 * 60,
  });

  return token;
}
