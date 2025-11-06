import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import passport from "passport";
import errorHandler from "./backend/utils/errorHandler.js";
import authRoutes from "./backend/routes/auth.js";
import adminRoutes from "./backend/routes/admin.js";
import historyRoutes from "./backend/routes/history.js";
import stripeRoutes from "./backend/routes/stripe.js";
import googleAuthRoutes from "./backend/routes/loginGoogle.js";
import profileRoutes from "./backend/routes/profile.js";
import logger from "./backend/utils/logger.js";
import {
  FRONTEND_URL,
  NODE_ENV,
  STRIPE_PUBLIC_KEY,
  PORTG,
} from "./backend/utils/config.js";

// --- Configuración inicial ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });
const app = express();

// Si el servicio está detrás de un proxy (Render), permite cookies seguras
if (NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        "https://cafearomadelaserrania.onrender.com",
        "http://localhost:5173",
        "http://localhost:3000",
        "https://webaromaserrania.onrender.com",
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("No permitido por CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(cookieParser());

// --- Logger ---
app.use((req, res, next) => {
  logger.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.use("/api", stripeRoutes);

app.use(express.json());
app.use(passport.initialize());
// --- Rutas API ---
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api", historyRoutes);
app.use("/api", googleAuthRoutes);
app.use("/api/user", profileRoutes);

app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// Stripe - Configuración pública
app.get("/api/config", (req, res) => {
  res.json({ publishableKey: STRIPE_PUBLIC_KEY });
});

// Manejo de errores
app.use((err, req, res, next) => {
  logger.error("❌ Server error:", err.message);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Error de Multer: ${err.message}` });
  }
  res.status(500).json({ error: "Error interno del servidor" });
});

app.use((req, res, next) => {
  if (req.url.startsWith("/api/")) {
    return res
      .status(404)
      .json({ error: `Ruta de API no encontrada: ${req.url}` });
  }
  next();
});

app.use(errorHandler);

// --- Iniciar servidor ---
const PORT = PORTG || 3000;
app.listen(PORT, () => {
  logger.log(`🚀 Backend corriendo en puerto ${PORT}`);
  logger.log(`🌐 FRONTEND_URL esperada: ${FRONTEND_URL}`);
});
