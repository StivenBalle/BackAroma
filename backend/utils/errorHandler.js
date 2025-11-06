import logger from "./logger.js";

function errorHandler(err, req, res, next) {
  logger.error("❌ Error detectado en backend:");
  logger.error("📍 Ruta:", req.method, req.url);
  logger.error("📄 Mensaje:", err.message);
  logger.error("🧵 Stack:", err.stack);

  res.status(err.status || 500).json({
    error: err.message || "Error interno del servidor",
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
  });
}

export default errorHandler;
