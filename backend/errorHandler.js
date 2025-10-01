// Middleware de manejo de errores
function errorHandler(err, req, res, next) {
  console.error("❌ Error detectado en backend:");
  console.error("📍 Ruta:", req.method, req.url);
  console.error("📄 Mensaje:", err.message);
  console.error("🧵 Stack:", err.stack);

  res.status(err.status || 500).json({
    error: err.message || "Error interno del servidor",
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
  });
}

export default errorHandler;
