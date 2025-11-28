import pkg from "pg";
import logger, { initializeLogger } from "../utils/logger.js";
import {
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DATABASE_URL,
  DB_PORT,
  DB_NAME,
  NODE_ENV,
} from "../utils/config.js";
import { sanitizeServerString } from "../middleware/inputProtect.js";

const { Pool } = pkg;

const sanitizedConfig = {
  host: sanitizeServerString(DB_HOST),
  port: parseInt(DB_PORT, 10) || 5432,
  user: sanitizeServerString(DB_USER),
  password: sanitizeServerString(DB_PASSWORD),
  database: sanitizeServerString(DB_NAME),
  connectionString: sanitizeServerString(DATABASE_URL || ""),
};

const pool = new Pool({
  connectionString: sanitizedConfig.connectionString || undefined,
  host: sanitizedConfig.host,
  port: sanitizedConfig.port,
  user: sanitizedConfig.user,
  password: sanitizedConfig.password,
  database: sanitizedConfig.database,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

initializeLogger(pool);

logger.log("🛠️ Verificando configuración de base de datos:");
logger.log(`Host: ${DB_HOST}`);
logger.log(`Puerto: ${DB_PORT}`);
logger.log(`Usuario: ${DB_USER}`);
logger.log(`Base de datos: ${DB_NAME}`);
logger.log(
  `Modo: ${
    NODE_ENV === "production" ? "Producción (SSL activo)" : "Desarrollo"
  }`
);

// Función de conexión con reintento automático
async function verifyConnection(retries = 3) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const client = await pool.connect();
      logger.log("✅ Conexión exitosa a PostgreSQL");
      client.release();
      return;
    } catch (err) {
      logger.error(`Intento ${attempt} de conexión fallido: ${err.message}`);
      if (attempt === retries) {
        logger.error("No se pudo establecer conexión a la base de datos.");
        throw err;
      }
      await new Promise((res) => setTimeout(res, 2000));
    }
  }
}

verifyConnection();

export default pool;
