import pkg from "pg";
import logger from "../utils/logger.js";

const { Pool } = pkg;
import {
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DATABASE_URL,
  DB_PORT,
  DB_NAME,
} from "../utils/config.js";

const pool = new Pool({
  connectionString: DATABASE_URL,
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: false,
});

// Logs de verificación
logger.log("🛠️ Verificando configuración de base de datos:");
logger.log("URL:", DATABASE_URL);
logger.log("Host:", DB_HOST);
logger.log("Puerto:", DB_PORT);
logger.log("Usuario:", DB_USER);
logger.log("Contraseña:", DB_PASSWORD ? "✔️ cargada" : "❌ vacía");
logger.log("Base de datos:", DB_NAME);

// Probar la conexión
(async () => {
  try {
    const client = await pool.connect();
    logger.log("✅ Conexión exitosa a PostgreSQL");
    client.release();
  } catch (err) {
    logger.error("❌ Error al conectar a PostgreSQL:", err.message);
  }
})();

export default pool;
