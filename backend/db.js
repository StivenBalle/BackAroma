import pkg from "pg";
const { Pool } = pkg;
import {
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DATABASE_URL,
  DB_PORT,
  DB_NAME,
} from "./config.js";

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
console.log("🛠️ Verificando configuración de base de datos:");
console.log("URL:", DATABASE_URL);
console.log("Host:", DB_HOST);
console.log("Puerto:", DB_PORT);
console.log("Usuario:", DB_USER);
console.log("Contraseña:", DB_PASSWORD ? "✔️ cargada" : "❌ vacía");
console.log("Base de datos:", DB_NAME);

// Probar la conexión
(async () => {
  try {
    const client = await pool.connect();
    console.log("✅ Conexión exitosa a PostgreSQL");
    client.release();
  } catch (err) {
    console.error("❌ Error al conectar a PostgreSQL:", err.message);
  }
})();

export default pool;
