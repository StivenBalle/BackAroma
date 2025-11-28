import { NODE_ENV } from "../utils/config.js";

const isDev = NODE_ENV === "development";
const isProd = NODE_ENV === "production";

let logQueue = [];
let isProcessing = false;
let poolInstance = null;

const LOG_LEVELS = {
  log: "INFO",
  warn: "WARNING",
  error: "ERROR",
};

export function initializeLogger(pool) {
  if (!pool) {
    console.error("Logger: pool no proporcionado en initializeLogger()");
    return;
  }
  poolInstance = pool;
  console.log("Logger inicializado correctamente con conexión a DB");
}

// Procesar cola de logs
async function processQueue() {
  if (isProcessing || logQueue.length === 0 || !poolInstance) return;

  isProcessing = true;
  const batch = logQueue.splice(0);

  try {
    if (batch.length === 0) return;

    const placeholders = batch
      .map(
        (_, i) => `($${i * 4 + 1}, $${i * 4 + 2}, $${i * 4 + 3}, $${i * 4 + 4})`
      )
      .join(", ");

    const values = batch.flatMap((log) => [
      log.level,
      log.message,
      log.details,
      log.created_at || new Date(),
    ]);

    await poolInstance.query(
      `INSERT INTO system_logs (level, message, details, created_at)
       VALUES ${placeholders}
       ON CONFLICT (id) DO NOTHING`,
      values
    );
  } catch (err) {
    console.error("Fallo crítico al guardar logs en DB:", err.message);
    console.error("Logs perdidos:", batch.length);
  } finally {
    isProcessing = false;
    if (logQueue.length > 0) {
      setTimeout(processQueue, 200);
    }
  }
}

function saveToDB(level, message, details = null) {
  if (!isProd || !poolInstance) return;

  logQueue.push({
    level: LOG_LEVELS[level] || "INFO",
    message: String(message).substring(0, 5000),
    details: details
      ? JSON.stringify(details, null, 2).substring(0, 10000)
      : null,
    created_at: new Date(),
  });

  if (!isProcessing) {
    setTimeout(processQueue, logQueue.length >= 20 ? 0 : 500);
  }
}

const logger = {
  log: (...args) => {
    const message = args
      .map((a) =>
        typeof a === "object" ? JSON.stringify(a, null, 2) : String(a)
      )
      .join(" ");

    if (isDev) console.log("INFO:", message);
    saveToDB("log", message);
  },

  warn: (...args) => {
    const message = args
      .map((a) => (typeof a === "object" ? JSON.stringify(a) : a))
      .join(" ");
    if (isDev) console.warn("WARNING:", message);
    saveToDB("warn", message);
  },

  error: (...args) => {
    let message = "Error desconocido";
    let details = null;

    const [first, ...rest] = args;

    if (typeof first === "string") {
      message = first;
      details = rest.length > 0 ? rest : null;
    } else if (first instanceof Error) {
      message = first.message || "Error sin mensaje";
      details = {
        name: first.name,
        stack: first.stack,
        ...first,
      };
    } else {
      details = first;
    }

    if (isDev) {
      console.error("ERROR:", message);
      if (details) console.error(details);
    }

    saveToDB("error", message, details);
  },
};

if (poolInstance) {
  logger.log("Logger ya estaba inicializado al cargar el módulo");
}

export default logger;
