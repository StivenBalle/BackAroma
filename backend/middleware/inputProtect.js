import createDOMPurify from "dompurify";
import express from "express";
import { JSDOM } from "jsdom";
import validator from "validator";

const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

const SECURITY_CONFIG = {
  // Rate limiting
  rateLimits: {
    general: { windowMs: 15 * 60 * 1000, max: 100 },
    auth: { windowMs: 15 * 60 * 1000, max: 5 },
    api: { windowMs: 1 * 60 * 1000, max: 30 },
    strict: { windowMs: 1 * 60 * 1000, max: 10 },
  },

  // Tamaños máximos
  maxSizes: {
    json: "1mb",
    urlencoded: "1mb",
    fileUpload: 5 * 1024 * 1024,
    stringLength: 5000,
  },

  // Patrones peligrosos
  dangerousPatterns: {
    sql: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|EXEC|UNION|SCRIPT|JAVASCRIPT|ONERROR|ONLOAD)\b|--|;|\/\*|\*\/|xp_|sp_)/gi,
    xss: /<script|<iframe|javascript:|onerror=|onload=|eval\(|expression\(/gi,
    pathTraversal: /\.\.|\/\.\.|\\\.\.|\.\.\\/gi,
    commandInjection: /[;&|`$(){}[\]]/g,
    nosql: /\$where|\$regex|\$ne|\$gt|\$lt/gi,
  },

  // Lista negra de extensiones peligrosas
  dangerousExtensions: [
    ".exe",
    ".bat",
    ".cmd",
    ".sh",
    ".php",
    ".jsp",
    ".asp",
    ".aspx",
    ".js",
    ".vbs",
    ".scr",
  ],
};

const xssOptions = {
  whiteList: { b: [], i: [], strong: [], em: [], p: [], br: [] },
  stripIgnoreTag: true,
};

export function sanitizeServerString(
  value = "",
  { allowHtml = false, maxLen = 5000 } = {}
) {
  if (typeof value !== "string") return "";
  let s = value.trim();
  s = allowHtml
    ? xss(s, xssOptions)
    : DOMPurify.sanitize(s, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

export function sanitizeObjectRecursivelyServer(obj, opts = {}) {
  if (!obj || typeof obj !== "object") return obj;
  const out = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === "string") out[key] = sanitizeServerString(val, opts);
    else if (typeof val === "object" && val !== null)
      out[key] = sanitizeObjectRecursivelyServer(val, opts);
    else out[key] = val;
  }
  return out;
}

export function validateEmailServer(email = "") {
  if (typeof email !== "string") return null;
  const e = sanitizeServerString(email.trim().toLowerCase(), { maxLen: 254 });
  return validator.isEmail(e) ? e : null;
}

export function validatePasswordServer(password = "") {
  if (typeof password !== "string") password = String(password || "");
  const p = password.trim();
  if (p.length < 8)
    return { ok: false, reason: "Debe tener al menos 8 caracteres" };
  if (!/[A-Z]/.test(p))
    return { ok: false, reason: "Debe contener una letra mayúscula" };
  if (!/[a-z]/.test(p))
    return { ok: false, reason: "Debe contener una letra minúscula" };
  if (!/[0-9]/.test(p)) return { ok: false, reason: "Debe contener un número" };
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(p))
    return { ok: false, reason: "Debe contener un carácter especial" };
  return { ok: true, value: p };
}

export async function securityMiddlewares(app) {
  // Helmet: protege cabeceras HTTP contra XSS, clickjacking, etc.
  const { default: helmet } = await import("helmet");
  app.use(
    helmet({
      crossOriginEmbedderPolicy: false,
      crossOriginResourcePolicy: { policy: "cross-origin" },
    })
  );

  // Rate limiter: evita ataques de fuerza bruta / DDoS simples
  const { default: rateLimit } = await import("express-rate-limit");
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Demasiadas peticiones, intenta de nuevo más tarde.",
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use("/api/", limiter);

  // Limita tamaño del body para evitar DoS con payloads grandes
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ limit: "1mb", extended: true }));
}

export function isValidUUID(id) {
  return validator.isUUID(id + "");
}

export function preventSQLInjection(value) {
  const dangerous =
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|EXEC)\b)/i;
  if (typeof value === "string" && dangerous.test(value)) {
    throw new Error("Posible intento de inyección SQL detectado");
  }
  return value;
}

// Sanitiza tokens (JWT o similares) para evitar encabezados maliciosos
export function sanitizeToken(token = "") {
  if (!token || typeof token !== "string") return null;
  const clean = token.replace(/[^a-zA-Z0-9\-_\.]/g, "");
  return clean.length > 10 ? clean : null;
}

// Escapa valores antes de renderizarlos (para evitar XSS reflejado)
export function escapeOutput(str = "") {
  if (typeof str !== "string") return str;
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// Sanitiza valores numéricos
export function sanitizeNumeric(value) {
  const num = parseFloat(value);
  return isNaN(num) ? null : num;
}

/**
 * Sanitiza un string individual
 * @param {string} value - Valor a sanitizar
 * @param {Object} options - Opciones de sanitización
 * @returns {string} String sanitizado
 */
export function sanitizeString(value = "", options = {}) {
  const {
    allowHtml = false,
    maxLength = SECURITY_CONFIG.maxSizes.stringLength,
    allowNewlines = true,
    strictMode = false,
  } = options;

  if (typeof value !== "string") return "";

  let sanitized = value.trim();

  if (allowHtml) {
    sanitized = DOMPurify.sanitize(sanitized, {
      ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li"],
      ALLOWED_ATTR: [],
    });
  } else {
    sanitized = DOMPurify.sanitize(sanitized, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: [],
    });
  }

  sanitized = sanitized.replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, "");

  if (!allowNewlines) {
    sanitized = sanitized.replace(/\s+/g, " ");
  }

  if (strictMode) {
    sanitized = sanitized.replace(/[^a-zA-Z0-9\s\-_.,@]/g, "");
  }

  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength);
  }

  return sanitized;
}

/**
 * Valida un nombre de archivo
 * @param {string} filename - Nombre del archivo
 * @returns {Object} Resultado de la validación
 */
export function validateFilename(filename) {
  if (!filename || typeof filename !== "string") {
    return { valid: false, reason: "Nombre de archivo inválido" };
  }

  const sanitized = sanitizeString(filename, { maxLength: 255 });

  // Verificar path traversal
  if (SECURITY_CONFIG.dangerousPatterns.pathTraversal.test(sanitized)) {
    return { valid: false, reason: "Path traversal detectado" };
  }

  // Verificar extensión peligrosa
  const ext = sanitized.substring(sanitized.lastIndexOf(".")).toLowerCase();
  if (SECURITY_CONFIG.dangerousExtensions.includes(ext)) {
    return { valid: false, reason: "Tipo de archivo no permitido" };
  }

  return { valid: true, sanitized };
}

/**
 * Sanitiza input de usuario
 * @param {*} input - Input a sanitizar
 * @returns {*} Input sanitizado
 */
export function sanitizeInput(input) {
  if (typeof input === "string") {
    return sanitizeServerString(input);
  }
  if (typeof input === "object" && input !== null) {
    return sanitizeObjectRecursivelyServer(input);
  }
  return input;
}

export function sanitizePasswordServer(password = "") {
  if (typeof password !== "string") return "";
  return password.trim().slice(0, 256);
}

export default {
  sanitizeServerString,
  sanitizeObjectRecursivelyServer,
  validateFilename,
  sanitizeInput,
  sanitizeToken,
  sanitizeString,
  escapeOutput,
  sanitizeNumeric,
  validateEmailServer,
  validatePasswordServer,
  isValidUUID,
  preventSQLInjection,
  securityMiddlewares,
  sanitizePasswordServer,
  SECURITY_CONFIG,
};
