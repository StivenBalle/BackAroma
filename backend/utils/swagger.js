import swaggerJSDoc from "swagger-jsdoc";
import logger from "./logger.js";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Café Aroma de la Serrania - Tienda Online Premium",
      version: "1.0.0",
      description:
        "API completa de Aroma de la Serrania: autenticación, pagos con Stripe, panel admin, seguridad bancaria, reseñas, SMS con Twilio y más.",
      contact: {
        name: "cafearomadelaserrania",
        email: "cafearomadelaserrnia2013@gmail.com",
      },
    },
    servers: [
      {
        url: "http://localhost:5000",
        description: "Servidor local",
      },
    ],
    components: {
      securitySchemes: {
        cookieAuth: {
          type: "apiKey",
          in: "cookie",
          name: "connect.sid",
          description: "Sesión autenticada mediante cookie (express-session)",
        },
      },
      schemas: {
        Error401: {
          type: "object",
          properties: { error: { type: "string", example: "No autenticado" } },
        },
        Error403: {
          type: "object",
          properties: { error: { type: "string", example: "Acceso denegado" } },
        },
        Error423: {
          type: "object",
          properties: {
            error: { type: "string" },
            remainingMin: { type: "integer", nullable: true },
            isPermanent: { type: "boolean" },
            lock_reason: { type: "string", nullable: true },
          },
        },
        Error500: {
          type: "object",
          properties: {
            error: { type: "string", example: "Error interno del servidor" },
          },
        },
      },
    },
    security: [{ cookieAuth: [] }],
  },
  apis: ["./backend/routes/*.js", "./backend/routes/**/*.js", "./routes/*.js"],
};

const swaggerSpec = swaggerJSDoc(options);

logger.log(
  "Rutas encontradas por Swagger:",
  Object.keys(swaggerSpec.paths || {})
);

export default swaggerSpec;
