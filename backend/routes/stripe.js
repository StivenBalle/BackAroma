import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import inputProtect from "../middleware/inputProtect.js";
import checkAccountLock from "../middleware/checkAccount.js";
import {
  createCheckOutSession,
  getDetailsPurchase,
  getProductsHome,
  webhookEventStripe,
} from "../controllers/buyStripe.controller.js";

const router = express.Router();

router.use((req, res, next) => {
  if (req.originalUrl === "/api/stripe/webhook") {
    return next();
  }

  if (req.body && Object.keys(req.body).length > 0) {
    req.body = inputProtect.sanitizeObjectRecursivelyServer(req.body);
  }
  next();
});

// Webhook para manejar eventos de stripe
/**
 * @swagger
 * /api/stripe/webhook:
 *   post:
 *     summary: Webhook de Stripe (procesa eventos de pago)
 *     description: |
 *       Endpoint crítico que recibe eventos de Stripe en tiempo real.
 *       **Importante**: Usa `express.raw()` para verificar la firma.
 *       Actualmente procesa `checkout.session.completed`:
 *       - Guarda la compra en la base de datos
 *       - Envía SMS al admin y al cliente vía Twilio
 *       - Incluye sanitización completa contra inyecciones
 *     tags: [Stripe - Webhook]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             description: Evento completo de Stripe (ver https://stripe.com/docs/webhooks)
 *     responses:
 *       200:
 *         description: Webhook recibido y procesado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 received:
 *                   type: boolean
 *                   example: true
 *       400:
 *         description: Firma inválida o evento no soportado
 */
router.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  webhookEventStripe
);

router.use(express.json());

// Obtener detalles de una compra desde el session_id
/**
 * @swagger
 * /api/create-checkout-session:
 *   post:
 *     summary: Crear sesión de pago con Stripe Checkout
 *     description: |
 *       Crea una sesión de pago única para un producto.
 *       Requiere autenticación del usuario.
 *       Solo permite envíos a Colombia (CO).
 *     tags: [Stripe]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - priceId
 *             properties:
 *               priceId:
 *                 type: string
 *                 description: ID del precio en Stripe (price_xxx)
 *                 example: "price_1QAbCdEFghIjKlMnOpQrStUv"
 *           examples:
 *             comprar_cafetera:
 *               summary: Comprar Cafetera Premium
 *               value: { "priceId": "price_1QAbCdEFghIjKlMnOpQrStUv" }
 *     responses:
 *       200:
 *         description: Sesión creada correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 url:
 *                   type: string
 *                   description: URL de Stripe Checkout
 *                   example: "https://checkout.stripe.com/c/pay/..."
 *       400:
 *         description: Datos incompletos o inválidos
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.get(
  "/stripe/purchase/:session_id",
  verifyToken,
  checkAccountLock,
  getDetailsPurchase
);

// Crear sesión de checkout para compra única
/**
 * @swagger
 * /api/create-checkout-session:
 *   post:
 *     summary: Crear sesión de pago con Stripe Checkout
 *     description: |
 *       Crea una sesión de pago única para un producto.
 *       Requiere autenticación del usuario.
 *       Solo permite envíos a Colombia (CO).
 *     tags: [Stripe]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - priceId
 *             properties:
 *               priceId:
 *                 type: string
 *                 description: ID del precio en Stripe (price_xxx)
 *                 example: "price_1QAbCdEFghIjKlMnOpQrStUv"
 *           examples:
 *             comprar_cafetera:
 *               summary: Comprar Cafetera Premium
 *               value: { "priceId": "price_1QAbCdEFghIjKlMnOpQrStUv" }
 *     responses:
 *       200:
 *         description: Sesión creada correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 url:
 *                   type: string
 *                   description: URL de Stripe Checkout
 *                   example: "https://checkout.stripe.com/c/pay/..."
 *       400:
 *         description: Datos incompletos o inválidos
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.post(
  "/create-checkout-session",
  verifyToken,
  checkAccountLock,
  createCheckOutSession
);

// Stripe - Productos
/**
 * @swagger
 * /api/stripe/purchase/{session_id}:
 *   get:
 *     summary: Obtener detalles de una compra por session_id de Stripe
 *     description: |
 *       Devuelve los detalles de una compra completada.
 *       Solo el dueño de la compra puede acceder.
 *     tags: [Stripe]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: session_id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID de la sesión de Stripe (cs_test_xxx o cs_live_xxx)
 *         example: "cs_test_a1b2c3d4e5f6g7h8i9j0"
 *     responses:
 *       200:
 *         description: Detalles de la compra
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id: { type: integer }
 *                 producto: { type: string }
 *                 precio: { type: number, format: float }
 *                 fecha: { type: string, format: date-time }
 *                 status: { type: string }
 *                 phone: { type: string, nullable: true }
 *                 shipping_address: { type: object, nullable: true }
 *                 image: { type: string, nullable: true }
 *                 usuario: { type: string }
 *                 email: { type: string, format: email }
 *       403:
 *         description: No eres el dueño de esta compra
 *       404:
 *         description: Compra no encontrada
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 */
router.get("/products", getProductsHome);

export default router;
