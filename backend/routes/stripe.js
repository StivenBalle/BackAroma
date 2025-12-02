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
router.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  webhookEventStripe
);

router.use(express.json());

// Obtener detalles de una compra desde el session_id
router.get(
  "/stripe/purchase/:session_id",
  verifyToken,
  checkAccountLock,
  getDetailsPurchase
);

// Crear sesión de checkout para compra única
router.post(
  "/create-checkout-session",
  verifyToken,
  checkAccountLock,
  createCheckOutSession
);

// Stripe - Productos
router.get("/products", getProductsHome);

export default router;
