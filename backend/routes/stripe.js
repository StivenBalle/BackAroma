import express from "express";
import Stripe from "stripe";
import { verifyToken } from "../middleware/jwt.js";
import pool from "../db.js";

import {
  STRIPE_SECRET_KEY,
  FRONTEND_URL,
  SESSION_SECRET,
  STRIPE_PUBLIC_KEY,
  STRIPE_WEBHOOK_SECRET,
  ACCOUNT_SSD,
  AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
  OWNER_PHONE_NUMBER,
} from "../config.js";

const router = express.Router();
const stripe = new Stripe(STRIPE_SECRET_KEY);

// Crear sesión de checkout para compra única
router.post("/create-checkout-session", verifyToken, async (req, res) => {
  try {
    const { priceId } = req.body;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: "payment", // Cambiado de 'subscription' a 'payment'
      success_url: `${FRONTEND_URL}/successfullPayment?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URLL}/paymentCanceled`,
      customer_email: req.user.email, // Usar email del usuario autenticado
      shipping_address_collection: {
        allowed_countries: ["CO"], // Permitir direcciones en Colombia
      },
      metadata: {
        user_id: req.user.id, // Guardar user_id para el webhook
      },
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error("❌ Error creando sesión de checkout:", error.message);
    res.status(500).json({ error: "No se pudo iniciar el checkout" });
  }
});

// Webhook para manejar eventos de Stripe
router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("❌ Webhook error:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      // Obtener detalles de los ítems comprados
      const lineItems = await stripe.checkout.sessions.listLineItems(
        session.id
      );
      const productData = lineItems.data[0];
      const priceId = productData.price.id;

      // Obtener información del producto desde Stripe
      const price = await stripe.prices.retrieve(priceId);
      const product = await stripe.products.retrieve(price.product);

      // Obtener datos de la dirección
      const shippingAddress = session.shipping_details?.address || {};

      // Guardar en la base de datos
      try {
        await pool.query(
          `INSERT INTO compras (user_id, producto, precio, fecha, status, phone, shipping_address)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            session.metadata.user_id,
            product.name,
            productData.amount_total / 100, // Convertir centavos a moneda
            new Date(),
            "paid",
            session.shipping_details?.phone || null,
            JSON.stringify(shippingAddress),
          ]
        );
        console.log("✅ Compra guardada en la base de datos");
      } catch (dbError) {
        console.error("❌ Error guardando compra:", dbError.message);
      }
    }

    res.json({ received: true });
  }
);

// Obtener productos y precios
router.get("/products", async (req, res) => {
  try {
    const products = await stripe.products.list({ limit: 100 });
    const prices = await stripe.prices.list({ limit: 100 });
    res.json({ products: products.data, prices: prices.data });
  } catch (error) {
    console.error("❌ Error obteniendo productos:", error.message);
    res.status(500).json({ error: "No se pudieron cargar los productos" });
  }
});

// Obtener clave pública de Stripe
router.get("/config", (req, res) => {
  res.json({ publishableKey: STRIPE_PUBLIC_KEY });
});

export default router;
