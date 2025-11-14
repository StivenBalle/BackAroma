import express from "express";
import Stripe from "stripe";
import Twilio from "twilio";
import pool from "../database/db.js";
import logger from "../utils/logger.js";
import { verifyToken } from "../middleware/jwt.js";
import inputProtect from "../middleware/inputProtect.js";
import {
  STRIPE_SECRET_KEY,
  FRONTEND_URL,
  STRIPE_WEBHOOK_SECRET,
  ACCOUNT_SSD,
  AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
  ADMIN_PHONE_NUMBER,
} from "../utils/config.js";

const router = express.Router();
const stripe = new Stripe(STRIPE_SECRET_KEY);
const twilioClient = Twilio(ACCOUNT_SSD, AUTH_TOKEN);

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
      logger.error("❌ Webhook error (firma inválida): ", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    const safeEvent = inputProtect.sanitizeObjectRecursivelyServer(event);
    if (!safeEvent || !safeEvent.type) {
      return res.status(400).json({ error: "Evento inválido" });
    }

    if (safeEvent.type === "checkout.session.completed") {
      const session = safeEvent.data.object;

      const sessionId = inputProtect.sanitizeServerString(session.id);
      const metadata = inputProtect.sanitizeObjectRecursivelyServer(
        session.metadata || {}
      );
      const customerName = inputProtect.sanitizeServerString(
        session.customer_details?.name || "Desconocido"
      );
      const shippingAddress = inputProtect.sanitizeObjectRecursivelyServer(
        session.customer_details?.address || {}
      );

      logger.log(`🧾 Pago completado (seguro) para sesión ${sessionId}`);

      let productData, product;
      try {
        const lineItems = await stripe.checkout.sessions.listLineItems(
          session.id,
          {
            expand: ["data.price.product"],
          }
        );
        productData = lineItems.data[0];
        product = productData.price.product;
      } catch (err) {
        logger.error("❌ Error obteniendo lineItems:", err.message);
        return res
          .status(500)
          .json({ error: "Error obteniendo ítems de la compra" });
      }

      let phone = null;
      try {
        const userResult = await pool.query(
          `SELECT phone_number FROM users WHERE id = $1`,
          [parseInt(metadata.user_id)]
        );
        phone = userResult.rows[0]?.phone_number || null;
        logger.log("user.phone_number from DB:", phone);
      } catch (dbError) {
        logger.error(
          "❌ Error obteniendo teléfono del usuario:",
          dbError.message
        );
      }
      // Formatear la dirección para el SMS
      const addressString =
        shippingAddress.line1 && shippingAddress.city
          ? `${shippingAddress.line1}, ${shippingAddress.city}, ${
              shippingAddress.country || ""
            }`
          : "No disponible";
      // Guardar en la base de datos
      let orderId;
      try {
        const insertResult = await pool.query(
          `INSERT INTO compras (user_id, producto, precio, fecha, status, phone, shipping_address, stripe_session_id, image)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
          [
            parseInt(metadata.user_id),
            inputProtect.preventSQLInjection(product.name),
            productData.amount_total / 100,
            new Date(),
            "pendiente",
            phone,
            JSON.stringify(shippingAddress),
            session.id,
            product.images?.[0] || "No image",
          ]
        );
        logger.log("🔍 insertResult:", JSON.stringify(insertResult, null, 2));
        if (!insertResult.rows[0]?.id) {
          throw new Error("No se obtuvo el ID de la compra");
        }
        orderId = insertResult.rows[0].id;
        logger.log("✅ Compra guardada en la base de datos, ID:", orderId);
      } catch (dbError) {
        logger.error("❌ Error guardando compra:", dbError.message);
        return res.status(500).json({ error: "Error guardando la compra" });
      }

      await sendAdminNotification(
        orderId,
        product.name,
        customerName || "Desconocido",
        phone,
        addressString
      );

      if (phone) {
        await sendUserNotification(
          customerName || "Cliente",
          product.name,
          productData.amount_total / 100,
          phone,
          addressString
        );
      } else {
        logger.log("No se envió SMS al usuario: teléfono no disponible");
      }
    }

    res.json({ received: true });
  }
);

router.use(express.json());

// Obtener detalles de una compra desde el session_id
router.get("/stripe/purchase/:session_id", verifyToken, async (req, res) => {
  const { session_id } = req.params;

  try {
    const result = await pool.query(
      `SELECT c.id, c.producto, c.precio, c.fecha, c.status, c.phone, c.shipping_address, c.image,
              u.name AS usuario, u.email AS email
       FROM compras c
       JOIN users u ON c.user_id = u.id
       WHERE c.stripe_session_id = $1`,
      [session_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Compra no encontrada" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    logger.error("❌ Error obteniendo detalles de la compra:", error.message);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// --- Función para enviar SMS al admin ---
async function sendAdminNotification(
  orderId,
  productName,
  customerName,
  phone,
  shippingAddress
) {
  try {
    const message = `🛒 Nuevo pedido #${orderId}: ${customerName} compró "${productName}". Tel: ${
      phone || "N/A"
    }. Dir: ${shippingAddress || "No disponible"}.`;
    const messageObj = await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE_NUMBER,
      to: ADMIN_PHONE_NUMBER,
    });
    logger.log("✅ SMS enviado al admin:", messageObj.sid);
  } catch (err) {
    logger.error("❌ Error enviando SMS al admin:", err.message);
  }
}

// --- Función para enviar SMS al usuario ---
async function sendUserNotification(
  customerName,
  productName,
  amount,
  phone,
  shippingAddress
) {
  let formattedPhone = phone;
  if (phone && !phone.startsWith("+")) {
    formattedPhone = "+57" + phone;
  }
  try {
    const message = `¡Gracias por tu compra, ${customerName}! Has adquirido "${productName}" por $${amount.toFixed(
      2
    )}. Dir ${shippingAddress || "No disponible"}, te contactaremos pronto. ☕`;
    const messageObj = await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE_NUMBER,
      to: formattedPhone,
    });
    logger.log("✅ SMS enviado al usuario", messageObj.sid);
  } catch (err) {
    logger.error("❌ Error enviando SMS al usuario:", err.message);
  }
}

// Crear sesión de checkout para compra única
router.post("/create-checkout-session", verifyToken, async (req, res) => {
  try {
    const { priceId } = inputProtect.sanitizeObjectRecursivelyServer(req.body);

    const userData = await pool.query("SELECT email FROM users WHERE id = $1", [
      req.user.id,
    ]);
    const customer_email = userData.rows[0]?.email;

    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: "Usuario no autenticado" });
    }
    if (!priceId || !customer_email) {
      return res.status(400).json({ error: "Datos incompletos" });
    }
    if (!inputProtect.validateEmailServer(customer_email)) {
      return res.status(400).json({ error: "Correo inválido" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${FRONTEND_URL}/successfullPayment?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/paymentCanceled`,
      customer_email,
      billing_address_collection: "auto",
      shipping_address_collection: {
        allowed_countries: ["CO"],
      },
      metadata: {
        user_id: req.user.id.toString(),
      },
    });
    res.json({ url: session.url });
  } catch (error) {
    logger.error("❌ Error creating checkout session:", error.message);
    res.status(500).json({ error: "No se pudo crear la sesión de pago" });
  }
});

// Stripe - Productos
router.get("/products", async (req, res, next) => {
  try {
    const productsRes = await stripe.products.list({ active: true });
    const pricesRes = await stripe.prices.list({ active: true });

    const validPrices = pricesRes.data.filter((price) =>
      productsRes.data.some((product) => product.id === price.product)
    );

    res.json({ products: productsRes.data, prices: validPrices });
  } catch (error) {
    logger.error("❌ Error al obtener productos:", error.message);
    next(error);
  }
});

export default router;
