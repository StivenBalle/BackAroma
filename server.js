import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import Stripe from "stripe";
import errorHandler from "./backend/errorHandler.js";
import authRoutes from "./backend/routes/auth.js";
import adminRoutes from "./backend/routes/admin.js";
import shoppingRoutes from "./backend/routes/shopping.js";
import { verifyToken } from "./backend/middleware/jwt.js";
import pool from "./backend/db.js";
import Twilio from "twilio";
import "./backend/routes/loginGoogle.js";

import {
  STRIPE_SECRET_KEY,
  FRONTEND_URL,
  SESSION_SECRET,
  NODE_ENV,
  STRIPE_PUBLIC_KEY,
  PORTG,
  STRIPE_WEBHOOK_SECRET,
  ACCOUNT_SSD,
  AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
  ADMIN_PHONE_NUMBER,
} from "./backend/config.js";

// --- Configuración inicial ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });
const stripe = new Stripe(STRIPE_SECRET_KEY);
const twilioClient = Twilio(ACCOUNT_SSD, AUTH_TOKEN);
const app = express();

// Si el servicio está detrás de un proxy (Render), permite cookies seguras
if (NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        "https://cafearomadelaserrania.onrender.com",
        "http://localhost:5173",
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("No permitido por CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(cookieParser());

// --- Logger ---
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// --- Webhook de Stripe (debe ir antes de express.json) ---
app.post(
  "/api/stripe/webhook",
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

      // Depurar datos relevantes del objeto session
      console.log(
        "🔍 session.shipping_details:",
        JSON.stringify(session.shipping_details, null, 2)
      );
      console.log(
        "🔍 session.customer_details:",
        JSON.stringify(session.customer_details, null, 2)
      );
      console.log(
        "🔍 session.shipping:",
        JSON.stringify(session.shipping, null, 2)
      );

      // Obtener detalles de los ítems comprados
      let productData, priceId, price, product;
      try {
        const lineItems = await stripe.checkout.sessions.listLineItems(
          session.id,
          {
            expand: ["data.price.product"],
          }
        );
        productData = lineItems.data[0];
        priceId = productData.price.id;
        price = productData.price;
        product = price.product;
      } catch (err) {
        console.error("❌ Error obteniendo lineItems:", err.message);
        return res
          .status(500)
          .json({ error: "Error obteniendo ítems de la compra" });
      }

      // Obtener datos de la dirección
      const shippingAddress = session.customer_details?.address || {};
      console.log(
        "🔍 shippingAddress:",
        JSON.stringify(shippingAddress, null, 2)
      );
      // Obtener el teléfono del usuario registrado desde la tabla users
      let phone = null;
      try {
        const userResult = await pool.query(
          `SELECT phone_number FROM users WHERE id = $1`,
          [parseInt(session.metadata.user_id)]
        );
        phone = userResult.rows[0]?.phone_number || null;
        console.log("🔍 user.phone_number from DB:", phone);
      } catch (dbError) {
        console.error(
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
          `INSERT INTO compras (user_id, producto, precio, fecha, status, phone, shipping_address, stripe_session_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
          [
            parseInt(session.metadata.user_id),
            product.name,
            productData.amount_total / 100, // Convertir centavos a moneda
            new Date(),
            "paid",
            phone,
            JSON.stringify(shippingAddress),
            session.id,
          ]
        );
        console.log("🔍 insertResult:", JSON.stringify(insertResult, null, 2));
        if (!insertResult.rows[0]?.id) {
          throw new Error("No se obtuvo el ID de la compra");
        }
        orderId = insertResult.rows[0].id;
        console.log("✅ Compra guardada en la base de datos, ID:", orderId);
      } catch (dbError) {
        console.error("❌ Error guardando compra:", dbError.message);
        return res.status(500).json({ error: "Error guardando la compra" });
      }
      // Enviar SMS al admin
      await sendAdminNotification(
        orderId,
        product.name,
        session.customer_details?.name || "Desconocido",
        phone,
        addressString
      );

      // Enviar SMS al usuario (solo si hay teléfono)
      if (phone) {
        await sendUserNotification(
          session.customer_details?.name || "Cliente",
          product.name,
          productData.amount_total / 100,
          phone,
          addressString
        );
      } else {
        console.log("⚠️ No se envió SMS al usuario: teléfono no disponible");
      }
    }

    res.json({ received: true });
  }
);

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
    console.log("✅ SMS enviado al admin:", messageObj.sid);
  } catch (err) {
    console.error("❌ Error enviando SMS al admin:", err.message);
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
    console.log("✅ SMS enviado al usuario", messageObj.sid);
  } catch (err) {
    console.error("❌ Error enviando SMS al usuario:", err.message);
  }
}

app.use(express.json());

// --- Rutas API ---
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api", shoppingRoutes);

// Stripe - Configuración pública
app.get("/api/config", (req, res) => {
  res.json({ publishableKey: STRIPE_PUBLIC_KEY });
});

// Stripe - Productos
app.get("/api/products", async (req, res, next) => {
  try {
    const productsRes = await stripe.products.list({ active: true });
    const pricesRes = await stripe.prices.list({ active: true });

    const validPrices = pricesRes.data.filter((price) =>
      productsRes.data.some((product) => product.id === price.product)
    );

    res.json({ products: productsRes.data, prices: validPrices });
  } catch (error) {
    console.error("❌ Error al obtener productos:", error.message);
    next(error);
  }
});

// Stripe - Crear sesión de pago
app.post("/api/create-checkout-session", verifyToken, async (req, res) => {
  try {
    const { priceId, customer_email } = req.body;
    if (!req.user || !req.user.id) {
      return res.status(401).json({ error: "Usuario no autenticado" });
    }
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${FRONTEND_URL}/successfullPayment?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/paymentCanceled`,
      customer_email: customer_email, // Prefill email
      billing_address_collection: "auto", // Captura dirección de facturación
      shipping_address_collection: {
        allowed_countries: ["CO"], // Solo Colombia, ajusta según necesites
      },
      // Campos personalizados para teléfono (opcional, se capturan en address)
      metadata: {
        user_id: req.user.id.toString(),
      },
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error("❌ Error creating checkout session:", error.message);
    res.status(500).json({ error: "No se pudo crear la sesión de pago" });
  }
});

app.use((req, res, next) => {
  if (req.url.startsWith("/api/")) {
    return res
      .status(404)
      .json({ error: `Ruta de API no encontrada: ${req.url}` });
  }
  next();
});

app.use(errorHandler);

// --- Iniciar servidor ---
const PORT = PORTG || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Backend corriendo en puerto ${PORT}`);
  console.log(`🌐 FRONTEND_URL esperada: ${FRONTEND_URL}`);
});
