import dotenv from "dotenv";
import path from "path";

// Cargar variables desde .env en la raíz
dotenv.config({ path: path.resolve(process.cwd(), ".env") });

export const {
  PORTG,
  NODE_ENV,
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  DATABASE_URL,
  STRIPE_SECRET_KEY,
  STRIPE_PUBLIC_KEY,
  SESSION_SECRET,
  FRONTEND_URL,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  BACKEND_URL,
  ACCOUNT_SSD,
  AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
  ADMIN_PHONE_NUMBER,
  STRIPE_WEBHOOK_SECRET,
} = process.env;
