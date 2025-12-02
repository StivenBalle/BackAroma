import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { verifyToken } from "../middleware/jwt.js";
import { fileURLToPath } from "url";
import inputProtect from "../middleware/inputProtect.js";
import checkAccountLock from "../middleware/checkAccount.js";
import {
  changeUserPassword,
  createReviews,
  createUserAddress,
  deleteImageProfile,
  getAllReviewsHome,
  getDataProfile,
  getUserAddress,
  updateDataProfile,
  updateUserAddress,
  uploadImageProfile,
  verifyOrderWithReview,
} from "../controllers/userData.controller.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const router = express.Router();

// ====== MULTER CONFIG ======
const uploadDir = path.join(__dirname, "../../uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const validation = inputProtect.validateFilename(file.originalname);

    if (!validation.valid) {
      return cb(new Error(validation.reason));
    }

    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(validation.sanitized);
    const name = path.basename(validation.sanitized, ext);

    cb(null, `${name}-${uniqueSuffix}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowed = ["image/jpeg", "image/png"];
  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Solo se permiten imágenes JPEG o PNG"));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 },
});

router.use((req, res, next) => {
  if (req.body && typeof req.body === "object") {
    req.body = inputProtect.sanitizeObjectRecursivelyServer(req.body);
  }
  if (req.params && typeof req.params === "object") {
    req.params = inputProtect.sanitizeObjectRecursivelyServer(req.params);
  }
  next();
});

// POST /api/user/profile-image - Cargar imagen de perfil
router.post(
  "/profile-image",
  verifyToken,
  checkAccountLock,
  upload.single("profileImage"),
  uploadImageProfile
);

// GET /api/user/profile - Obtener datos del perfil
router.get("/profile", verifyToken, checkAccountLock, getDataProfile);

// DELETE /api/user/delete-image - Eliminar imagen de perfil
router.delete(
  "/delete-image",
  verifyToken,
  checkAccountLock,
  deleteImageProfile
);

// PUT /api/user/profile - Actualizar datos del perfil
router.put("/update", verifyToken, checkAccountLock, updateDataProfile);

// PUT /api/user/shipping-address - Actualizar dirección de envío en users
router.put(
  "/update/shipping-address",
  verifyToken,
  checkAccountLock,
  updateUserAddress
);

// POST /api/user/shipping-address - Crear una nueva dirección de envío
router.post(
  "/add/shipping-address",
  verifyToken,
  checkAccountLock,
  createUserAddress
);

// GET /api/user/shipping-address - Obtener la dirección de envío del usuario
router.get("/shipping-address", verifyToken, checkAccountLock, getUserAddress);

// POST - Crear reseña
router.post("/reviews", verifyToken, checkAccountLock, createReviews);

// Obtener todas las reseñas (para el Home)
router.get("/reviews", getAllReviewsHome);

// Verificar si una orden ya tiene reseña
router.get(
  "/reviews/order/:orderId",
  verifyToken,
  checkAccountLock,
  verifyOrderWithReview
);

// Cambio de contraseña
router.put("/password", verifyToken, checkAccountLock, changeUserPassword);

export default router;
