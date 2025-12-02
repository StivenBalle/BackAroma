import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import { NODE_ENV } from "../utils/config.js";
import checkAccountLock from "../middleware/checkAccount.js";
import {
  getProfile,
  userLogin,
  updateUserPhone,
  userRegister,
} from "../controllers/authUser.controller.js";

const router = express.Router();

// LOGIN
router.post("/login", userLogin);

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: NODE_ENV === "development",
    sameSite: "none",
  });
  res.json({ message: "✅ Logout exitoso" });
});

// PERFIL
router.get("/profile", verifyToken, checkAccountLock, getProfile);

// REGISTRO
router.post("/register", userRegister);

// ACTUALIZAR TELÉFONO
router.put("/update-phone", verifyToken, checkAccountLock, updateUserPhone);

export default router;
