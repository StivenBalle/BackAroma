import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import checkAccountLock from "../middleware/checkAccount.js";
import { getHistorial } from "../controllers/userData.controller.js";

const router = express.Router();

router.get("/historial", verifyToken, checkAccountLock, getHistorial);

export default router;
