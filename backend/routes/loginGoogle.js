import express from "express";
import { authUserWithGoogle } from "../controllers/authUser.controller.js";

const router = express.Router();

router.post("/auth/google", authUserWithGoogle);

export default router;
