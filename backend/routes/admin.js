import express from "express";
import { verifyToken } from "../middleware/jwt.js";
import checkAccountLock from "../middleware/checkAccount.js";
import { requireAdmin, requireAdminOrViewer } from "../middleware/roleCheck.js";
import {
  getUsersSecurity,
  unlockUser,
  lockUser,
  resetAttempts,
  getSecurityDetails,
  getSecurityStats,
  exportLogs,
  changeRolUser,
  deleteUser,
} from "../controllers/adminSecurity.controller.js";
import {
  getSaleByMonths,
  getStateOrder,
  getTopProducts,
  getUsersByMonths,
} from "../controllers/adminChangeData.controller.js";
import {
  getAllOrders,
  getHistorialUser,
  getUserByNameOrEmail,
  getUserProfile,
} from "../controllers/userData.controller.js";

const router = express.Router();

// Obtener todas las órdenes
router.get(
  "/orders",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getAllOrders
);

// Buscar usuarios (por nombre o email)
router.get(
  "/users",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getUserByNameOrEmail
);

// Eliminar usuario
router.delete(
  "/users/:id",
  verifyToken,
  requireAdmin,
  checkAccountLock,
  deleteUser
);

// Perfil completo del usuario
router.get(
  "/users/:userId",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getUserProfile
);

// Historial de compras de un usuario
router.get(
  "/users/:userId/historial",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getHistorialUser
);

// Cambiar rol de usuario
router.put(
  "/users/:id/role",
  verifyToken,
  requireAdmin,
  checkAccountLock,
  changeRolUser
);

// Ventas por mes
router.get(
  "/stats/sales-by-month",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getSaleByMonths
);

// Productos más vendidos
router.get(
  "/stats/top-products",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getTopProducts
);

// Usuarios registrados por mes
router.get(
  "/stats/users-by-month",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getUsersByMonths
);

// Cambiar estado de orden
router.patch(
  "/change-order/:id/status",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getStateOrder
);

router.get(
  "/security/users",
  verifyToken,
  requireAdminOrViewer,
  getUsersSecurity
);

router.get(
  "/security/stats",
  verifyToken,
  requireAdminOrViewer,
  getSecurityStats
);

router.get(
  "/security/logs/export",
  verifyToken,
  requireAdminOrViewer,
  exportLogs
);

router.post(
  "/security/users/:id/unlock",
  verifyToken,
  requireAdmin,
  unlockUser
);

router.post("/security/users/:id/lock", verifyToken, requireAdmin, lockUser);

router.post(
  "/security/users/:id/reset-attempts",
  verifyToken,
  requireAdmin,
  resetAttempts
);

router.get(
  "/security/users/:id/details",
  verifyToken,
  requireAdminOrViewer,
  getSecurityDetails
);

export default router;
