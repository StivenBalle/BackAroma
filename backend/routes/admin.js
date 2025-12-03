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
/**
 * @swagger
 * /api/admin/orders:
 *   get:
 *     summary: Obtiene todas las órdenes de compra (solo admin y viewer)
 *     description: |
 *       Devuelve la lista completa de órdenes con información del usuario.
 *       Accesible solo para roles **admin** y **viewer**.
 *     tags: [Admin]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Lista de órdenes obtenida exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 orders:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 123
 *                       producto:
 *                         type: string
 *                         example: "Cafetera Premium"
 *                       precio:
 *                         type: number
 *                         format: float
 *                         example: 89.99
 *                       fecha:
 *                         type: string
 *                         format: date-time
 *                         example: "2025-04-01T10:30:00.000Z"
 *                       status:
 *                         type: string
 *                         enum: [pendiente, enviado, entregado, cancelado]
 *                         example: "enviado"
 *                       phone:
 *                         type: string
 *                         nullable: true
 *                         example: "+58412..."
 *                       shipping_address:
 *                         type: object
 *                         nullable: true
 *                         properties:
 *                           line1:
 *                             type: string
 *                           city:
 *                             type: string
 *                           country:
 *                             type: string
 *                         example:
 *                           line1: "Calle 10, Edif. 5"
 *                           city: "Caracas"
 *                           country: "Venezuela"
 *                       user_name:
 *                         type: string
 *                         example: "Juan Pérez"
 *                       user_email:
 *                         type: string
 *                         format: email
 *                         example: "juan@example.com"
 *             examples:
 *               éxito:
 *                 summary: Ejemplo de respuesta exitosa
 *                 value:
 *                   orders:
 *                     - id: 123
 *                       producto: "Cafetera Premium"
 *                       precio: 89.99
 *                       fecha: "2025-04-01T10:30:00.000Z"
 *                       status: "enviado"
 *                       phone: "+584129991234"
 *                       shipping_address:
 *                         line1: "Av. Principal"
 *                         city: "Maracaibo"
 *                         country: "Venezuela"
 *                       user_name: "María González"
 *                       user_email: "maria@example.com"
 *       401:
 *         description: No autenticado o sesión expirada
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error401'
 *       403:
 *         description: Acceso denegado (no eres admin ni viewer)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error403'
 *       423:
 *         description: Cuenta bloqueada temporal o permanentemente
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error423'
 *       500:
 *         description: Error interno del servidor
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Error al cargar órdenes"
 */
router.get(
  "/orders",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getAllOrders
);

// Buscar usuarios (por nombre o email)
/**
 * @swagger
 * /api/admin/users:
 *   get:
 *     summary: Buscar usuarios por nombre o email
 *     description: |
 *       Devuelve una lista de usuarios activos (excluye role = 'inactive').
 *       Permite búsqueda parcial por nombre o email.
 *       Solo accesible para **admin** y **viewer**.
 *     tags: [Admin]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Término de búsqueda (nombre o email). Búsqueda parcial con ILIKE.
 *         example: "juan"
 *     responses:
 *       200:
 *         description: Lista de usuarios encontrada
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 users:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 42
 *                       name:
 *                         type: string
 *                         example: "Juan Pérez"
 *                       email:
 *                         type: string
 *                         format: email
 *                         example: "juan@example.com"
 *                       role:
 *                         type: string
 *                         enum: [user, admin, viewer]
 *                         example: "user"
 *                       image:
 *                         type: string
 *                         nullable: true
 *                         example: "https://tudominio.com/uploads/avatar-42.jpg"
 *             examples:
 *               usuarios_encontrados:
 *                 summary: Ejemplo con resultados
 *                 value:
 *                   users:
 *                     - id: 42
 *                       name: "Juan Pérez"
 *                       email: "juan@example.com"
 *                       role: "user"
 *                       image: "https://tudominio.com/uploads/avatar-42.jpg"
 *                     - id: 15
 *                       name: "María González"
 *                       email: "maria@example.com"
 *                       role: "viewer"
 *                       image: null
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.get(
  "/users",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getUserByNameOrEmail
);

// Eliminar usuario
/**
 * @swagger
 * /api/admin/users/{id}:
 *   delete:
 *     summary: Eliminar usuario permanentemente
 *     description: |
 *       Elimina un usuario de la base de datos.
 *       **Restricciones importantes:**
 *       - No puedes eliminar tu propia cuenta
 *       - No puedes eliminar al último administrador del sistema
 *       - Solo usuarios con rol **admin** pueden usar este endpoint
 *     tags: [Admin]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario a eliminar
 *         example: 42
 *     responses:
 *       200:
 *         description: Usuario eliminado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *       400:
 *         description: Validación fallida
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     propio:
 *                       value: "No puedes eliminar tu propia cuenta"
 *                     ultimo_admin:
 *                       value: "No puedes eliminar el último administrador"
 *       404:
 *         description: Usuario no encontrado
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.delete(
  "/users/:id",
  verifyToken,
  requireAdmin,
  checkAccountLock,
  deleteUser
);

// Perfil completo del usuario
/**
 * @swagger
 * /api/admin/users/{userId}:
 *   get:
 *     summary: Perfil completo de un usuario por ID
 *     description: |
 *       Devuelve toda la información del usuario: datos personales, rol, imagen, proveedor de autenticación, etc.
 *       Solo accesible para **admin** y **viewer**.
 *     tags: [Admin]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario
 *         example: 42
 *     responses:
 *       200:
 *         description: Perfil del usuario obtenido correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   example: 42
 *                 name:
 *                   type: string
 *                   example: "Juan Pérez"
 *                 email:
 *                   type: string
 *                   format: email
 *                   example: "juan@example.com"
 *                 phone_number:
 *                   type: string
 *                   nullable: true
 *                   example: "+584129991234"
 *                 role:
 *                   type: string
 *                   enum: [user, admin, viewer]
 *                   example: "user"
 *                 image:
 *                   type: string
 *                   nullable: true
 *                   example: "https://tudominio.com/uploads/avatar-42.jpg"
 *                 auth_provider:
 *                   type: string
 *                   enum: [local, google]
 *                   example: "google"
 *                 address:
 *                   type: string
 *                   nullable: true
 *                   example: "Calle 5, Urbanización Los Robles"
 *                 created_at:
 *                   type: string
 *                   format: date-time
 *                   example: "2024-11-20T10:30:00.000Z"
 *             examples:
 *               perfil_completo:
 *                 summary: Ejemplo de usuario con Google
 *                 value:
 *                   id: 42
 *                   name: "Juan Pérez"
 *                   email: "juan@example.com"
 *                   phone_number: "+584129991234"
 *                   role: "user"
 *                   image: "https://tudominio.com/uploads/avatar-42.jpg"
 *                   auth_provider: "google"
 *                   address: "Av. Principal, Edif. 10"
 *                   created_at: "2024-11-20T10:30:00.000Z"
 *       404:
 *         description: Usuario no encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Usuario no encontrado"
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.get(
  "/users/:userId",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getUserProfile
);

// Historial de compras de un usuario
/**
 * @swagger
 * /api/admin/users/{userId}/historial:
 *   get:
 *     summary: Historial de compras de un usuario específico
 *     description: |
 *       Obtiene todas las compras realizadas por un usuario.
 *       Solo accesible para **admin** y **viewer**.
 *     tags: [Admin]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario
 *         example: 42
 *     responses:
 *       200:
 *         description: Historial de compras del usuario
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 compras:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 101
 *                       producto:
 *                         type: string
 *                         example: "Cafetera Premium"
 *                       precio:
 *                         type: number
 *                         format: float
 *                         example: 89.99
 *                       fecha:
 *                         type: string
 *                         format: date-time
 *                         example: "2025-03-15T14:22:10.000Z"
 *                       status:
 *                         type: string
 *                         enum: [pendiente, enviado, entregado, cancelado]
 *                         example: "entregado"
 *                       shipping_address:
 *                         type: object
 *                         nullable: true
 *                         properties:
 *                           line1:
 *                             type: string
 *                           city:
 *                             type: string
 *                           country:
 *                             type: string
 *                         example:
 *                           line1: "Av. Libertador"
 *                           city: "Caracas"
 *                           country: "Venezuela"
 *             examples:
 *               historial_completo:
 *                 summary: Ejemplo con compras
 *                 value:
 *                   compras:
 *                     - id: 101
 *                       producto: "Cafetera Premium"
 *                       precio: 89.99
 *                       fecha: "2025-03-15T14:22:10.000Z"
 *                       status: "entregado"
 *                       shipping_address:
 *                         line1: "Av. Libertador"
 *                         city: "Caracas"
 *                         country: "Venezuela"
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.get(
  "/users/:userId/historial",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getHistorialUser
);

// Cambiar rol de usuario
/**
 * @swagger
 * /api/admin/users/{id}/role:
 *   put:
 *     summary: Cambiar rol de un usuario
 *     description: |
 *       Permite cambiar el rol de un usuario (user, admin, viewer).
 *       Solo usuarios con rol **admin** pueden realizar esta acción.
 *       No puedes cambiar tu propio rol.
 *     tags: [Admin]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario
 *         example: 42
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - role
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [user, admin, viewer]
 *                 example: "viewer"
 *           examples:
 *             cambiar_a_viewer:
 *               summary: Hacer viewer
 *               value: { "role": "viewer" }
 *             cambiar_a_admin:
 *               summary: Hacer admin
 *               value: { "role": "admin" }
 *     responses:
 *       200:
 *         description: Rol actualizado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 user:
 *                   type: object
 *                   properties:
 *                     id: { type: integer }
 *                     name: { type: string }
 *                     email: { type: string }
 *                     role: { type: string, enum: [user, admin, viewer] }
 *       400:
 *         description: Datos inválidos
 *       404:
 *         description: Usuario no encontrado
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.put(
  "/users/:id/role",
  verifyToken,
  requireAdmin,
  checkAccountLock,
  changeRolUser
);

// Ventas por mes
/**
 * @swagger
 * /api/admin/stats/sales-by-month:
 *   get:
 *     summary: Ventas totales por mes
 *     description: Estadísticas de ventas agrupadas por mes (año-mes)
 *     tags: [Admin - Estadísticas]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Datos de ventas por mes
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   mes:
 *                     type: string
 *                     pattern: ^\d{4}-\d{2}$
 *                     example: "2025-03"
 *                   total_compras:
 *                     type: integer
 *                     example: 45
 *                   total_ventas:
 *                     type: number
 *                     format: float
 *                     example: 2850.50
 *             examples:
 *               ejemplo:
 *                 value:
 *                   - mes: "2025-01"
 *                     total_compras: 32
 *                     total_ventas: 1890.00
 *                   - mes: "2025-02"
 *                     total_compras: 41
 *                     total_ventas: 2499.99
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.get(
  "/stats/sales-by-month",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getSaleByMonths
);

// Productos más vendidos
/**
 * @swagger
 * /api/admin/stats/top-products:
 *   get:
 *     summary: Productos más vendidos (Top 5)
 *     description: Los 5 productos con más unidades vendidas
 *     tags: [Admin - Estadísticas]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Top 5 productos más vendidos
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   producto:
 *                     type: string
 *                     example: "Cafetera Premium"
 *                   cantidad_vendida:
 *                     type: integer
 *                     example: 28
 *                   total_ventas:
 *                     type: number
 *                     format: float
 *                     example: 2516.00
 *             examples:
 *               top_productos:
 *                 value:
 *                   - producto: "Cafetera Premium"
 *                     cantidad_vendida: 28
 *                     total_ventas: 2516.00
 *                   - producto: "Taza Térmica"
 *                     cantidad_vendida: 19
 *                     total_ventas: 380.00
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.get(
  "/stats/top-products",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getTopProducts
);

// Usuarios registrados por mes
/**
 * @swagger
 * /api/admin/stats/users-by-month:
 *   get:
 *     summary: Nuevos usuarios registrados por mes
 *     description: Estadísticas de crecimiento de usuarios por mes
 *     tags: [Admin - Estadísticas]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Usuarios nuevos por mes
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   mes:
 *                     type: string
 *                     pattern: ^\d{4}-\d{2}$
 *                     example: "2025-03"
 *                   nuevos_usuarios:
 *                     type: integer
 *                     example: 87
 *             examples:
 *               crecimiento:
 *                 value:
 *                   - mes: "2025-01"
 *                     nuevos_usuarios: 45
 *                   - mes: "2025-02"
 *                     nuevos_usuarios: 68
 *                   - mes: "2025-03"
 *                     nuevos_usuarios: 87
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.get(
  "/stats/users-by-month",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getUsersByMonths
);

// Cambiar estado de orden
/**
 * @swagger
 * /api/admin/change-order/{id}/status:
 *   patch:
 *     summary: Cambiar estado de una orden de compra
 *     description: |
 *       Actualiza el estado de una orden existente.
 *       Solo accesible para **admin** y **viewer**.
 *     tags: [Admin - Órdenes]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la orden
 *         example: 123
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [pendiente, procesando, enviado, completado, cancelado]
 *                 example: "enviado"
 *           examples:
 *             marcar_enviado:
 *               summary: Marcar como enviado
 *               value: { "status": "enviado" }
 *             completar_orden:
 *               summary: Marcar como completado
 *               value: { "status": "completado" }
 *     responses:
 *       200:
 *         description: Estado actualizado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 status:
 *                   type: string
 *                   example: "enviado"
 *       400:
 *         description: Estado no válido
 *       404:
 *         description: Orden no encontrada
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.patch(
  "/change-order/:id/status",
  verifyToken,
  requireAdminOrViewer,
  checkAccountLock,
  getStateOrder
);

/**
 * @swagger
 * /api/admin/security/users:
 *   get:
 *     summary: Panel de seguridad - Lista de usuarios con estado de bloqueo
 *     description: |
 *       Devuelve usuarios con información de seguridad: intentos fallidos, bloqueos temporales/permanentes, tiempo restante, etc.
 *       Incluye limpieza automática de bloqueos expirados.
 *       Soporta filtros y búsqueda.
 *     tags: [Admin - Seguridad]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Buscar por nombre o email
 *       - in: query
 *         name: filter
 *         schema:
 *           type: string
 *           enum: [all, locked, permanent, suspicious]
 *           default: all
 *         description: Filtrar por estado de seguridad
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Página actual
 *     responses:
 *       200:
 *         description: Lista de usuarios con datos de seguridad
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 users:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id: { type: integer }
 *                       name: { type: string }
 *                       email: { type: string, format: email }
 *                       image: { type: string, nullable: true }
 *                       login_attempts: { type: integer, example: 3 }
 *                       is_locked: { type: boolean }
 *                       is_permanently_locked: { type: boolean }
 *                       locked_until: { type: string, format: date-time, nullable: true }
 *                       last_failed_login: { type: string, format: date-time, nullable: true }
 *                       lock_reason: { type: string, nullable: true }
 *                       remaining_minutes: { type: integer, example: 8 }
 *                 stats:
 *                   type: object
 *                   description: Estadísticas globales de seguridad
 *                 pagination:
 *                   type: object
 *                   properties:
 *                     page: { type: integer }
 *                     totalPages: { type: integer }
 *                     total: { type: integer }
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 */
router.get(
  "/security/users",
  verifyToken,
  requireAdminOrViewer,
  getUsersSecurity
);

/**
 * @swagger
 * /api/admin/security/stats:
 *   get:
 *     summary: Estadísticas globales de seguridad del sistema
 *     description: |
 *       Devuelve métricas en tiempo real del sistema de seguridad:
 *       - Cuentas bloqueadas permanentemente
 *       - Cuentas con bloqueo activo (temporal)
 *       - Cuentas con intentos fallidos (pero no bloqueadas)
 *       - Intentos fallidos y exitosos de hoy
 *
 *       Ideal para mostrar en el dashboard de administración.
 *     tags: [Admin - Seguridad]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Estadísticas de seguridad obtenidas correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 permanently_locked:
 *                 type: integer
 *                 description: Usuarios bloqueados de forma permanente
 *                 example: 2
 *                 locked_accounts:
 *                   type: integer
 *                   description: Usuarios con bloqueo temporal activo en este momento
 *                   example: 5
 *                 accounts_with_attempts:
 *                   type: integer
 *                   description: Usuarios que han tenido intentos fallidos pero aún no están bloqueados
 *                   example: 12
 *                 failed_logins_today:
 *                   type: integer
 *                   description: Número total de intentos fallidos de login hoy
 *                   example: 38
 *                 successful_logins_today:
 *                   type: integer
 *                   description: Número total de inicios de sesión exitosos hoy
 *                   example: 245
 *             examples:
 *               estadísticas_reales:
 *                 summary: Ejemplo realista de un día activo
 *                 value:
 *                   permanently_locked: 1
 *                   locked_accounts: 3
 *                   accounts_with_attempts: 9
 *                   failed_logins_today: 27
 *                   successful_logins_today: 189
 *               sistema_limpio:
 *                 summary: Sistema sin actividad sospechosa
 *                 value:
 *                   permanently_locked: 0
 *                   locked_accounts: 0
 *                   accounts_with_attempts: 2
 *                   failed_logins_today: 4
 *                   successful_logins_today: 312
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       423:
 *         $ref: '#/components/schemas/Error423'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
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

/**
 * @swagger
 * /api/admin/security/users/{id}/unlock:
 *   post:
 *     summary: Desbloquear cuenta de usuario (temporal o permanente)
 *     description: Reinicia intentos y desactiva cualquier bloqueo activo.
 *     tags: [Admin - Seguridad]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Usuario desbloqueado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 *       500:
 *         $ref: '#/components/schemas/Error500'
 */
router.post(
  "/security/users/:id/unlock",
  verifyToken,
  requireAdmin,
  unlockUser
);

/**
 * @swagger
 * /api/admin/security/users/{id}/lock:
 *   post:
 *     summary: Bloquear cuenta de usuario (temporal o permanente)
 *     description: |
 *       Bloquea una cuenta por seguridad.
 *       Requiere razón mínima de 10 caracteres.
 *     tags: [Admin - Seguridad]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               duration:
 *                 type: integer
 *                 description: Minutos de bloqueo (solo si no es permanente)
 *                 example: 30
 *               reason:
 *                 type: string
 *                 minLength: 10
 *                 example: "Actividad sospechosa detectada en múltiples intentos"
 *               permanent:
 *                 type: boolean
 *                 default: false
 *                 description: Si es true, ignora duration y bloquea permanentemente
 *           examples:
 *             bloqueo_temporal:
 *               value: { "duration": 60, "reason": "Demasiados intentos fallidos", "permanent": false }
 *             bloqueo_permanente:
 *               value: { "reason": "Fraude confirmado por soporte", "permanent": true }
 *     responses:
 *       200:
 *         description: Usuario bloqueado correctamente
 *       400:
 *         description: Razón demasiado corta
 *       401:
 *         $ref: '#/components/schemas/Error401'
 *       403:
 *         $ref: '#/components/schemas/Error403'
 */
router.post("/security/users/:id/lock", verifyToken, requireAdmin, lockUser);

/**
 * @swagger
 * /api/admin/security/users/{id}/reset-attempts:
 *   post:
 *     summary: Reiniciar contador de intentos fallidos
 *     description: Pone a cero los intentos de login fallidos
 *     tags: [Admin - Seguridad]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Intentos reiniciados
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 */
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
