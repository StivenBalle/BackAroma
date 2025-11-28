import logger from "../utils/logger.js";

/**
 * Verifica que el usuario tenga uno de los roles permitidos
 * @param {Array<string>} allowedRoles - Roles permitidos: ['admin', 'viewer', 'user']
 */
export const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    try {
      if (!req.user || !req.user.role) {
        logger.warn("⚠️ Usuario sin rol intentó acceder");
        return res.status(403).json({
          error: "Acceso denegado: No tienes permisos",
          code: "NO_ROLE",
        });
      }

      const userRole = req.user.role;

      if (!allowedRoles.includes(userRole)) {
        logger.warn(
          `🚫 Usuario con rol '${userRole}' intentó acceder a recurso que requiere: [${allowedRoles.join(
            ", "
          )}]`
        );
        return res.status(403).json({
          error: "Acceso denegado: Permisos insuficientes",
          code: "INSUFFICIENT_PERMISSIONS",
          required: allowedRoles,
          current: userRole,
        });
      }

      logger.log(`✅ Acceso permitido para rol: ${userRole}`);
      next();
    } catch (err) {
      logger.error("❌ Error en requireRole:", err.message);
      return res.status(500).json({
        error: "Error interno en verificación de permisos",
      });
    }
  };
};

/**
 * Solo administradores
 */
export const requireAdmin = requireRole(["admin"]);

/**
 * Admin o Viewer (solo lectura)
 */
export const requireAdminOrViewer = requireRole(["admin", "viewer"]);

/**
 * Verifica que sea admin para acciones de escritura
 * Si es viewer, bloquea con mensaje específico
 */
export const requireWriteAccess = (req, res, next) => {
  try {
    if (!req.user || !req.user.role) {
      return res.status(403).json({
        error: "Acceso denegado",
        code: "NO_ROLE",
      });
    }

    if (req.user.role === "viewer") {
      logger.warn(
        `🚫 Viewer intentó realizar acción de escritura: ${req.method} ${req.path}`
      );
      return res.status(403).json({
        error: "Acceso denegado: Solo lectura",
        code: "READ_ONLY_ACCESS",
        message:
          "Tu rol de 'Viewer' solo permite visualizar información. No puedes realizar modificaciones.",
      });
    }

    if (req.user.role !== "admin") {
      return res.status(403).json({
        error: "Acceso denegado: Solo administradores",
        code: "ADMIN_REQUIRED",
      });
    }

    next();
  } catch (err) {
    logger.error("❌ Error en requireWriteAccess:", err.message);
    return res.status(500).json({
      error: "Error interno en verificación de permisos",
    });
  }
};

/**
 * Permite a usuarios modificar solo sus propios datos
 * Admins pueden modificar cualquier dato
 */
export const requireOwnerOrAdmin = (req, res, next) => {
  try {
    const userId = req.user.id;
    const targetUserId = parseInt(req.params.id || req.params.userId);

    // Admin puede acceder a cualquier recurso
    if (req.user.role === "admin") {
      return next();
    }

    // Usuario normal solo puede acceder a sus propios datos
    if (userId === targetUserId) {
      return next();
    }

    logger.warn(
      `🚫 Usuario ${userId} intentó acceder a datos de usuario ${targetUserId}`
    );
    return res.status(403).json({
      error: "Acceso denegado: Solo puedes acceder a tus propios datos",
      code: "UNAUTHORIZED_ACCESS",
    });
  } catch (err) {
    logger.error("❌ Error en requireOwnerOrAdmin:", err.message);
    return res.status(500).json({
      error: "Error interno en verificación de permisos",
    });
  }
};

export default {
  requireRole,
  requireAdmin,
  requireAdminOrViewer,
  requireWriteAccess,
  requireOwnerOrAdmin,
};
