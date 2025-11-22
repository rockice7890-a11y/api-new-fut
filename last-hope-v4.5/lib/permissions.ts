/**
 * Advanced Permission Management System
 * Provides comprehensive role-based and attribute-based access control
 */

import { PrismaClient } from "@prisma/client"
import { PermissionType, PermissionScope, AdminLevel } from "@prisma/client"

const prisma = new PrismaClient()

export interface PermissionContext {
  userId: string
  hotelId?: string
  department?: string
  resourceId?: string
}

export interface PermissionCheck {
  permission: PermissionType
  scope: PermissionScope
  hotelId?: string
  department?: string
  context?: PermissionContext
}

export interface PermissionResult {
  granted: boolean
  reason?: string
  requiresAuth?: boolean
  auditRequired?: boolean
}

export class PermissionManager {
  /**
   * Check if user has a specific permission
   */
  static async checkPermission({
    permission,
    scope,
    hotelId,
    department,
    context
  }: PermissionCheck): Promise<PermissionResult> {
    try {
      if (!context) {
        return {
          granted: false,
          reason: "Permission context is required",
          requiresAuth: true
        }
      }
      
      const { userId } = context

      // Get user with permissions
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          permissions: true
        }
      })

      if (!user) {
        return { 
          granted: false, 
          reason: "User not found",
          requiresAuth: true 
        }
      }

      // Check if permission is explicitly granted/denied at user level
      const userPermission = user.permissions.find(p => 
        p.permission === permission && 
        p.hotelId === hotelId &&
        p.department === department
      )

      if (userPermission) {
        if (!userPermission.granted) {
          return { 
            granted: false, 
            reason: "Permission explicitly denied",
            auditRequired: true 
          }
        }
        
        if (userPermission.expiresAt && userPermission.expiresAt < new Date()) {
          return { 
            granted: false, 
            reason: "Permission expired",
            auditRequired: true 
          }
        }
        
        return { 
          granted: true, 
          reason: "User-level permission granted",
          auditRequired: true 
        }
      }

      // Check role-based permissions using user's role
      const userRole = user.role
      
      // Simple role-based access logic
      const hasRoleAccess = 
        (userRole === 'ADMIN' && (scope === 'GLOBAL' || scope === 'HOTEL')) ||
        (userRole === 'HOTEL_MANAGER' && (scope === 'HOTEL' || scope === 'DEPARTMENT')) ||
        (userRole === 'USER' && permission === PermissionType.USER_READ)

      if (hasRoleAccess) {
        return { 
          granted: true, 
          reason: "Role-based permission granted",
          auditRequired: true 
        }
      }

      // Check scope-based permissions
      return this.checkScopePermission(user, permission, scope, hotelId, department)
      
    } catch (error) {
      console.error("Permission check error:", error)
      return { 
        granted: false, 
        reason: "System error during permission check",
        auditRequired: true 
      }
    }
  }

  /**
   * Check scope-based permissions (GLOBAL, HOTEL, PERSONAL, DEPARTMENT)
   */
  private static async checkScopePermission(
    user: any,
    permission: PermissionType,
    scope: PermissionScope,
    hotelId?: string,
    department?: string
  ): Promise<PermissionResult> {
    
    const userLevel = user.adminLevel || AdminLevel.SUPERVISOR

    switch (scope) {
      case PermissionScope.GLOBAL:
        if (userLevel === AdminLevel.SUPER_ADMIN || userLevel === AdminLevel.SYSTEM_ADMIN) {
          return { granted: true, reason: "Global admin access" }
        }
        return { granted: false, reason: "Insufficient admin level for global access" }

      case PermissionScope.HOTEL:
        if (userLevel === AdminLevel.SUPER_ADMIN) {
          return { granted: true, reason: "Super admin hotel access" }
        }
        
        if (userLevel === AdminLevel.HOTEL_ADMIN && hotelId) {
          // Check if user is manager of this hotel
          const hotel = await prisma.hotel.findUnique({
            where: { id: hotelId },
            select: { managerId: true }
          })
          
          if (hotel?.managerId === user.id) {
            return { granted: true, reason: "Hotel manager access" }
          }
        }
        return { granted: false, reason: "No hotel access rights" }

      case PermissionScope.PERSONAL:
        // Users can always access their own data
        return { granted: true, reason: "Personal data access" }

      case PermissionScope.DEPARTMENT:
        if (userLevel === AdminLevel.SUPER_ADMIN || 
            userLevel === AdminLevel.HOTEL_ADMIN ||
            userLevel === AdminLevel.SUPERVISOR) {
          return { granted: true, reason: "Department access granted" }
        }
        return { granted: false, reason: "Insufficient level for department access" }

      default:
        return { granted: false, reason: "Unknown permission scope" }
    }
  }

  /**
   * Grant permission to user
   */
  static async grantUserPermission(
    targetUserId: string,
    permission: PermissionType,
    scope: PermissionScope,
    hotelId?: string,
    department?: string,
    expiresAt?: Date,
    grantedBy?: string
  ): Promise<boolean> {
    try {
      // Verify the granting user has permission to grant
      const grantCheck = await this.checkPermission({
        permission: PermissionType.ROLE_MANAGEMENT,
        scope: scope,
        hotelId,
        department,
        context: { userId: grantedBy || 'system' }
      })

      if (!grantCheck.granted) {
        throw new Error(`Insufficient permissions to grant: ${grantCheck.reason}`)
      }

      await prisma.userPermission.create({
        data: {
          userId: targetUserId,
          permission,
          scope,
          hotelId,
          department,
          expiresAt,
          createdBy: grantedBy || 'system'
        }
      })

      // Log the action
      await this.logAuditAction({
        userId: grantedBy || 'system',
        action: "GRANT_PERMISSION",
        resource: "USER_PERMISSION",
        resourceId: targetUserId,
        newValues: JSON.stringify({ permission, scope, hotelId, department }),
        success: true
      })

      return true
    } catch (error) {
      console.error("Grant permission error:", error)
      
      // Log the failed attempt
      await this.logAuditAction({
        userId: grantedBy || 'system',
        action: "GRANT_PERMISSION_FAILED",
        resource: "USER_PERMISSION",
        resourceId: targetUserId,
        errorMessage: error instanceof Error ? error.message : "Unknown error",
        success: false
      })
      
      return false
    }
  }

  /**
   * Revoke permission from user
   */
  static async revokeUserPermission(
    targetUserId: string,
    permission: PermissionType,
    hotelId?: string,
    department?: string,
    revokedBy?: string
  ): Promise<boolean> {
    try {
      // Verify the revoking user has permission to revoke
      const revokeCheck = await this.checkPermission({
        permission: PermissionType.ROLE_MANAGEMENT,
        scope: PermissionScope.GLOBAL,
        context: { userId: revokedBy || 'system' }
      })

      if (!revokeCheck.granted) {
        throw new Error(`Insufficient permissions to revoke: ${revokeCheck.reason}`)
      }

      const deleted = await prisma.userPermission.deleteMany({
        where: {
          userId: targetUserId,
          permission,
          hotelId,
          department
        }
      })

      if (deleted.count === 0) {
        throw new Error("Permission not found to revoke")
      }

      // Log the action
      await this.logAuditAction({
        userId: revokedBy || 'system',
        action: "REVOKE_PERMISSION",
        resource: "USER_PERMISSION",
        resourceId: targetUserId,
        newValues: JSON.stringify({ permission, hotelId, department }),
        success: true
      })

      return true
    } catch (error) {
      console.error("Revoke permission error:", error)
      
      await this.logAuditAction({
        userId: revokedBy || 'system',
        action: "REVOKE_PERMISSION_FAILED",
        resource: "USER_PERMISSION",
        resourceId: targetUserId,
        errorMessage: error instanceof Error ? error.message : "Unknown error",
        success: false
      })
      
      return false
    }
  }

  /**
   * Get all permissions for a user
   */
  static async getUserPermissions(userId: string): Promise<any[]> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        permissions: true
      }
    })

    if (!user) {
      return []
    }

    return [
      ...user.permissions.map(p => ({
        ...p,
        type: 'user',
        source: 'individual'
      }))
    ]
  }

  /**
   * Create a new role
   */
  static async createRole(
    name: string,
    description: string,
    level: AdminLevel,
    permissions: Array<{
      permission: PermissionType
      scope: PermissionScope
      hotelId?: string
      department?: string
    }>,
    createdBy: string
  ): Promise<string | null> {
    try {
      // Verify creator has permission
      const createCheck = await this.checkPermission({
        permission: PermissionType.ROLE_MANAGEMENT,
        scope: PermissionScope.GLOBAL,
        context: { userId: createdBy }
      })

      if (!createCheck.granted) {
        throw new Error(`Insufficient permissions to create role: ${createCheck.reason}`)
      }

      const role = await prisma.role.create({
        data: {
          name,
          description,
          level,
          rolePermissions: {
            create: permissions.map(p => ({
              permission: p.permission,
              scope: p.scope,
              hotelId: p.hotelId,
              department: p.department,
              createdBy: 'system'
            }))
          }
        }
      })

      await this.logAuditAction({
        userId: createdBy,
        action: "CREATE_ROLE",
        resource: "ROLE",
        resourceId: role.id,
        newValues: JSON.stringify({ name, level, permissions: permissions.length }),
        success: true
      })

      return role.id
    } catch (error) {
      console.error("Create role error:", error)
      return null
    }
  }

  /**
   * Audit logging helper
   */
  private static async logAuditAction(params: {
    userId: string
    action: string
    resource: string
    resourceId?: string
    oldValues?: string
    newValues?: string
    success: boolean
    errorMessage?: string
    ipAddress?: string
    userAgent?: string
  }): Promise<void> {
    try {
      await prisma.auditLog.create({
        data: {
          userId: params.userId,
          action: params.action,
          resource: params.resource,
          resourceId: params.resourceId,
          oldValues: params.oldValues,
          newValues: params.newValues,
          success: params.success,
          errorMessage: params.errorMessage,
          ipAddress: params.ipAddress || "unknown",
          userAgent: params.userAgent,
          endpoint: "permissions-api",
          method: "SYSTEM"
        }
      })
    } catch (error) {
      console.error("Audit log error:", error)
    }
  }

  /**
   * Check multiple permissions at once
   */
  static async checkMultiplePermissions(
    permissions: PermissionCheck[],
    context: PermissionContext
  ): Promise<Record<string, PermissionResult>> {
    const results: Record<string, PermissionResult> = {}

    for (const perm of permissions) {
      results[perm.permission] = await this.checkPermission({
        ...perm,
        context
      })
    }

    return results
  }
}

// Permission middleware for API routes
export function withPermission(requiredPermission: PermissionType, scope: PermissionScope) {
  return async (handler: Function) => {
    return async (req: any, res: any) => {
      try {
        const userId = req.user?.id
        const hotelId = req.user?.hotelId
        const department = req.user?.department

        if (!userId) {
          return res.status(401).json({ 
            error: "Authentication required",
            code: "AUTH_REQUIRED"
          })
        }

        const permissionCheck = await PermissionManager.checkPermission({
          permission: requiredPermission,
          scope,
          hotelId,
          department,
          context: { userId, hotelId, department }
        })

        if (!permissionCheck.granted) {
          return res.status(403).json({ 
            error: "Insufficient permissions",
            code: "PERMISSION_DENIED",
            details: permissionCheck.reason
          })
        }

        return await handler(req, res)
      } catch (error) {
        console.error("Permission middleware error:", error)
        return res.status(500).json({ 
          error: "Permission check failed",
          code: "PERMISSION_ERROR"
        })
      }
    }
  }
}

// Export permission types for easy import
export { PermissionType, PermissionScope, AdminLevel }