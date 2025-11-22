export const dynamic = 'force-dynamic'

/**
 * Advanced Admin Permission Management API
 * Provides comprehensive role and permission management
 */

import { NextRequest, NextResponse } from "next/server"
import { PermissionManager, PermissionType, PermissionScope, AdminLevel } from "@/lib/permissions"
import { verifyAuth } from "@/lib/auth"
import { z } from "zod"

// Validation schemas
const grantPermissionSchema = z.object({
  targetUserId: z.string().cuid(),
  permission: z.nativeEnum(PermissionType),
  scope: z.nativeEnum(PermissionScope),
  hotelId: z.string().cuid().optional(),
  department: z.string().optional(),
  expiresAt: z.string().datetime().optional()
})

const revokePermissionSchema = z.object({
  targetUserId: z.string().cuid(),
  permission: z.nativeEnum(PermissionType),
  hotelId: z.string().cuid().optional(),
  department: z.string().optional()
})

const createRoleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().optional(),
  level: z.nativeEnum(AdminLevel),
  permissions: z.array(z.object({
    permission: z.nativeEnum(PermissionType),
    scope: z.nativeEnum(PermissionScope),
    hotelId: z.string().cuid().optional(),
    department: z.string().optional()
  })).min(1)
})

const updateUserRoleSchema = z.object({
  userId: z.string().cuid(),
  roleId: z.string().cuid()
})

/**
 * GET /api/admin/permissions
 * Get comprehensive permission information
 */
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    const action = searchParams.get('action')
    const userId = searchParams.get('userId')
    const hotelId = searchParams.get('hotelId')

    // Verify authentication
    const user = await verifyAuth(req)
    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    // Initialize Prisma client for database operations
    const { PrismaClient } = await import('@prisma/client')
    const prisma = new PrismaClient()

    switch (action) {
      case 'user-permissions':
        if (!userId) {
          return NextResponse.json({ error: "User ID required" }, { status: 400 })
        }
        const userPermissions = await PermissionManager.getUserPermissions(userId)
        return NextResponse.json({ 
          success: true, 
          data: userPermissions 
        })

      case 'check':
        const permission = searchParams.get('permission') as PermissionType
        const scope = searchParams.get('scope') as PermissionScope
        const dept = searchParams.get('department') || undefined
        
        if (!permission || !scope) {
          return NextResponse.json({ 
            error: "Permission and scope required" 
          }, { status: 400 })
        }

        const checkResult = await PermissionManager.checkPermission({
          permission,
          scope,
          hotelId: hotelId || undefined,
          department: dept,
          context: { 
            userId: user.userId,
            hotelId: hotelId || undefined,
            department: dept
          }
        })

        return NextResponse.json({
          success: true,
          data: checkResult
        })

      case 'roles':
        // Get all roles with their permissions
        const roles = await prisma.role.findMany({
          include: {
            rolePermissions: true,
            _count: {
              select: { rolePermissions: true }
            }
          }
        })

        return NextResponse.json({
          success: true,
          data: roles
        })

      case 'users':
        // Get users with their roles and permissions
        const users = await prisma.user.findMany({
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            role: true,
            adminLevel: true,
            createdAt: true,
            _count: {
              select: {
                bookings: true,
                reviews: true,
                auditLogs: true
              }
            }
          }
        })

        return NextResponse.json({
          success: true,
          data: users
        })

      case 'audit-logs':
        // Get recent audit logs
        const logs = await prisma.auditLog.findMany({
          take: 100,
          orderBy: { timestamp: 'desc' },
          include: {
            user: {
              select: {
                email: true,
                firstName: true,
                lastName: true
              }
            }
          }
        })

        return NextResponse.json({
          success: true,
          data: logs
        })

      default:
        return NextResponse.json({ 
          error: "Invalid action parameter" 
        }, { status: 400 })
    }

  } catch (error) {
    console.error("Permission API GET error:", error)
    return NextResponse.json({ 
      error: "Internal server error",
      details: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 })
  }
}

/**
 * POST /api/admin/permissions
 * Grant permissions, create roles, etc.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { action } = body

    // Verify authentication
    const user = await verifyAuth(req)
    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    switch (action) {
      case 'grant-permission':
        const grantData = grantPermissionSchema.parse((body as any).data)
        
        const grantResult = await PermissionManager.grantUserPermission(
          grantData.targetUserId,
          grantData.permission,
          grantData.scope,
          grantData.hotelId,
          grantData.department,
          grantData.expiresAt ? new Date(grantData.expiresAt) : undefined,
          user.userId
        )

        if (!grantResult) {
          return NextResponse.json({ 
            error: "Failed to grant permission",
            code: "GRANT_FAILED"
          }, { status: 400 })
        }

        return NextResponse.json({
          success: true,
          message: "Permission granted successfully"
        })

      case 'create-role':
        const roleData = createRoleSchema.parse((body as any).data) as any
        
        const roleId = await PermissionManager.createRole(
          roleData.name,
          roleData.description || '',
          roleData.level,
          roleData.permissions,
          user.userId
        )

        if (!roleId) {
          return NextResponse.json({ 
            error: "Failed to create role",
            code: "ROLE_CREATION_FAILED"
          }, { status: 400 })
        }

        return NextResponse.json({
          success: true,
          message: "Role created successfully",
          data: { roleId }
        })

      case 'bulk-check':
        const { permissions, context } = body
        
        if (!permissions || !Array.isArray(permissions) || !context) {
          return NextResponse.json({ 
            error: "Invalid bulk check request" 
          }, { status: 400 })
        }

        const results = await PermissionManager.checkMultiplePermissions(
          permissions,
          context
        )

        return NextResponse.json({
          success: true,
          data: results
        })

      default:
        return NextResponse.json({ 
          error: "Invalid action" 
        }, { status: 400 })
    }

  } catch (error) {
    console.error("Permission API POST error:", error)
    
    if (error instanceof z.ZodError) {
      return NextResponse.json({
        error: "Validation error",
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({ 
      error: "Internal server error",
      details: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 })
  }
}

/**
 * DELETE /api/admin/permissions
 * Revoke permissions, delete roles, etc.
 */
export async function DELETE(req: NextRequest) {
  try {
    const body = await req.json()
    const { action } = body

    // Verify authentication
    const user = await verifyAuth(req)
    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    switch (action) {
      case 'revoke-permission':
        const revokeData = revokePermissionSchema.parse((body as any).data)
        
        const revokeResult = await PermissionManager.revokeUserPermission(
          revokeData.targetUserId,
          revokeData.permission,
          revokeData.hotelId,
          revokeData.department,
          user.userId
        )

        if (!revokeResult) {
          return NextResponse.json({ 
            error: "Failed to revoke permission",
            code: "REVOKE_FAILED"
          }, { status: 400 })
        }

        return NextResponse.json({
          success: true,
          message: "Permission revoked successfully"
        })

      case 'delete-role':
        const { roleId } = body
        
        if (!roleId) {
          return NextResponse.json({ 
            error: "Role ID required" 
          }, { status: 400 })
        }

        // Check if user has permission to delete roles
        const deleteCheck = await PermissionManager.checkPermission({
          permission: PermissionType.ROLE_MANAGEMENT,
          scope: PermissionScope.GLOBAL,
          context: { userId: user.userId }
        })

        if (!deleteCheck.granted) {
          return NextResponse.json({
            error: "Insufficient permissions to delete role",
            details: deleteCheck.reason
          }, { status: 403 })
        }

        const { PrismaClient } = await import('@prisma/client')
        const prisma = new PrismaClient()

        // Check if role exists
        const roleUsage = await prisma.role.findUnique({
          where: { id: roleId }
        })

        if (!roleUsage) {
          return NextResponse.json({ 
            error: "Role not found" 
          }, { status: 404 })
        }

        // Note: Cannot check if role is in use as there's no direct User-Role relation in schema
        // Consider adding a roleId field to User model if role assignment tracking is needed

        await prisma.role.delete({
          where: { id: roleId }
        })

        return NextResponse.json({
          success: true,
          message: "Role deleted successfully"
        })

      default:
        return NextResponse.json({ 
          error: "Invalid action" 
        }, { status: 400 })
    }

  } catch (error) {
    console.error("Permission API DELETE error:", error)
    
    if (error instanceof z.ZodError) {
      return NextResponse.json({
        error: "Validation error",
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({ 
      error: "Internal server error",
      details: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 })
  }
}

/**
 * PUT /api/admin/permissions
 * Update roles, assign roles to users, etc.
 */
export async function PUT(req: NextRequest) {
  try {
    const body = await req.json()
    const { action } = body

    // Verify authentication
    const user = await verifyAuth(req)
    if (!user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 })
    }

    switch (action) {
      case 'assign-role':
        const updateData = updateUserRoleSchema.parse((body as any).data)
        
        const { PrismaClient } = await import('@prisma/client')
        const prisma = new PrismaClient()

        // Verify role exists
        const role = await prisma.role.findUnique({
          where: { id: updateData.roleId }
        })

        if (!role) {
          return NextResponse.json({ 
            error: "Role not found" 
          }, { status: 404 })
        }

        // Update user role
        await prisma.user.update({
          where: { id: updateData.userId },
          data: { 
            role: role.level as any,
            adminLevel: role.level
          }
        })

        return NextResponse.json({
          success: true,
          message: "Role assigned successfully"
        })

      case 'update-role':
        const { roleId, name, description, level, permissions } = body
        
        if (!roleId) {
          return NextResponse.json({ 
            error: "Role ID required" 
          }, { status: 400 })
        }

        const { PrismaClient: PrismaClient2 } = await import('@prisma/client')
        const prisma2 = new PrismaClient2()

        // Update role basic info
        const roleUpdateData = {
          ...(name && { name }),
          ...(description && { description }),
          ...(level && { level })
        }

        await prisma2.role.update({
          where: { id: roleId },
          data: roleUpdateData
        })

        // Update permissions if provided
        if (permissions && Array.isArray(permissions)) {
          // Delete existing permissions
          await prisma2.rolePermission.deleteMany({
            where: { roleId }
          })

          // Create new permissions
          await prisma2.rolePermission.createMany({
            data: permissions.map((p: any) => ({
              roleId,
              permission: p.permission,
              scope: p.scope,
              hotelId: p.hotelId,
              department: p.department,
              createdBy: user.userId
            }))
          })
        }

        return NextResponse.json({
          success: true,
          message: "Role updated successfully"
        })

      default:
        return NextResponse.json({ 
          error: "Invalid action" 
        }, { status: 400 })
    }

  } catch (error) {
    console.error("Permission API PUT error:", error)
    
    if (error instanceof z.ZodError) {
      return NextResponse.json({
        error: "Validation error",
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({ 
      error: "Internal server error",
      details: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 })
  }
}