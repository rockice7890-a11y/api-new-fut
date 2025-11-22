import { prisma } from "@/lib/prisma"
import { UserRole } from "@prisma/client"

export const PermissionsService = {
  // Page blocking functionality
  async blockPage(pagePath: string, reason: string, message: string, blockedBy: string, unblockAt?: Date) {
    const existingBlock = await prisma.pageBlock.findUnique({
      where: { pagePath },
    })

    if (existingBlock) {
      return prisma.pageBlock.update({
        where: { pagePath },
        data: {
          isBlocked: true,
          blockReason: reason,
          blockMessage: message,
          blockedBy,
          unblockAt,
          blockedAt: new Date(),
        },
      })
    }

    return prisma.pageBlock.create({
      data: {
        pagePath,
        isBlocked: true,
        blockReason: reason,
        blockMessage: message,
        blockedBy,
        unblockAt,
      },
    })
  },

  async unblockPage(pagePath: string) {
    return prisma.pageBlock.update({
      where: { pagePath },
      data: { isBlocked: false, unblockAt: null },
    })
  },

  async isPageBlocked(pagePath: string, userRole: UserRole) {
    const pageBlock = await prisma.pageBlock.findUnique({
      where: { pagePath },
    })

    if (!pageBlock || !pageBlock.isBlocked) {
      return { blocked: false }
    }

    // ADMIN can always access
    if (userRole === UserRole.ADMIN) {
      return { blocked: false }
    }

    // Check if role is in allowed roles
    if (pageBlock.allowedRoles.length > 0 && !pageBlock.allowedRoles.includes(userRole)) {
      return {
        blocked: true,
        reason: pageBlock.blockReason,
        message: pageBlock.blockMessage,
      }
    }

    return { blocked: true, reason: pageBlock.blockReason, message: pageBlock.blockMessage }
  },

  // Feature toggle functionality
  async toggleFeature(featureName: string, isEnabled: boolean, toggledBy: string) {
    const existingFeature = await prisma.featureToggle.findUnique({
      where: { featureName },
    })

    if (existingFeature) {
      return prisma.featureToggle.update({
        where: { featureName },
        data: { isEnabled, toggledBy, toggledAt: new Date() },
      })
    }

    return prisma.featureToggle.create({
      data: { featureName, isEnabled, toggledBy, toggledAt: new Date() },
    })
  },

  async isFeatureEnabled(featureName: string, userRole: UserRole) {
    const feature = await prisma.featureToggle.findUnique({
      where: { featureName },
    })

    if (!feature) {
      return true // Feature is enabled by default if not found
    }

    if (!feature.isEnabled) {
      return false
    }

    // If enabledRoles array is empty, feature is enabled for everyone
    if (feature.enabledRoles.length === 0) {
      return true
    }

    // Check if user role is in enabled roles
    return feature.enabledRoles.includes(userRole)
  },

  // Button permission functionality
  async setButtonPermission(buttonName: string, isHidden: boolean, isDisabled: boolean, message?: string) {
    const existingButton = await prisma.buttonPermission.findUnique({
      where: { buttonName },
    })

    const permissionLevel = isHidden ? 2 : isDisabled ? 1 : 0

    if (existingButton) {
      return prisma.buttonPermission.update({
        where: { buttonName },
        data: {
          isHidden,
          isDisabled,
          disabledMessage: message,
          permissionLevel,
        },
      })
    }

    return prisma.buttonPermission.create({
      data: {
        buttonName,
        isHidden,
        isDisabled,
        disabledMessage: message,
        permissionLevel,
      },
    })
  },

  async getButtonPermission(buttonName: string, userRole: UserRole) {
    const button = await prisma.buttonPermission.findUnique({
      where: { buttonName },
    })

    if (!button) {
      return { visible: true, enabled: true }
    }

    // ADMIN can always see and use all buttons
    if (userRole === UserRole.ADMIN) {
      return { visible: true, enabled: true }
    }

    // Check if hidden
    if (button.isHidden) {
      return {
        visible: false,
        enabled: false,
        message: button.disabledMessage || "This action is not available",
      }
    }

    // Check if disabled
    if (button.isDisabled) {
      return {
        visible: true,
        enabled: false,
        message: button.disabledMessage || "This action is currently disabled",
      }
    }

    // Check role restrictions
    if (button.allowedRoles.length > 0 && !button.allowedRoles.includes(userRole)) {
      return {
        visible: false,
        enabled: false,
        message: "You do not have permission for this action",
      }
    }

    return { visible: true, enabled: true }
  },

  async getAllButtonPermissions() {
    return prisma.buttonPermission.findMany()
  },

  // System maintenance
  async createMaintenance(
    title: string,
    description: string,
    startTime: Date,
    endTime: Date,
    severity: string,
    services: string[],
    createdBy: string,
  ) {
    return prisma.systemMaintenance.create({
      data: {
        title,
        description,
        startTime,
        endTime,
        severity,
        affectedServices: services,
        createdBy,
      },
    })
  },

  async getActiveMaintenance() {
    const now = new Date()
    return prisma.systemMaintenance.findMany({
      where: {
        startTime: { lte: now },
        endTime: { gte: now },
        status: "IN_PROGRESS",
      },
    })
  },

  // Audit logging
  async logAudit(
    userId: string,
    action: string,
    resource: string,
    resourceId: string,
    oldValue?: any,
    newValue?: any,
    ipAddress?: string,
    userAgent?: string,
  ) {
    return prisma.auditLog.create({
      data: {
        userId,
        action,
        resource,
        resourceId,
        oldValues: oldValue ? JSON.stringify(oldValue) : null,
        newValues: newValue ? JSON.stringify(newValue) : null,
        ipAddress: ipAddress || 'unknown',
        userAgent: userAgent || 'unknown',
      },
    })
  },

  async getAuditLogs(action?: string, resource?: string, limit = 100) {
    return prisma.auditLog.findMany({
      where: {
        ...(action && { action }),
        ...(resource && { resource }),
      },
      orderBy: { timestamp: "desc" },
      take: limit,
    })
  },
}
