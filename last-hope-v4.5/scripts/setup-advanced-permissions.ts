/**
 * Advanced Permission Setup Script
 * Initializes the permission system with default roles and permissions
 */

import { PrismaClient } from "@prisma/client"
import { PermissionType, PermissionScope, AdminLevel } from "@prisma/client"

const prisma = new PrismaClient()

interface PermissionDefinition {
  permission: PermissionType
  scope: PermissionScope
  description: string
}

interface RoleDefinition {
  name: string
  description: string
  level: AdminLevel
  permissions: PermissionDefinition[]
}

const DEFAULT_ROLES: RoleDefinition[] = [
  {
    name: "Super Administrator",
    description: "Full system access with all permissions",
    level: AdminLevel.SUPER_ADMIN,
    permissions: [
      { permission: PermissionType.SYSTEM_CONFIGURATION, scope: PermissionScope.GLOBAL, description: "System configuration management" },
      { permission: PermissionType.SYSTEM_MONITORING, scope: PermissionScope.GLOBAL, description: "System monitoring and alerts" },
      { permission: PermissionType.SYSTEM_BACKUP, scope: PermissionScope.GLOBAL, description: "System backup and restore" },
      { permission: PermissionType.USER_CREATE, scope: PermissionScope.GLOBAL, description: "Create users" },
      { permission: PermissionType.USER_READ, scope: PermissionScope.GLOBAL, description: "View all users" },
      { permission: PermissionType.USER_UPDATE, scope: PermissionScope.GLOBAL, description: "Update user information" },
      { permission: PermissionType.USER_DELETE, scope: PermissionScope.GLOBAL, description: "Delete users" },
      { permission: PermissionType.USER_BLOCK, scope: PermissionScope.GLOBAL, description: "Block/unblock users" },
      { permission: PermissionType.HOTEL_CREATE, scope: PermissionScope.GLOBAL, description: "Create hotels" },
      { permission: PermissionType.HOTEL_READ, scope: PermissionScope.GLOBAL, description: "View all hotels" },
      { permission: PermissionType.HOTEL_UPDATE, scope: PermissionScope.GLOBAL, description: "Update hotel information" },
      { permission: PermissionType.HOTEL_DELETE, scope: PermissionScope.GLOBAL, description: "Delete hotels" },
      { permission: PermissionType.ADMIN_PANEL_ACCESS, scope: PermissionScope.GLOBAL, description: "Access admin panel" },
      { permission: PermissionType.ROLE_MANAGEMENT, scope: PermissionScope.GLOBAL, description: "Manage roles" },
      { permission: PermissionType.PERMISSION_MANAGEMENT, scope: PermissionScope.GLOBAL, description: "Manage permissions" },
      { permission: PermissionType.SYSTEM_LOGS_VIEW, scope: PermissionScope.GLOBAL, description: "View system logs" },
      { permission: PermissionType.GLOBAL_SETTINGS, scope: PermissionScope.GLOBAL, description: "Global settings management" },
      { permission: PermissionType.SECURITY_AUDIT, scope: PermissionScope.GLOBAL, description: "Security auditing" },
      { permission: PermissionType.COMPLIANCE_MONITORING, scope: PermissionScope.GLOBAL, description: "Compliance monitoring" },
      { permission: PermissionType.DATA_EXPORT, scope: PermissionScope.GLOBAL, description: "Data export" },
      { permission: PermissionType.FINANCIAL_VIEW, scope: PermissionScope.GLOBAL, description: "View financial data" },
      { permission: PermissionType.INVOICE_GENERATE, scope: PermissionScope.GLOBAL, description: "Generate invoices" }
    ]
  },
  {
    name: "Hotel Manager",
    description: "Full access to assigned hotel operations",
    level: AdminLevel.HOTEL_ADMIN,
    permissions: [
      { permission: PermissionType.HOTEL_MANAGE_STAFF, scope: PermissionScope.HOTEL, description: "Manage hotel staff" },
      { permission: PermissionType.HOTEL_FINANCIAL_REPORTS, scope: PermissionScope.HOTEL, description: "View financial reports" },
      { permission: PermissionType.BOOKING_CREATE, scope: PermissionScope.HOTEL, description: "Create bookings" },
      { permission: PermissionType.BOOKING_READ, scope: PermissionScope.HOTEL, description: "View bookings" },
      { permission: PermissionType.BOOKING_UPDATE, scope: PermissionScope.HOTEL, description: "Update bookings" },
      { permission: PermissionType.BOOKING_DELETE, scope: PermissionScope.HOTEL, description: "Delete bookings" },
      { permission: PermissionType.BOOKING_CANCEL, scope: PermissionScope.HOTEL, description: "Cancel bookings" },
      { permission: PermissionType.BOOKING_REFUND, scope: PermissionScope.HOTEL, description: "Process refunds" },
      { permission: PermissionType.FINANCIAL_VIEW, scope: PermissionScope.HOTEL, description: "View hotel financial data" },
      { permission: PermissionType.FINANCIAL_UPDATE, scope: PermissionScope.HOTEL, description: "Update financial data" },
      { permission: PermissionType.PAYMENT_PROCESS, scope: PermissionScope.HOTEL, description: "Process payments" },
      { permission: PermissionType.INVOICE_GENERATE, scope: PermissionScope.HOTEL, description: "Generate invoices" },
      { permission: PermissionType.DISCOUNT_MANAGE, scope: PermissionScope.HOTEL, description: "Manage discounts" },
      { permission: PermissionType.PRICING_CONTROL, scope: PermissionScope.HOTEL, description: "Control pricing" },
      { permission: PermissionType.SECURITY_AUDIT, scope: PermissionScope.HOTEL, description: "Hotel security auditing" },
      { permission: PermissionType.ACCESS_LOG_VIEW, scope: PermissionScope.HOTEL, description: "View access logs" }
    ]
  },
  {
    name: "Department Head",
    description: "Manage specific department operations",
    level: AdminLevel.DEPARTMENT_HEAD,
    permissions: [
      { permission: PermissionType.BOOKING_READ, scope: PermissionScope.DEPARTMENT, description: "View department bookings" },
      { permission: PermissionType.BOOKING_UPDATE, scope: PermissionScope.DEPARTMENT, description: "Update department bookings" },
      { permission: PermissionType.FINANCIAL_VIEW, scope: PermissionScope.DEPARTMENT, description: "View department financial data" },
      { permission: PermissionType.ACCESS_LOG_VIEW, scope: PermissionScope.DEPARTMENT, description: "View department access logs" }
    ]
  },
  {
    name: "Supervisor",
    description: "Basic supervisory role with limited permissions",
    level: AdminLevel.SUPERVISOR,
    permissions: [
      { permission: PermissionType.BOOKING_READ, scope: PermissionScope.PERSONAL, description: "View own bookings" },
      { permission: PermissionType.FINANCIAL_VIEW, scope: PermissionScope.PERSONAL, description: "View personal financial data" }
    ]
  },
  {
    name: "Staff Member",
    description: "Basic staff member with minimal permissions",
    level: AdminLevel.DEPARTMENT_HEAD,
    permissions: [
      { permission: PermissionType.BOOKING_READ, scope: PermissionScope.PERSONAL, description: "View assigned bookings" },
      { permission: PermissionType.BOOKING_UPDATE, scope: PermissionScope.PERSONAL, description: "Update assigned bookings" }
    ]
  },
  {
    name: "Regular User",
    description: "Standard user with basic permissions",
    level: AdminLevel.SUPERVISOR,
    permissions: [
      { permission: PermissionType.BOOKING_CREATE, scope: PermissionScope.PERSONAL, description: "Create personal bookings" },
      { permission: PermissionType.BOOKING_READ, scope: PermissionScope.PERSONAL, description: "View personal bookings" },
      { permission: PermissionType.BOOKING_UPDATE, scope: PermissionScope.PERSONAL, description: "Update personal bookings" }
    ]
  },
  {
    name: "Guest",
    description: "Limited guest access",
    level: AdminLevel.SUPERVISOR,
    permissions: [
      { permission: PermissionType.BOOKING_CREATE, scope: PermissionScope.PERSONAL, description: "Create booking" },
      { permission: PermissionType.BOOKING_READ, scope: PermissionScope.PERSONAL, description: "View booking" }
    ]
  }
]

const SYSTEM_CONFIGS = [
  {
    key: "security.max_login_attempts",
    value: "5",
    type: "number",
    description: "Maximum failed login attempts before account lock",
    category: "SECURITY",
    isEditable: true
  },
  {
    key: "security.session_timeout",
    value: "3600",
    type: "number",
    description: "Session timeout in seconds",
    category: "SECURITY",
    isEditable: true
  },
  {
    key: "security.enable_2fa",
    value: "false",
    type: "boolean",
    description: "Enable two-factor authentication",
    category: "SECURITY",
    isEditable: true
  },
  {
    key: "system.maintenance_mode",
    value: "false",
    type: "boolean",
    description: "System maintenance mode",
    category: "SYSTEM",
    isEditable: true
  },
  {
    key: "booking.auto_confirm",
    value: "false",
    type: "boolean",
    description: "Auto-confirm bookings",
    category: "BOOKINGS",
    isEditable: true
  },
  {
    key: "booking.max_advance_booking",
    value: "365",
    type: "number",
    description: "Maximum days in advance for booking",
    category: "BOOKINGS",
    isEditable: true
  },
  {
    key: "payment.currency_default",
    value: "USD",
    type: "string",
    description: "Default payment currency",
    category: "PAYMENT",
    isEditable: true
  },
  {
    key: "notification.email_enabled",
    value: "true",
    type: "boolean",
    description: "Enable email notifications",
    category: "NOTIFICATIONS",
    isEditable: true
  },
  {
    key: "notification.sms_enabled",
    value: "false",
    type: "boolean",
    description: "Enable SMS notifications",
    category: "NOTIFICATIONS",
    isEditable: true
  },
  {
    key: "audit.retention_days",
    value: "90",
    type: "number",
    description: "Audit log retention period in days",
    category: "SECURITY",
    isEditable: true
  }
]

async function setupAdvancedPermissions() {
  console.log("🚀 Starting Advanced Permission System Setup...")

  try {
    // 1. Create default roles with permissions
    console.log("\n📋 Creating default roles...")
    for (const roleDef of DEFAULT_ROLES) {
      const existingRole = await prisma.role.findUnique({
        where: { name: roleDef.name }
      })

      if (existingRole) {
        console.log(`✅ Role "${roleDef.name}" already exists`)
        continue
      }

      const role = await prisma.role.create({
        data: {
          name: roleDef.name,
          description: roleDef.description,
          level: roleDef.level,
          createdBy: "system-setup" // System-created role
        }
      })

      console.log(`✅ Created role: ${role.name}`)

      // Create role permissions
      for (const permDef of roleDef.permissions) {
        await prisma.rolePermission.create({
          data: {
            roleId: role.id,
            permission: permDef.permission,
            scope: permDef.scope,
            createdBy: "system-setup"
          }
        })
      }

      console.log(`   📝 Added ${roleDef.permissions.length} permissions`)
    }

    // 2. Create system configuration
    console.log("\n⚙️ Setting up system configuration...")
    for (const config of SYSTEM_CONFIGS) {
      const existingConfig = await prisma.systemConfig.findUnique({
        where: { key: config.key }
      })

      if (existingConfig) {
        console.log(`✅ Config "${config.key}" already exists`)
        continue
      }

      await prisma.systemConfig.create({
        data: config
      })

      console.log(`✅ Created config: ${config.key}`)
    }

    // 3. Create admin user if not exists
    console.log("\n👤 Setting up default admin user...")
    const adminEmail = "admin@hotelmanagement.com"
    
    let adminUser = await prisma.user.findUnique({
      where: { email: adminEmail }
    })

    if (!adminUser) {
      // Hash the default password (admin123)
      const bcrypt = require('bcryptjs')
      const hashedPassword = await bcrypt.hash('admin123', 12)

      adminUser = await prisma.user.create({
        data: {
          email: adminEmail,
          password: hashedPassword,
          firstName: "System",
          lastName: "Administrator",
          role: 'ADMIN',
          adminLevel: AdminLevel.SUPER_ADMIN
        }
      })

      console.log(`✅ Created admin user: ${adminEmail}`)
      console.log("⚠️  Default password: admin123 (CHANGE IMMEDIATELY)")
    } else {
      console.log(`✅ Admin user already exists: ${adminEmail}`)
      
      // Ensure admin has super admin level
      if (adminUser.adminLevel !== AdminLevel.SUPER_ADMIN) {
        await prisma.user.update({
          where: { id: adminUser.id },
          data: { adminLevel: AdminLevel.SUPER_ADMIN }
        })
        console.log("✅ Updated admin to super admin level")
      }
    }

    // 4. Grant super admin permissions to admin user
    if (adminUser) {
      console.log("\n🔐 Granting super admin permissions...")
      
      const superAdminRole = await prisma.role.findUnique({
        where: { name: "Super Administrator" }
      })

      if (superAdminRole) {
        // Grant all super admin permissions to the admin user
        const superAdminPermissions = await prisma.rolePermission.findMany({
          where: { roleId: superAdminRole.id }
        })

        for (const rolePerm of superAdminPermissions) {
          const existingUserPerm = await prisma.userPermission.findFirst({
            where: {
              userId: adminUser.id,
              permission: rolePerm.permission,
              scope: rolePerm.scope,
              hotelId: rolePerm.hotelId
            }
          })

          if (!existingUserPerm) {
            await prisma.userPermission.create({
              data: {
                userId: adminUser.id,
                permission: rolePerm.permission,
                scope: rolePerm.scope,
                hotelId: rolePerm.hotelId,
                department: rolePerm.department,
                granted: true,
                createdBy: "system-setup"
              }
            })
          }
        }

        console.log(`✅ Granted ${superAdminPermissions.length} permissions to admin user`)
      }
    }

    // 5. Create initial audit log entry
    if (adminUser) {
      await prisma.auditLog.create({
        data: {
          userId: adminUser.id,
          action: "SYSTEM_SETUP",
          resource: "PERMISSION_SYSTEM",
          resourceId: "setup-complete",
          oldValues: null,
          newValues: JSON.stringify({
            rolesCreated: DEFAULT_ROLES.length,
            permissionsCreated: DEFAULT_ROLES.reduce((acc, role) => acc + role.permissions.length, 0),
            configsCreated: SYSTEM_CONFIGS.length
          }),
          success: true,
          ipAddress: "127.0.0.1",
          userAgent: "System Setup Script",
          endpoint: "system-setup",
          method: "SCRIPT"
        }
      })
    }

    console.log("\n🎉 Advanced Permission System Setup Complete!")
    console.log("\n📊 Summary:")
    console.log(`   • ${DEFAULT_ROLES.length} roles created`)
    const totalPerms = DEFAULT_ROLES.reduce((acc, role) => acc + role.permissions.length, 0)
    console.log(`   • ${totalPerms} permissions configured`)
    console.log(`   • ${SYSTEM_CONFIGS.length} system configs set up`)
    console.log(`   • Admin user: ${adminEmail} (password: admin123)`)
    
    console.log("\n🔒 Security Recommendations:")
    console.log("   1. Change default admin password immediately")
    console.log("   2. Enable two-factor authentication")
    console.log("   3. Review and customize permissions as needed")
    console.log("   4. Set up proper backup procedures")
    console.log("   5. Configure monitoring and alerting")

  } catch (error) {
    console.error("❌ Setup failed:", error)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

// Run the setup if this file is executed directly
if (require.main === module) {
  setupAdvancedPermissions()
    .then(() => {
      console.log("\n✨ Setup completed successfully!")
      process.exit(0)
    })
    .catch((error) => {
      console.error("\n💥 Setup failed:", error)
      process.exit(1)
    })
}

export { setupAdvancedPermissions }