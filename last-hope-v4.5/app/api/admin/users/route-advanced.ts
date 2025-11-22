import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { advancedAPISecurity } from "@/lib/api-security-advanced"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان - Admin operations require highest security
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action !== 'ALLOW') {
      console.warn(`[Advanced Security] Admin users access blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons,
        requiresAdminLevel: true
      })
      return NextResponse.json(
        failResponse(null, "Admin access blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req, ["ADMIN"])
    if (!auth.isValid) return auth.response!

    // Enhanced parameter validation with security filtering
    const searchParams = req.nextUrl.searchParams
    const search = searchParams.get("search")
    const role = searchParams.get("role")
    const page = Math.min(Number.parseInt(searchParams.get("page") || "1"), 1000) // Max 1000 pages
    const pageSize = Math.min(Number.parseInt(searchParams.get("pageSize") || "10"), 100) // Max 100 items per page

    // Enhanced validation for search parameters
    if (page < 1 || page > 1000) {
      return NextResponse.json(
        failResponse(null, "Invalid page number", "INVALID_PAGE"),
        { status: 400 }
      )
    }

    if (pageSize < 1 || pageSize > 100) {
      return NextResponse.json(
        failResponse(null, "Invalid page size", "INVALID_PAGE_SIZE"),
        { status: 400 }
      )
    }

    const where: any = {}

    // Enhanced search with SQL injection protection
    if (search) {
      // Sanitize search input
      const sanitizedSearch = search.trim().substring(0, 100) // Max 100 characters
      
      if (sanitizedSearch.length > 0) {
        where.OR = [
          { 
            email: { 
              contains: sanitizedSearch, 
              mode: "insensitive",
              // Additional security: restrict email pattern
              contains: {
                contains: sanitizedSearch,
                not: { contains: /[@<>"']/g } // Prevent SQL injection in email search
              }
            } 
          },
          { firstName: { contains: sanitizedSearch, mode: "insensitive" } },
          { lastName: { contains: sanitizedSearch, mode: "insensitive" } },
        ]
      }
    }

    // Enhanced role filtering with validation
    if (role) {
      const allowedRoles = ['USER', 'MANAGER', 'ADMIN', 'OWNER']
      if (allowedRoles.includes(role)) {
        where.role = role
      } else {
        return NextResponse.json(
          failResponse(null, "Invalid role specified", "INVALID_ROLE"),
          { status: 400 }
        )
      }
    }

    // Enhanced query with security optimizations
    const users = await prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        createdAt: true,
        updatedAt: true,
        lastLoginAt: true,
        isActive: true,
        // Exclude sensitive data like passwords, tokens, etc.
      },
      skip: (page - 1) * pageSize,
      take: pageSize,
      orderBy: { createdAt: "desc" },
    })

    const total = await prisma.user.count({ where })

    // Enhanced response with admin-specific metadata
    return NextResponse.json(
      successResponse(
        { 
          users, 
          total, 
          page, 
          pageSize,
          hasMore: (page * pageSize) < total,
        },
        "Users retrieved successfully",
        {
          admin: {
            requestedBy: auth.payload.userId,
            requestedAt: new Date().toISOString(),
            searchQuery: search ? 'FILTERED' : 'ALL',
            securityLevel: securityContext.securityLevel,
            threatScore: decision.threatScore
          },
          audit: {
            queryHash: `${search || 'all'}:${role || 'all'}:${page}:${pageSize}`,
            requiresAuditLog: total > 0
          }
        }
      ),
      { 
        status: 200,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Admin-Access': 'USERS_READ',
          'X-Audit-Required': total > 0 ? 'true' : 'false'
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Admin Get Users Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to retrieve users", "ADMIN_FETCH_USERS_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR',
          'X-Admin-Access': 'USERS_READ_FAILED'
        }
      }
    )
  }
}

export async function POST(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان - User creation requires highest security
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action !== 'ALLOW') {
      console.warn(`[Advanced Security] Admin user creation blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons,
        requiresAdminLevel: true,
        operation: 'USER_CREATION'
      })
      return NextResponse.json(
        failResponse(null, "User creation blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req, ["ADMIN"])
    if (!auth.isValid) return auth.response!

    // Enhanced input validation with comprehensive security checks
    let body: any
    try {
      body = await req.json()
    } catch (jsonError) {
      return NextResponse.json(
        failResponse(null, "Invalid JSON format", "INVALID_JSON"),
        { status: 400 }
      )
    }

    // Enhanced email validation
    const email = body.email?.toString().trim().toLowerCase()
    if (!email || typeof email !== 'string' || email.length > 255 || !email.includes('@')) {
      return NextResponse.json(
        failResponse(null, "Invalid email format", "INVALID_EMAIL"),
        { status: 400 }
      )
    }

    // Check for SQL injection patterns in email
    if (/[;'"\\<>]/.test(email)) {
      return NextResponse.json(
        failResponse(null, "Invalid characters in email", "INVALID_EMAIL_CHARS"),
        { status: 400 }
      )
    }

    // Enhanced name validation
    const firstName = body.firstName?.toString().trim()
    const lastName = body.lastName?.toString().trim()
    
    if (!firstName || firstName.length > 100 || /[0-9<>"]/.test(firstName)) {
      return NextResponse.json(
        failResponse(null, "Invalid first name", "INVALID_FIRST_NAME"),
        { status: 400 }
      )
    }

    if (!lastName || lastName.length > 100 || /[0-9<>"]/.test(lastName)) {
      return NextResponse.json(
        failResponse(null, "Invalid last name", "INVALID_LAST_NAME"),
        { status: 400 }
      )
    }

    // Enhanced role validation
    const role = body.role?.toString().toUpperCase()
    const allowedRoles = ['USER', 'MANAGER', 'ADMIN', 'OWNER']
    if (!role || !allowedRoles.includes(role)) {
      return NextResponse.json(
        failResponse(null, "Invalid role", "INVALID_ROLE"),
        { status: 400 }
      )
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
      select: { id: true, email: true, isActive: true }
    })

    if (existingUser) {
      if (existingUser.isActive) {
        return NextResponse.json(
          failResponse(null, "User with this email already exists", "USER_EXISTS"),
          { status: 409 }
        )
      } else {
        // Reactivate user if exists but inactive
        const reactivatedUser = await prisma.user.update({
          where: { id: existingUser.id },
          data: {
            firstName,
            lastName,
            role,
            isActive: true,
            updatedAt: new Date(),
            lastLoginAt: null, // Reset last login
            metadata: {
              reactivatedBy: auth.payload.userId,
              reactivatedAt: new Date().toISOString(),
              originalEmail: email
            }
          },
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            role: true,
            createdAt: true,
            isActive: true
          }
        })

        console.log(`[Admin Security] User reactivated by admin ${auth.payload.userId}`, {
          userId: reactivatedUser.id,
          email: reactivatedUser.email,
          role: reactivatedUser.role
        })

        return NextResponse.json(
          successResponse(reactivatedUser, "User reactivated successfully", {
            admin: {
              requestedBy: auth.payload.userId,
              action: 'REACTIVATE_USER',
              securityLevel: securityContext.securityLevel
            }
          }),
          { 
            status: 200,
            headers: {
              'X-Security-Threat-Score': decision.threatScore.toString(),
              'X-Security-Action': decision.action,
              'X-Security-Level': securityContext.securityLevel,
              'X-Admin-Action': 'USER_REACTIVATE'
            }
          }
        )
      }
    }

    // Create new user with enhanced security
    const newUser = await prisma.user.create({
      data: {
        email,
        firstName,
        lastName,
        role,
        isActive: true,
        createdAt: new Date(),
        metadata: {
          createdBy: auth.payload.userId,
          createdByRole: auth.payload.role,
          securityContext: {
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel,
            ipAddress: req.ip,
            userAgent: req.headers.get('user-agent')
          }
        }
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        createdAt: true,
        isActive: true
      }
    })

    console.log(`[Admin Security] New user created by admin ${auth.payload.userId}`, {
      userId: newUser.id,
      email: newUser.email,
      role: newUser.role,
      threatScore: decision.threatScore
    })

    return NextResponse.json(
      successResponse(newUser, "User created successfully", {
        admin: {
          requestedBy: auth.payload.userId,
          action: 'CREATE_USER',
          securityLevel: securityContext.securityLevel
        },
        security: {
          requiresInitialPassword: true,
          requiresEmailVerification: true
        }
      }),
      { 
        status: 201,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Admin-Action': 'USER_CREATE'
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Admin Create User Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create user", "ADMIN_CREATE_USER_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR',
          'X-Admin-Access': 'USER_CREATE_FAILED'
        }
      }
    )
  }
}

export async function PUT(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان - User update requires high security
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action !== 'ALLOW') {
      console.warn(`[Advanced Security] Admin user update blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons,
        operation: 'USER_UPDATE'
      })
      return NextResponse.json(
        failResponse(null, "User update blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req, ["ADMIN"])
    if (!auth.isValid) return auth.response!

    // Enhanced input validation
    let body: any
    try {
      body = await req.json()
    } catch (jsonError) {
      return NextResponse.json(
        failResponse(null, "Invalid JSON format", "INVALID_JSON"),
        { status: 400 }
      )
    }

    const { userId } = body
    if (!userId || typeof userId !== 'string') {
      return NextResponse.json(
        failResponse(null, "User ID is required", "MISSING_USER_ID"),
        { status: 400 }
      )
    }

    // Enhanced update data validation
    const updateData: any = {}
    
    if (body.firstName !== undefined) {
      const firstName = body.firstName.toString().trim()
      if (!firstName || firstName.length > 100 || /[0-9<>"]/.test(firstName)) {
        return NextResponse.json(
          failResponse(null, "Invalid first name", "INVALID_FIRST_NAME"),
          { status: 400 }
        )
      }
      updateData.firstName = firstName
    }

    if (body.lastName !== undefined) {
      const lastName = body.lastName.toString().trim()
      if (!lastName || lastName.length > 100 || /[0-9<>"]/.test(lastName)) {
        return NextResponse.json(
          failResponse(null, "Invalid last name", "INVALID_LAST_NAME"),
          { status: 400 }
        )
      }
      updateData.lastName = lastName
    }

    if (body.role !== undefined) {
      const role = body.role.toString().toUpperCase()
      const allowedRoles = ['USER', 'MANAGER', 'ADMIN', 'OWNER']
      if (!allowedRoles.includes(role)) {
        return NextResponse.json(
          failResponse(null, "Invalid role", "INVALID_ROLE"),
          { status: 400 }
        )
      }
      updateData.role = role
    }

    if (body.isActive !== undefined) {
      updateData.isActive = Boolean(body.isActive)
    }

    if (Object.keys(updateData).length === 0) {
      return NextResponse.json(
        failResponse(null, "No valid fields to update", "NO_UPDATE_FIELDS"),
        { status: 400 }
      )
    }

    updateData.updatedAt = new Date()

    // Update user with enhanced security
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        ...updateData,
        metadata: {
          lastUpdatedBy: auth.payload.userId,
          lastUpdatedByRole: auth.payload.role,
          lastUpdatedAt: new Date().toISOString(),
          securityContext: {
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel
          }
        }
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        createdAt: true,
        updatedAt: true,
        isActive: true
      }
    })

    console.log(`[Admin Security] User updated by admin ${auth.payload.userId}`, {
      userId: updatedUser.id,
      updatedFields: Object.keys(updateData),
      threatScore: decision.threatScore
    })

    return NextResponse.json(
      successResponse(updatedUser, "User updated successfully", {
        admin: {
          requestedBy: auth.payload.userId,
          action: 'UPDATE_USER',
          updatedFields: Object.keys(updateData),
          securityLevel: securityContext.securityLevel
        }
      }),
      { 
        status: 200,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Admin-Action': 'USER_UPDATE'
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Admin Update User Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update user", "ADMIN_UPDATE_USER_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR',
          'X-Admin-Access': 'USER_UPDATE_FAILED'
        }
      }
    )
  }
}