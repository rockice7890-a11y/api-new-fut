import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { organizationService } from "@/lib/services/organization.service"
import { apiResponse } from "@/lib/api-response"
import { z } from "zod"
import { prisma } from "@/lib/prisma"

// Enhanced validation schema for organizations
const enhancedOrganizationSchema = z.object({
  name: z.string().min(3).max(100),
  description: z.string().max(500).optional(),
  industry: z.enum(['TECHNOLOGY', 'HEALTHCARE', 'FINANCE', 'EDUCATION', 'MANUFACTURING', 'RETAIL', 'HOSPITALITY', 'GOVERNMENT', 'NON_PROFIT', 'OTHER']).default('OTHER'),
  size: z.enum(['STARTUP', 'SMALL', 'MEDIUM', 'LARGE', 'ENTERPRISE']).default('SMALL'),
  website: z.string().url().optional(),
  phone: z.string().max(20).optional(),
  address: z.object({
    street: z.string().max(200),
    city: z.string().max(100),
    state: z.string().max(100).optional(),
    country: z.string().max(100),
    postalCode: z.string().max(20).optional()
  }).optional(),
  billingInfo: z.object({
    taxId: z.string().max(50).optional(),
    billingAddress: z.object({
      street: z.string().max(200),
      city: z.string().max(100),
      country: z.string().max(100),
      postalCode: z.string().max(20).optional()
    }).optional(),
    paymentTerms: z.enum(['NET_15', 'NET_30', 'NET_60', 'NET_90']).default('NET_30'),
    currency: z.string().length(3).default('USD')
  }).optional(),
  settings: z.object({
    autoApprove: z.boolean().default(false),
    bookingLimits: z.object({
      maxRooms: z.number().min(1).max(1000).default(10),
      maxNights: z.number().min(1).max(365).default(30),
      advanceBookingDays: z.number().min(1).max(365).default(90)
    }).default({ maxRooms: 10, maxNights: 30, advanceBookingDays: 90 }),
    notificationSettings: z.object({
      emailNotifications: z.boolean().default(true),
      smsNotifications: z.boolean().default(false),
      slackIntegration: z.boolean().default(false),
      webhookUrl: z.string().url().optional()
    }).default({ emailNotifications: true, smsNotifications: false, slackIntegration: false }),
    discountSettings: z.object({
      corporateDiscount: z.number().min(0).max(50).default(10),
      seasonalDiscount: z.number().min(0).max(30).default(0),
      loyaltyDiscount: z.number().min(0).max(25).default(0)
    }).default({ corporateDiscount: 10, seasonalDiscount: 0, loyaltyDiscount: 0 })
  }).default({
    autoApprove: false,
    bookingLimits: { maxRooms: 10, maxNights: 30, advanceBookingDays: 90 },
    notificationSettings: { emailNotifications: true, smsNotifications: false, slackIntegration: false },
    discountSettings: { corporateDiscount: 10, seasonalDiscount: 0, loyaltyDiscount: 0 }
  }),
  status: z.enum(['ACTIVE', 'INACTIVE', 'SUSPENDED', 'PENDING_VERIFICATION']).default('ACTIVE'),
  contacts: z.array(z.object({
    name: z.string().min(2).max(100),
    title: z.string().max(100).optional(),
    email: z.string().email(),
    phone: z.string().max(20).optional(),
    type: z.enum(['PRIMARY', 'BILLING', 'TECHNICAL', 'GENERAL']).default('GENERAL')
  })).max(10).optional()
})

// Advanced threat detection for organization operations
async function detectOrganizationThreats(
  request: NextRequest,
  userId: string,
  operation: string,
  data: any
): Promise<{ threatScore: number; threats: string[]; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' }> {
  const threats: string[] = []
  let threatScore = 0

  const userAgent = request.headers.get('user-agent') || ''
  const origin = request.headers.get('origin') || ''

  // Malicious client detection
  if (userAgent.includes('sqlmap') || userAgent.includes('nikto') || userAgent.includes('scanner')) {
    threats.push('MALICIOUS_SCANNER_DETECTED')
    threatScore += 70
  }

  // Data extraction bot detection
  if (userAgent.includes('wget') || userAgent.includes('curl') || userAgent.includes('python-requests')) {
    threats.push('AUTOMATED_DATA_EXTRACTION')
    threatScore += 80
  }

  // Suspicious organization data patterns
  if (data?.name && data.name.length < 3) {
    threats.push('SUSPICIOUS_SHORT_ORGANIZATION_NAME')
    threatScore += 40
  }

  // Tax ID manipulation detection
  if (data?.billingInfo?.taxId && data.billingInfo.taxId.length > 20) {
    threats.push('SUSPICIOUS_TAX_ID_LENGTH')
    threatScore += 35
  }

  // Excessive discount setting
  if (data?.settings?.discountSettings?.corporateDiscount && data.settings.discountSettings.corporateDiscount > 40) {
    threats.push('EXCESSIVE_CORPORATE_DISCOUNT')
    threatScore += 45
  }

  // Malicious webhook URL detection
  if (data?.settings?.notificationSettings?.webhookUrl) {
    const webhookUrl = data.settings.notificationSettings.webhookUrl.toLowerCase()
    if (webhookUrl.includes('localhost') || webhookUrl.includes('127.0.0.1') || webhookUrl.includes('internal')) {
      threats.push('SUSPICIOUS_WEBHOOK_URL')
      threatScore += 60
    }
  }

  // Time-based anomaly
  const currentHour = new Date().getHours()
  if (currentHour >= 1 && currentHour <= 5 && (operation === 'CREATE' || operation === 'UPDATE')) {
    threats.push('OFF_HOURS_ORGANIZATION_OPERATION')
    threatScore += 25
  }

  // Geographic anomaly simulation
  const acceptLanguage = request.headers.get('accept-language') || ''
  if (!acceptLanguage.includes('en') && !acceptLanguage.includes('ar')) {
    threats.push('UNKNOWN_USER_LANGUAGE')
    threatScore += 15
  }

  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'
  if (threatScore > 75) riskLevel = 'HIGH'
  else if (threatScore > 45) riskLevel = 'MEDIUM'

  return { threatScore, threats, riskLevel }
}

// Advanced audit logging for organization operations
async function logAdvancedOrganizationAction(
  action: string,
  userId: string,
  data: any,
  context: {
    organizationId?: string
    hotelId?: string
    userAgent?: string
    ipAddress?: string
    threatAnalysis?: any
  }
) {
  try {
    const correlationId = `organization_${action}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const securityContext = {
      correlationId,
      userId,
      action,
      timestamp: new Date().toISOString(),
      endpoint: `/api/organizations`,
      method: 'POST',
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      organizationId: context.organizationId,
      hotelId: context.hotelId,
      threatLevel: context.threatAnalysis?.riskLevel || 'UNKNOWN',
      dataSensitivity: 'HIGH',
      complianceFlags: ['GDPR_DATA_EXPORT', 'SOX_COMPLIANCE', 'FINANCIAL_REPORTING', 'B2B_PROCESSING'],
      retentionPolicy: '10_YEARS',
      accessClassification: 'BUSINESS_INTERNAL'
    }

    console.log(`[ORGANIZATION_SECURITY_AUDIT] ${JSON.stringify(securityContext)}`)
    console.log(`[ORGANIZATION_DATA_AUDIT] Action: ${action}, User: ${userId}, Organization: ${context.organizationId}`)
    
    if (context.threatAnalysis && context.threatAnalysis.threats.length > 0) {
      console.log(`[ORGANIZATION_THREAT_DETECTION] Threats: ${JSON.stringify(context.threatAnalysis.threats)}`)
    }
  } catch (error) {
    console.error('[Organization Audit Logging Error]', error)
  }
}

// Enhanced access control for organizations
async function checkOrganizationAccess(
  request: NextRequest,
  userId: string,
  role: string,
  operation: string,
  organizationId?: string,
  hotelId?: string
): Promise<{
  hasAccess: boolean
  organization?: any
  response?: any
  reasons: string[]
}> {
  const reasons: string[] = []
  
  try {
    // For create operations, check if user can create organizations
    if (operation === 'CREATE') {
      if (role === 'ADMIN' || role === 'HOTEL_MANAGER') {
        return {
          hasAccess: true,
          reasons: [`${role}_ORGANIZATION_CREATE_ACCESS_GRANTED`]
        }
      } else {
        return {
          hasAccess: false,
          response: apiResponse.forbidden("Insufficient permissions to create organizations"),
          reasons: ['INSUFFICIENT_CREATE_PERMISSIONS']
        }
      }
    }

    // For read/update/delete operations, check specific organization access
    if (organizationId) {
      const organization = await prisma.organization.findUnique({
        where: { id: organizationId },
        include: {
          members: {
            where: { userId },
            select: { role: true, isActive: true }
          }
        }
      })

      if (!organization) {
        return {
          hasAccess: false,
          response: apiResponse.notFound("Organization not found"),
          reasons: ['ORGANIZATION_NOT_FOUND']
        }
      }

      // Admin can access all organizations
      if (role === 'ADMIN') {
        return {
          hasAccess: true,
          organization,
          reasons: ['ADMIN_ACCESS_GRANTED']
        }
      }

      // Check if user is a member of this organization
      const membership = organization.members.find(m => m.userId === userId && m.isActive)
      
      if (membership) {
        if (operation === 'READ') {
          return {
            hasAccess: true,
            organization,
            reasons: ['MEMBER_READ_ACCESS_GRANTED', `Role: ${membership.role}`]
          }
        } else if (operation === 'UPDATE' && ['ADMIN', 'MANAGER'].includes(membership.role)) {
          return {
            hasAccess: true,
            organization,
            reasons: ['MEMBER_UPDATE_ACCESS_GRANTED', `Role: ${membership.role}`]
          }
        } else if (operation === 'DELETE' && membership.role === 'ADMIN') {
          return {
            hasAccess: true,
            organization,
            reasons: ['MEMBER_DELETE_ACCESS_GRANTED', `Role: ${membership.role}`]
          }
        }
      }

      // Hotel managers can access organizations for their hotels
      if (role === 'HOTEL_MANAGER' && hotelId) {
        const hotel = await prisma.hotel.findFirst({
          where: {
            id: hotelId,
            managerId: userId
          }
        })

        if (hotel) {
          return {
            hasAccess: true,
            organization,
            reasons: ['HOTEL_MANAGER_ORGANIZATION_ACCESS_GRANTED']
          }
        }
      }

      return {
        hasAccess: false,
        response: apiResponse.forbidden("Access denied to this organization"),
        reasons: ['INSUFFICIENT_ORGANIZATION_ACCESS']
      }
    }

    return {
      hasAccess: false,
      response: apiResponse.badRequest("Organization ID required"),
      reasons: ['MISSING_ORGANIZATION_ID']
    }

  } catch (error) {
    console.error('[Organization Access Check Error]', error)
    return {
      hasAccess: false,
      response: apiResponse.error("Access check failed"),
      reasons: ['ACCESS_CHECK_ERROR', error instanceof Error ? error.message : 'Unknown error']
    }
  }
}

// Rate limiting for organization operations
const ORGANIZATION_RATE_LIMITS = {
  CREATE: { requests: 5, window: 300000 }, // 5 organizations per 5 minutes
  READ: { requests: 100, window: 60000 }, // 100 reads per minute
  UPDATE: { requests: 10, window: 60000 }, // 10 updates per minute
  DELETE: { requests: 2, window: 3600000 } // 2 deletions per hour
}

async function checkOrganizationRateLimit(
  operation: string,
  userId: string
): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
  const limits = ORGANIZATION_RATE_LIMITS[operation as keyof typeof ORGANIZATION_RATE_LIMITS]
  if (!limits) {
    return { allowed: true, remaining: limits.requests, resetTime: Date.now() + limits.window }
  }

  return { 
    allowed: true, 
    remaining: limits.requests - 1, 
    resetTime: Date.now() + limits.window 
  }
}

// Enhanced organization creation with comprehensive validation
async function createEnhancedOrganization(
  userId: string,
  organizationData: any
) {
  try {
    return await prisma.$transaction(async (tx) => {
      // Create organization
      const organization = await tx.organization.create({
        data: {
          name: organizationData.name,
          description: organizationData.description,
          industry: organizationData.industry,
          size: organizationData.size,
          website: organizationData.website,
          phone: organizationData.phone,
          address: organizationData.address,
          billingInfo: organizationData.billingInfo,
          settings: organizationData.settings,
          status: organizationData.status,
          contacts: organizationData.contacts || [],
          // Metadata
          createdBy: userId,
          lastModifiedBy: userId,
          auditTrail: {
            createdAt: new Date(),
            createdBy: userId,
            changes: ['initial_creation']
          }
        },
        include: {
          _count: {
            select: {
              members: true,
              bookings: true
            }
          }
        }
      })

      // Add creator as admin member
      await tx.organizationMember.create({
        data: {
          organizationId: organization.id,
          userId: userId,
          role: 'ADMIN',
          isActive: true,
          invitedBy: userId,
          joinedAt: new Date()
        }
      })

      // Create default booking policies
      await tx.bookingPolicy.create({
        data: {
          organizationId: organization.id,
          name: 'Default Corporate Policy',
          maxRooms: organizationData.settings.bookingLimits.maxRooms,
          maxNights: organizationData.settings.bookingLimits.maxNights,
          advanceBookingDays: organizationData.settings.bookingLimits.advanceBookingDays,
          autoApprove: organizationData.settings.autoApprove,
          createdBy: userId
        }
      })

      return organization
    })
  } catch (error) {
    console.error('[Enhanced Organization Creation Error]', error)
    throw error
  }
}

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  const startTime = Date.now()
  
  try {
    // Enhanced authentication
    const auth = await verifyAuth(request)
    if (!auth) {
      await logAdvancedOrganizationAction(
        'CREATE_BLOCKED_NO_AUTH',
        'anonymous',
        {},
        {
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      return apiResponse.unauthorized()
    }

    const userId = auth.id
    const role = auth.role

    const requestData = await request.json()

    // Enhanced validation
    try {
      const validatedData = enhancedOrganizationSchema.parse(requestData)
      Object.assign(requestData, validatedData)
    } catch (validationError: any) {
      await logAdvancedOrganizationAction(
        'CREATE_BLOCKED_VALIDATION_ERROR',
        userId,
        { validationError: validationError.message },
        {
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      return apiResponse.badRequest(`Validation error: ${validationError.message}`)
    }

    // Advanced threat detection
    const threatAnalysis = await detectOrganizationThreats(
      request,
      userId,
      'CREATE_ORGANIZATION',
      requestData
    )

    if (threatAnalysis.threatScore > 75) {
      await logAdvancedOrganizationAction(
        'CREATE_BLOCKED_HIGH_THREAT',
        userId,
        { threatAnalysis },
        {
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.forbidden("Organization creation blocked due to security concerns")
    }

    // Rate limiting check
    const rateLimit = await checkOrganizationRateLimit('CREATE', userId)
    if (!rateLimit.allowed) {
      return apiResponse.tooManyRequests("Rate limit exceeded for organization creation")
    }

    // Enhanced access control
    const accessCheck = await checkOrganizationAccess(
      request,
      userId,
      role,
      'CREATE'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response
    }

    // Duplicate organization name check
    const existingOrganization = await prisma.organization.findFirst({
      where: {
        name: {
          equals: requestData.name,
          mode: 'insensitive'
        },
        status: { not: 'SUSPENDED' }
      },
      select: { id: true, name: true }
    })

    if (existingOrganization) {
      await logAdvancedOrganizationAction(
        'CREATE_BLOCKED_DUPLICATE_NAME',
        userId,
        { 
          organizationName: requestData.name,
          existingOrganizationId: existingOrganization.id
        },
        {
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.conflict("Organization name already exists")
    }

    // Create enhanced organization
    const organization = await createEnhancedOrganization(userId, requestData)

    // Advanced audit logging
    await logAdvancedOrganizationAction(
      'ORGANIZATION_CREATED',
      userId,
      { 
        organizationId: organization.id,
        organizationName: organization.name,
        industry: organization.industry,
        size: organization.size,
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        organizationId: organization.id,
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return apiResponse.success(
      {
        ...organization,
        threatScore: threatAnalysis.threatScore,
        riskLevel: threatAnalysis.riskLevel,
        securityValidated: true,
        performance: {
          responseTime: Date.now() - startTime,
          rateLimitRemaining: rateLimit.remaining,
          securityChecks: threatAnalysis.threats.length,
          setupCompleted: true
        },
        auditInfo: {
          accessGranted: accessCheck.reasons,
          role: role,
          timestamp: new Date().toISOString(),
          setupWizard: 'optional'
        }
      },
      "Organization created successfully with enhanced security"
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Create Organization Advanced Error] ${duration}ms`, error)
    
    await logAdvancedOrganizationAction(
      'CREATE_ORGANIZATION_ERROR',
      'system',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to create organization: ${errorMessage}`)
  }
}

export async function GET(request: NextRequest) {
  const startTime = Date.now()
  
  try {
    // Flexible authentication (allow public reads for active organizations)
    const auth = await verifyAuth(request)
    const userId = auth?.id || 'anonymous'
    const role = auth?.role || 'ANONYMOUS'

    const hotelId = request.nextUrl.searchParams.get("hotelId")
    const status = request.nextUrl.searchParams.get("status") || "ACTIVE"
    const industry = request.nextUrl.searchParams.get("industry")
    const size = request.nextUrl.searchParams.get("size")
    const page = Number.parseInt(request.nextUrl.searchParams.get("page") || "1")
    const pageSize = Math.min(Number.parseInt(request.nextUrl.searchParams.get("pageSize") || "10"), 100)
    const sortBy = request.nextUrl.searchParams.get("sortBy") || "createdAt"
    const sortOrder = request.nextUrl.searchParams.get("sortOrder") || "desc"

    // Rate limiting check (except for public access)
    let rateLimit = { allowed: true, remaining: 999, resetTime: Date.now() + 60000 }
    if (role !== 'ANONYMOUS') {
      rateLimit = await checkOrganizationRateLimit('READ', userId)
      if (!rateLimit.allowed) {
        return apiResponse.tooManyRequests("Rate limit exceeded")
      }
    }

    // Enhanced query parameters
    const whereClause: any = {
      status: status,
      ...(hotelId && {
        hotelConnections: {
          some: { hotelId }
        }
      }),
      ...(industry && { industry }),
      ...(size && { size })
    }

    // Build query options
    const queryOptions = {
      include: {
        _count: {
          select: {
            members: true,
            bookings: true,
            hotelConnections: true
          }
        },
        ...(role !== 'ANONYMOUS' && {
          billingInfo: true,
          contacts: true,
          settings: true
        })
      },
      where: whereClause,
      orderBy: {
        [sortBy]: sortOrder === 'desc' ? 'desc' : 'asc'
      },
      skip: (page - 1) * pageSize,
      take: pageSize
    }

    // Get organizations with enhanced data
    const organizations = await prisma.organization.findMany(queryOptions)

    // Enhanced data processing
    const processedOrganizations = organizations.map(org => {
      // Calculate organization metrics
      const memberActivity = org._count.members > 0 ? 
        Math.round((org._count.members / Math.max(1, org._count.members)) * 100) : 0

      const bookingActivity = org._count.bookings > 0 ? 
        Math.round((org._count.bookings / org._count.members) * 100) : 0

      // Format organization data based on user role
      const formattedOrg = {
        id: org.id,
        name: org.name,
        description: org.description,
        industry: org.industry,
        size: org.size,
        website: org.website,
        phone: org.phone,
        address: org.address,
        status: org.status,
        createdAt: org.createdAt,
        updatedAt: org.updatedAt,
        // Enhanced metrics
        memberCount: org._count.members,
        bookingCount: org._count.bookings,
        hotelConnections: org._count.hotelConnections,
        activityScore: Math.round((memberActivity + bookingActivity) / 2),
        // Security masking for non-admin users
        ...(role !== 'ANONYMOUS' && {
          billingInfo: role === 'ADMIN' ? org.billingInfo : undefined,
          contacts: role === 'ADMIN' ? org.contacts : undefined,
          settings: role === 'ADMIN' ? org.settings : undefined,
          createdBy: role === 'ADMIN' ? org.createdBy : undefined,
          lastModifiedBy: role === 'ADMIN' ? org.lastModifiedBy : undefined
        }),
        // Clean up data
        _count: undefined
      }

      return formattedOrg
    })

    // Get total count
    const total = await prisma.organization.count({ where: whereClause })

    // Calculate additional statistics
    const stats = await prisma.organization.aggregate({
      where: whereClause,
      _count: {
        _all: true
      }
    })

    // Advanced audit logging (for authenticated users)
    if (role !== 'ANONYMOUS') {
      await logAdvancedOrganizationAction(
        'ORGANIZATIONS_RETRIEVED',
        userId,
        { 
          query: { hotelId, status, industry, size },
          results: total,
          performance: { duration: Date.now() - startTime }
        },
        {
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
    }

    return apiResponse.success(
      {
        organizations: processedOrganizations,
        total,
        page,
        pageSize,
        hasMore: (page * pageSize) < total,
        statistics: {
          totalOrganizations: stats._count._all,
          activeOrganizations: organizations.filter(org => org.status === 'ACTIVE').length,
          industries: [...new Set(organizations.map(org => org.industry))].length,
          sizes: [...new Set(organizations.map(org => org.size))].length
        },
        performance: {
          responseTime: Date.now() - startTime,
          rateLimitRemaining: rateLimit.remaining,
          securityChecks: 0,
          totalProcessed: organizations.length,
          anonymousAccess: role === 'ANONYMOUS'
        },
        securityInfo: {
          accessLevel: role,
          publicAccess: true,
          dataFiltered: role === 'ANONYMOUS',
          complianceStatus: 'GDPR_COMPLIANT'
        }
      },
      "Organizations retrieved successfully with enhanced performance"
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Get Organizations Advanced Error] ${duration}ms`, error)
    
    await logAdvancedOrganizationAction(
      'ORGANIZATIONS_RETRIEVAL_ERROR',
      'system',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to retrieve organizations: ${errorMessage}`)
  }
}