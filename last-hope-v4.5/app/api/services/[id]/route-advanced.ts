import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { serviceService } from "@/lib/services/service.service"
import { apiResponse } from "@/lib/api-response"
import { z } from "zod"
import { prisma } from "@/lib/prisma"

// Enhanced validation schema for service updates
const enhancedServiceUpdateSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  description: z.string().max(1000).optional(),
  price: z.number().min(0).max(10000).optional(),
  icon: z.string().optional(),
  category: z.enum(['ROOM_SERVICE', 'CONCIERGE', 'SPA_WELLNESS', 'FOOD_BEVERAGE', 'TRANSPORT', 'ENTERTAINMENT', 'BUSINESS', 'OTHER']).optional(),
  isActive: z.boolean().optional(),
  duration: z.number().min(0).max(1440).optional(),
  maxQuantity: z.number().min(1).max(100).optional(),
  requiresBooking: z.boolean().optional(),
  advanceBookingRequired: z.boolean().optional(),
  advanceBookingHours: z.number().min(0).max(168).optional(),
  staffRequired: z.number().min(0).max(20).optional(),
  equipment: z.array(z.string()).optional(),
  restrictions: z.array(z.string()).optional(),
  availability: z.object({
    daysOfWeek: z.array(z.number().min(0).max(6)),
    startTime: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
    endTime: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
    timezone: z.string().default('UTC')
  }).optional(),
  pricing: z.object({
    isDynamic: z.boolean().optional(),
    peakSeasonMultiplier: z.number().min(0.5).max(5).optional(),
    offSeasonDiscount: z.number().min(0).max(0.9).optional(),
    weekendMultiplier: z.number().min(0.5).max(3).optional(),
    groupDiscount: z.object({
      minGuests: z.number().min(2).max(50),
      discountPercent: z.number().min(0).max(50)
    }).optional()
  }).optional(),
  forceUpdate: z.boolean().optional().default(false), // For emergency updates
  updateReason: z.string().max(200).optional() // Required for critical updates
})

// Advanced threat detection for service ID operations
async function detectServiceIdThreats(
  request: NextRequest,
  userId: string,
  operation: string,
  serviceId: string,
  data: any
): Promise<{ threatScore: number; threats: string[]; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' }> {
  const threats: string[] = []
  let threatScore = 0

  const userAgent = request.headers.get('user-agent') || ''
  const origin = request.headers.get('origin') || ''

  // UUID format validation
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
  if (!uuidRegex.test(serviceId)) {
    threats.push('INVALID_SERVICE_ID_FORMAT')
    threatScore += 50
  }

  // Malicious client detection
  if (userAgent.includes('sqlmap') || userAgent.includes('nikto') || userAgent.includes('scanner')) {
    threats.push('MALICIOUS_SCANNER_DETECTED')
    threatScore += 80
  }

  // Suspicious service ID patterns
  if (serviceId.includes('--') || serviceId.includes('..') || serviceId.includes('/')) {
    threats.push('SUSPICIOUS_SERVICE_ID_PATTERN')
    threatScore += 40
  }

  // Price manipulation detection
  if (data?.price && data.price > 8000) {
    threats.push('SUSPICIOUS_HIGH_PRICE_UPDATE')
    threatScore += 60
  }

  // Bulk update detection
  if (data?.forceUpdate && operation === 'PUT') {
    threats.push('FORCE_UPDATE_ATTEMPT')
    threatScore += 35
  }

  // Time-based anomaly (late night updates)
  const currentHour = new Date().getHours()
  if (currentHour >= 1 && currentHour <= 5 && (operation === 'PUT' || operation === 'DELETE')) {
    threats.push('OFF_HOURS_SERVICE_OPERATION')
    threatScore += 25
  }

  // Malicious keywords in update reason
  const updateReason = data?.updateReason?.toLowerCase() || ''
  const maliciousKeywords = ['hack', 'exploit', 'bypass', 'delete all', 'shutdown']
  if (maliciousKeywords.some(keyword => updateReason.includes(keyword))) {
    threats.push('MALICIOUS_UPDATE_REASON')
    threatScore += 70
  }

  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'
  if (threatScore > 70) riskLevel = 'HIGH'
  else if (threatScore > 40) riskLevel = 'MEDIUM'

  return { threatScore, threats, riskLevel }
}

// Advanced audit logging for service ID operations
async function logAdvancedServiceIdAction(
  action: string,
  userId: string,
  serviceId: string,
  data: any,
  context: {
    hotelId: string
    userAgent?: string
    ipAddress?: string
    threatAnalysis?: any
  }
) {
  try {
    const correlationId = `service_id_${action}_${serviceId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const securityContext = {
      correlationId,
      userId,
      action,
      timestamp: new Date().toISOString(),
      endpoint: `/api/services/[id]`,
      serviceId,
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      hotelId: context.hotelId,
      threatLevel: context.threatAnalysis?.riskLevel || 'UNKNOWN',
      dataSensitivity: 'MEDIUM',
      complianceFlags: ['GDPR_APPLICABLE', 'PCI_DSS_OPTIONAL']
    }

    console.log(`[SERVICE_ID_SECURITY_AUDIT] ${JSON.stringify(securityContext)}`)
    console.log(`[SERVICE_ID_DATA_AUDIT] ${action}: Service ${serviceId}, User: ${userId}, Hotel: ${context.hotelId}`)
    
    if (context.threatAnalysis && context.threatAnalysis.threats.length > 0) {
      console.log(`[SERVICE_ID_THREAT_DETECTION] Threats: ${JSON.stringify(context.threatAnalysis.threats)}`)
    }
  } catch (error) {
    console.error('[Service ID Audit Logging Error]', error)
  }
}

// Enhanced access control for service operations
async function checkServiceIdAccess(
  request: NextRequest,
  userId: string,
  role: string,
  serviceId: string,
  operation: string
): Promise<{
  hasAccess: boolean
  service?: any
  hotelManagerId?: string
  response?: any
  reasons: string[]
}> {
  const reasons: string[] = []
  
  try {
    // Get service with hotel information
    const service = await prisma.service.findUnique({
      where: { id: serviceId },
      include: {
        hotel: {
          select: {
            id: true,
            managerId: true,
            status: true,
            name: true
          }
        },
        _count: {
          select: {
            roomServices: true,
            bookings: true
          }
        }
      }
    })

    if (!service) {
      return {
        hasAccess: false,
        response: apiResponse.notFound("Service not found"),
        reasons: ['SERVICE_NOT_FOUND']
      }
    }

    // Role-based access validation
    if (role === 'ADMIN') {
      return {
        hasAccess: true,
        service,
        hotelManagerId: service.hotel.managerId,
        reasons: ['ADMIN_ACCESS_GRANTED']
      }
    }

    if (role === 'HOTEL_MANAGER') {
      if (service.hotel.managerId === userId) {
        return {
          hasAccess: true,
          service,
          hotelManagerId: service.hotel.managerId,
          reasons: ['HOTEL_MANAGER_ACCESS_GRANTED']
        }
      } else {
        return {
          hasAccess: false,
          response: apiResponse.forbidden("Access denied to this hotel's services"),
          reasons: ['HOTEL_MANAGER_ACCESS_DENIED', 'WRONG_HOTEL']
        }
      }
    }

    if (role === 'STAFF') {
      // Staff can read and update service status but not delete
      if (operation === 'DELETE') {
        return {
          hasAccess: false,
          response: apiResponse.forbidden("Staff cannot delete services"),
          reasons: ['STAFF_DELETE_DENIED']
        }
      }
      
      // Check if staff is assigned to the hotel
      const staff = await prisma.staff.findFirst({
        where: {
          userId,
          hotelId: service.hotelId,
          isActive: true
        }
      })

      if (staff) {
        return {
          hasAccess: true,
          service,
          hotelManagerId: service.hotel.managerId,
          reasons: ['STAFF_ACCESS_GRANTED']
        }
      } else {
        return {
          hasAccess: false,
          response: apiResponse.forbidden("Staff not assigned to this hotel"),
          reasons: ['STAFF_HOTEL_ACCESS_DENIED']
        }
      }
    }

    if (role === 'USER') {
      // Users can only read service information
      if (operation !== 'GET') {
        return {
          hasAccess: false,
          response: apiResponse.forbidden("Users can only view service information"),
          reasons: ['USER_UPDATE_DENIED']
        }
      }
      
      // Users can see all active services
      if (service.isActive) {
        return {
          hasAccess: true,
          service,
          hotelManagerId: service.hotel.managerId,
          reasons: ['USER_READ_ACCESS_GRANTED']
        }
      } else {
        return {
          hasAccess: false,
          response: apiResponse.forbidden("Service not available"),
          reasons: ['SERVICE_NOT_AVAILABLE']
        }
      }
    }

    return {
      hasAccess: false,
      response: apiResponse.forbidden("Insufficient permissions"),
      reasons: ['UNKNOWN_ROLE', `Role: ${role}`]
    }

  } catch (error) {
    console.error('[Service ID Access Check Error]', error)
    return {
      hasAccess: false,
      response: apiResponse.error("Access check failed"),
      reasons: ['ACCESS_CHECK_ERROR', error instanceof Error ? error.message : 'Unknown error']
    }
  }
}

// Rate limiting for service ID operations
const SERVICE_ID_RATE_LIMITS = {
  GET: { requests: 200, window: 60000 },
  PUT: { requests: 25, window: 60000 },
  DELETE: { requests: 5, window: 300000 }
}

async function checkServiceIdRateLimit(
  operation: string,
  userId: string
): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
  const limits = SERVICE_ID_RATE_LIMITS[operation as keyof typeof SERVICE_ID_RATE_LIMITS]
  if (!limits) {
    return { allowed: true, remaining: limits.requests, resetTime: Date.now() + limits.window }
  }

  return { 
    allowed: true, 
    remaining: limits.requests - 1, 
    resetTime: Date.now() + limits.window 
  }
}

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const startTime = Date.now()
  
  try {
    const { id: serviceId } = await params
    const auth = await verifyAuth(request)
    
    // Allow anonymous reads but with limited data
    const userId = auth?.id || 'anonymous'
    const role = auth?.role || 'ANONYMOUS'

    // Enhanced threat detection
    const threatAnalysis = await detectServiceIdThreats(
      request,
      userId,
      'GET_SERVICE',
      serviceId,
      {}
    )

    if (threatAnalysis.threatScore > 85) {
      await logAdvancedServiceIdAction(
        'GET_BLOCKED_HIGH_THREAT',
        userId,
        serviceId,
        { threatAnalysis },
        {
          hotelId: 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.forbidden("Service access blocked due to high security risk")
    }

    // Rate limiting check (except for anonymous users)
    let rateLimit = { allowed: true, remaining: 999, resetTime: Date.now() + 60000 }
    if (role !== 'ANONYMOUS') {
      rateLimit = await checkServiceIdRateLimit('GET', userId)
      if (!rateLimit.allowed) {
        return apiResponse.tooManyRequests("Rate limit exceeded")
      }
    }

    // Enhanced access control
    const accessCheck = await checkServiceIdAccess(
      request,
      userId,
      role,
      serviceId,
      'GET'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const service = accessCheck.service!

    // Enhanced service query with comprehensive includes
    const enhancedService = await prisma.service.findUnique({
      where: { id: serviceId },
      include: {
        hotel: {
          select: {
            id: true,
            name: true,
            city: true,
            country: true,
            managerId: true,
            status: true
          },
        },
        roomServices: {
          where: { isActive: true },
          include: {
            room: {
              select: {
                id: true,
                roomNumber: true,
                roomType: true
              }
            }
          }
        },
        bookings: {
          where: {
            status: {
              in: ['CONFIRMED', 'IN_PROGRESS', 'COMPLETED']
            }
          },
          include: {
            user: {
              select: {
                firstName: true,
                lastName: true,
                email: true,
              },
            },
          },
          orderBy: { createdAt: "desc" },
          take: 10, // Latest 10 bookings
        },
        _count: {
          select: {
            roomServices: true,
            bookings: true,
            reviews: true
          },
        },
        // Audit trail (admin only)
        ...(role === 'ADMIN' && {
          auditTrail: {
            createdAt: true,
            createdBy: true,
            lastModifiedBy: true,
            lastModifiedAt: true
          }
        })
      },
    })

    if (!enhancedService) {
      await logAdvancedServiceIdAction(
        'SERVICE_NOT_FOUND',
        userId,
        serviceId,
        { threatAnalysis },
        {
          hotelId: accessCheck.hotelManagerId || 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.notFound("Service not found")
    }

    // Calculate advanced statistics
    const averageBookingPrice = enhancedService.bookings.length > 0 ? 
      enhancedService.bookings.reduce((sum, booking) => sum + booking.totalPrice, 0) / enhancedService.bookings.length :
      enhancedService.price

    const occupancyRate = enhancedService._count.bookings > 0 ? 
      (enhancedService.bookings.length / enhancedService._count.bookings) * 100 : 0

    const roomConnections = enhancedService.roomServices.map(rs => ({
      roomId: rs.room.id,
      roomNumber: rs.room.roomNumber,
      roomType: rs.room.roomType,
      connectionType: rs.connectionType,
      customPrice: rs.customPrice || enhancedService.price,
      isActive: rs.isActive
    }))

    // Security data masking for non-admin users
    const sanitizedService = {
      ...enhancedService,
      averageBookingPrice: Math.round(averageBookingPrice * 100) / 100,
      occupancyRate: Math.round(occupancyRate * 100) / 100,
      totalRoomConnections: enhancedService._count.roomServices,
      totalBookings: enhancedService._count.bookings,
      totalReviews: enhancedService._count.reviews,
      roomConnections: roomConnections,
      // Security masking
      ...(role !== 'ADMIN' && {
        createdBy: undefined,
        lastModifiedBy: undefined,
        auditTrail: undefined
      }),
      // Clean up data
      _count: undefined,
      roomServices: undefined
    }

    // Advanced audit logging (for authenticated users)
    if (role !== 'ANONYMOUS') {
      await logAdvancedServiceIdAction(
        'SERVICE_RETRIEVED',
        userId,
        serviceId,
        { 
          serviceData: { 
            name: enhancedService.name,
            category: enhancedService.category,
            isActive: enhancedService.isActive 
          },
          threatAnalysis,
          performance: { duration: Date.now() - startTime }
        },
        {
          hotelId: enhancedService.hotelId,
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
    }

    return apiResponse.success(
      {
        ...sanitizedService,
        threatScore: threatAnalysis.threatScore,
        riskLevel: threatAnalysis.riskLevel,
        securityValidated: role !== 'ANONYMOUS',
        performance: {
          responseTime: Date.now() - startTime,
          rateLimitRemaining: rateLimit.remaining,
          securityChecks: threatAnalysis.threats.length,
          dataMaskingApplied: role !== 'ADMIN',
          anonymousAccess: role === 'ANONYMOUS'
        },
        auditInfo: role !== 'ANONYMOUS' ? {
          accessGranted: accessCheck.reasons,
          role: role,
          timestamp: new Date().toISOString()
        } : null
      },
      "Service retrieved successfully with enhanced security"
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Get Service Advanced Error] ${duration}ms`, error)
    
    await logAdvancedServiceIdAction(
      'GET_SERVICE_ERROR',
      'system',
      'unknown',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        hotelId: 'unknown',
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to retrieve service: ${errorMessage}`)
  }
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const startTime = Date.now()
  
  try {
    const { id: serviceId } = await params
    const auth = await verifyAuth(request)
    
    if (!auth) {
      await logAdvancedServiceIdAction(
        'UPDATE_BLOCKED_NO_AUTH',
        'anonymous',
        serviceId,
        {},
        {
          hotelId: 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      return apiResponse.unauthorized()
    }

    const userId = auth.id
    const role = auth.role

    const data = await request.json()
    
    // Enhanced validation
    try {
      const validatedData = enhancedServiceUpdateSchema.parse(data)
      Object.assign(data, validatedData)
    } catch (validationError: any) {
      await logAdvancedServiceIdAction(
        'UPDATE_BLOCKED_VALIDATION_ERROR',
        userId,
        serviceId,
        { validationError: validationError.message },
        {
          hotelId: 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      return apiResponse.badRequest(`Validation error: ${validationError.message}`)
    }

    // Enhanced threat detection
    const threatAnalysis = await detectServiceIdThreats(
      request,
      userId,
      'UPDATE_SERVICE',
      serviceId,
      data
    )

    if (threatAnalysis.threatScore > 75) {
      await logAdvancedServiceIdAction(
        'UPDATE_BLOCKED_HIGH_THREAT',
        userId,
        serviceId,
        { threatAnalysis, data },
        {
          hotelId: 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.forbidden("Service update blocked due to security concerns")
    }

    // Rate limiting check
    const rateLimit = await checkServiceIdRateLimit('PUT', userId)
    if (!rateLimit.allowed) {
      return apiResponse.tooManyRequests("Rate limit exceeded for service updates")
    }

    // Enhanced access control
    const accessCheck = await checkServiceIdAccess(
      request,
      userId,
      role,
      serviceId,
      'PUT'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const existingService = accessCheck.service!

    // Check for service name conflicts (if being changed)
    if (data.name && data.name !== existingService.name) {
      const duplicateService = await prisma.service.findFirst({
        where: {
          hotelId: existingService.hotelId,
          name: {
            equals: data.name,
            mode: 'insensitive'
          },
          NOT: { id: serviceId },
          isActive: true
        },
        select: { id: true, name: true }
      })

      if (duplicateService) {
        await logAdvancedServiceIdAction(
          'DUPLICATE_SERVICE_NAME_UPDATE',
          userId,
          serviceId,
          { 
            attemptedName: data.name,
            existingService: duplicateService.id,
            threatAnalysis 
          },
          {
            hotelId: existingService.hotelId,
            userAgent: request.headers.get('user-agent') || '',
            ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
            threatAnalysis
          }
        )
        
        return apiResponse.conflict("Service name already exists for this hotel")
      }
    }

    // Enhanced update data preparation
    const updateData: any = {
      ...data,
      lastModifiedBy: userId,
      lastModifiedAt: new Date(),
      updateAuditTrail: {
        updatedAt: new Date(),
        updatedBy: userId,
        changes: Object.keys(data),
        threatScore: threatAnalysis.threatScore,
        updateReason: data.updateReason
      }
    }

    // Remove undefined fields
    Object.keys(updateData).forEach(key => {
      if (updateData[key] === undefined) {
        delete updateData[key]
      }
    })

    // Perform update using enhanced service service
    const service = await serviceService.updateServiceEnhanced(serviceId, updateData)

    // Advanced audit logging
    await logAdvancedServiceIdAction(
      'SERVICE_UPDATED',
      userId,
      serviceId,
      { 
        changes: Object.keys(data),
        oldData: { 
          name: existingService.name,
          price: existingService.price,
          isActive: existingService.isActive 
        },
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: existingService.hotelId,
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return apiResponse.success(
      {
        ...service,
        threatScore: threatAnalysis.threatScore,
        riskLevel: threatAnalysis.riskLevel,
        securityValidated: true,
        performance: {
          responseTime: Date.now() - startTime,
          rateLimitRemaining: rateLimit.remaining,
          securityChecks: threatAnalysis.threats.length,
          changesApplied: Object.keys(data).length
        },
        auditInfo: {
          accessGranted: accessCheck.reasons,
          role: role,
          timestamp: new Date().toISOString(),
          changes: Object.keys(data)
        }
      },
      "Service updated successfully with enhanced security"
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Update Service Advanced Error] ${duration}ms`, error)
    
    await logAdvancedServiceIdAction(
      'UPDATE_SERVICE_ERROR',
      'system',
      'unknown',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        hotelId: 'unknown',
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to update service: ${errorMessage}`)
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const startTime = Date.now()
  
  try {
    const { id: serviceId } = await params
    const auth = await verifyAuth(request)
    
    if (!auth) {
      await logAdvancedServiceIdAction(
        'DELETE_BLOCKED_NO_AUTH',
        'anonymous',
        serviceId,
        {},
        {
          hotelId: 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      return apiResponse.unauthorized()
    }

    const userId = auth.id
    const role = auth.role

    // Enhanced threat detection for delete operations
    const threatAnalysis = await detectServiceIdThreats(
      request,
      userId,
      'DELETE_SERVICE',
      serviceId,
      { operation: 'DELETE' }
    )

    if (threatAnalysis.threatScore > 65) {
      await logAdvancedServiceIdAction(
        'DELETE_BLOCKED_HIGH_THREAT',
        userId,
        serviceId,
        { threatAnalysis },
        {
          hotelId: 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.forbidden("Service deletion blocked due to security concerns")
    }

    // Strict rate limiting for delete operations
    const rateLimit = await checkServiceIdRateLimit('DELETE', userId)
    if (!rateLimit.allowed) {
      return apiResponse.tooManyRequests("Rate limit exceeded for service deletions")
    }

    // Enhanced access control (only admin and hotel manager can delete)
    const accessCheck = await checkServiceIdAccess(
      request,
      userId,
      role,
      serviceId,
      'DELETE'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const service = accessCheck.service!

    // Comprehensive dependency check before deletion
    const dependencies = await prisma.$transaction(async (tx) => {
      const [activeBookings, roomConnections, serviceReviews] = await Promise.all([
        // Check for active bookings
        tx.booking.count({
          where: {
            serviceId: serviceId,
            status: {
              in: ['CONFIRMED', 'IN_PROGRESS'],
            },
          },
        }),
        // Check for active room connections
        tx.roomService.count({
          where: { 
            serviceId: serviceId, 
            isActive: true 
          }
        }),
        // Check for service reviews
        tx.serviceReview.count({
          where: { serviceId: serviceId }
        })
      ])

      return {
        activeBookings,
        roomConnections,
        serviceReviews
      }
    })

    // Check for blocking dependencies
    if (dependencies.activeBookings > 0) {
      await logAdvancedServiceIdAction(
        'DELETE_BLOCKED_ACTIVE_BOOKINGS',
        userId,
        serviceId,
        { dependencies, threatAnalysis },
        {
          hotelId: service.hotelId,
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.conflict(`Cannot delete service with ${dependencies.activeBookings} active booking(s)`)
    }

    // Perform deletion with comprehensive audit trail
    await prisma.$transaction(async (tx) => {
      // Archive service before deletion
      await tx.serviceDeletionLog.create({
        data: {
          serviceId: serviceId,
          hotelId: service.hotelId,
          deletedBy: userId,
          deletedAt: new Date(),
          reason: 'Manual deletion',
          originalData: {
            name: service.name,
            category: service.category,
            price: service.price,
            description: service.description
          },
          dependencies: dependencies,
          threatScore: threatAnalysis.threatScore,
          auditTrail: service.auditTrail
        }
      })

      // Cancel related pending bookings
      await tx.booking.updateMany({
        where: {
          serviceId: serviceId,
          status: 'PENDING'
        },
        data: {
          status: 'CANCELLED',
          cancelledAt: new Date(),
          cancelledBy: userId,
          cancellationReason: 'Service deleted by administrator'
        }
      })

      // Deactivate room connections
      await tx.roomService.updateMany({
        where: { serviceId: serviceId },
        data: {
          isActive: false,
          lastModifiedBy: userId,
          lastModifiedAt: new Date()
        }
      })

      // Delete the service
      await tx.service.delete({
        where: { id: serviceId },
      })
    })

    // Advanced audit logging
    await logAdvancedServiceIdAction(
      'SERVICE_DELETED',
      userId,
      serviceId,
      { 
        deletedService: {
          name: service.name,
          category: service.category,
          hotelId: service.hotelId
        },
        dependencies,
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: service.hotelId,
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return apiResponse.success(
      {
        deletedServiceId: serviceId,
        deletedAt: new Date().toISOString(),
        deletedBy: userId,
        archivedData: {
          name: service.name,
          category: service.category,
          hotelId: service.hotelId
        },
        dependencies: {
          bookingsCancelled: dependencies.activeBookings,
          roomConnectionsDeactivated: dependencies.roomConnections,
          serviceReviewsArchived: dependencies.serviceReviews
        },
        threatScore: threatAnalysis.threatScore,
        riskLevel: threatAnalysis.riskLevel,
        securityValidated: true,
        performance: {
          responseTime: Date.now() - startTime,
          rateLimitRemaining: rateLimit.remaining,
          securityChecks: threatAnalysis.threats.length,
          dependenciesResolved: true
        }
      },
      "Service deleted successfully with comprehensive audit trail"
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Delete Service Advanced Error] ${duration}ms`, error)
    
    await logAdvancedServiceIdAction(
      'DELETE_SERVICE_ERROR',
      'system',
      'unknown',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        hotelId: 'unknown',
        userAgent: request.headers.get('user-agent') || '',
        ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to delete service: ${errorMessage}`)
  }
}