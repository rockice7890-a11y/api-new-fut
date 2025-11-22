import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { serviceService } from "@/lib/services/service.service"
import { apiResponse } from "@/lib/api-response"
import { z } from "zod"
import { prisma } from "@/lib/prisma"

// Enhanced validation schema for services
const enhancedServiceSchema = z.object({
  hotelId: z.string().uuid(),
  name: z.string().min(2).max(100),
  description: z.string().max(1000).optional(),
  price: z.number().min(0).max(10000),
  icon: z.string().optional(),
  category: z.enum(['ROOM_SERVICE', 'CONCIERGE', 'SPA_WELLNESS', 'FOOD_BEVERAGE', 'TRANSPORT', 'ENTERTAINMENT', 'BUSINESS', 'OTHER']).default('OTHER'),
  isActive: z.boolean().default(true),
  duration: z.number().min(0).max(1440).optional(), // Duration in minutes
  maxQuantity: z.number().min(1).max(100).optional(),
  requiresBooking: z.boolean().default(false),
  advanceBookingRequired: z.boolean().default(false),
  advanceBookingHours: z.number().min(0).max(168).optional(), // Hours in advance
  staffRequired: z.number().min(0).max(20).optional(),
  equipment: z.array(z.string()).optional(),
  restrictions: z.array(z.string()).optional(),
  availability: z.object({
    daysOfWeek: z.array(z.number().min(0).max(6)), // 0=Sunday, 6=Saturday
    startTime: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/), // HH:mm format
    endTime: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
    timezone: z.string().default('UTC')
  }).optional(),
  pricing: z.object({
    isDynamic: z.boolean().default(false),
    peakSeasonMultiplier: z.number().min(0.5).max(5).default(1),
    offSeasonDiscount: z.number().min(0).max(0.9).default(0),
    weekendMultiplier: z.number().min(0.5).max(3).default(1),
    groupDiscount: z.object({
      minGuests: z.number().min(2).max(50),
      discountPercent: z.number().min(0).max(50)
    }).optional()
  }).optional()
})

// Advanced threat detection for service operations
async function detectServiceThreats(
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

  // Price anomaly detection
  if (data?.price && data.price > 5000) {
    threats.push('ANOMALOUS_HIGH_PRICE')
    threatScore += 40
  }

  // Suspicious description patterns
  if (data?.description && data.description.length > 2000) {
    threats.push('EXCESSIVE_DESCRIPTION_LENGTH')
    threatScore += 25
  }

  // Malicious keywords in description
  const maliciousKeywords = ['hack', 'exploit', 'bypass', 'admin', 'root', 'delete']
  const description = data?.description?.toLowerCase() || ''
  if (maliciousKeywords.some(keyword => description.includes(keyword))) {
    threats.push('MALICIOUS_KEYWORDS_DETECTED')
    threatScore += 50
  }

  // Frequency-based detection (simulated)
  if (operation === 'CREATE' && data?.hotelId && data?.name) {
    // Simulate checking for duplicate service names
    if (data.name.length < 3) {
      threats.push('SUSPICIOUS_SHORT_NAME')
      threatScore += 30
    }
  }

  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'
  if (threatScore > 70) riskLevel = 'HIGH'
  else if (threatScore > 40) riskLevel = 'MEDIUM'

  return { threatScore, threats, riskLevel }
}

// Advanced audit logging for service operations
async function logAdvancedServiceAction(
  action: string,
  userId: string,
  data: any,
  context: {
    hotelId: string
    serviceId?: string
    userAgent?: string
    ipAddress?: string
    threatAnalysis?: any
  }
) {
  try {
    const correlationId = `service_${action}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const securityContext = {
      correlationId,
      userId,
      action,
      timestamp: new Date().toISOString(),
      endpoint: `/api/services`,
      method: 'POST',
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      hotelId: context.hotelId,
      serviceId: context.serviceId,
      threatLevel: context.threatAnalysis?.riskLevel || 'UNKNOWN',
      dataSensitivity: 'MEDIUM',
      complianceFlags: ['GDPR_APPLICABLE', 'PCI_DSS_OPTIONAL']
    }

    console.log(`[SERVICE_SECURITY_AUDIT] ${JSON.stringify(securityContext)}`)
    console.log(`[SERVICE_DATA_AUDIT] Action: ${action}, User: ${userId}, Hotel: ${context.hotelId}`)
    
    if (context.threatAnalysis && context.threatAnalysis.threats.length > 0) {
      console.log(`[SERVICE_THREAT_DETECTION] Threats: ${JSON.stringify(context.threatAnalysis.threats)}`)
    }
  } catch (error) {
    console.error('[Service Audit Logging Error]', error)
  }
}

// Enhanced access control for services
async function checkServiceAccess(
  request: NextRequest,
  userId: string,
  role: string,
  hotelId: string,
  operation: string
): Promise<{
  hasAccess: boolean
  hotelManagerId?: string
  response?: any
  reasons: string[]
}> {
  const reasons: string[] = []
  
  try {
    // Get hotel information
    const hotel = await prisma.hotel.findUnique({
      where: { id: hotelId },
      select: { id: true, managerId: true, status: true, name: true }
    })

    if (!hotel) {
      return {
        hasAccess: false,
        response: apiResponse.notFound("Hotel not found"),
        reasons: ['HOTEL_NOT_FOUND']
      }
    }

    // Role-based access validation
    if (role === 'ADMIN') {
      return {
        hasAccess: true,
        hotelManagerId: hotel.managerId,
        reasons: ['ADMIN_ACCESS_GRANTED']
      }
    }

    if (role === 'HOTEL_MANAGER') {
      if (hotel.managerId === userId) {
        return {
          hasAccess: true,
          hotelManagerId: hotel.managerId,
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
      // Check if staff is assigned to the hotel
      const staff = await prisma.staff.findFirst({
        where: {
          userId,
          hotelId: hotelId,
          isActive: true
        }
      })

      if (staff) {
        return {
          hasAccess: true,
          hotelManagerId: hotel.managerId,
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
      // Users can only read services
      if (operation !== 'GET') {
        return {
          hasAccess: false,
          response: apiResponse.forbidden("Users can only view services"),
          reasons: ['USER_CREATE_UPDATE_DENIED']
        }
      }
      
      return {
        hasAccess: true,
        hotelManagerId: hotel.managerId,
        reasons: ['USER_READ_ACCESS_GRANTED']
      }
    }

    return {
      hasAccess: false,
      response: apiResponse.forbidden("Insufficient permissions"),
      reasons: ['UNKNOWN_ROLE', `Role: ${role}`]
    }

  } catch (error) {
    console.error('[Service Access Check Error]', error)
    return {
      hasAccess: false,
      response: apiResponse.error("Access check failed"),
      reasons: ['ACCESS_CHECK_ERROR', error instanceof Error ? error.message : 'Unknown error']
    }
  }
}

// Performance optimization with caching for services
const serviceCache = new Map<string, { data: any; timestamp: number }>()
const SERVICE_CACHE_TTL = 300000 // 5 minutes

function getServiceCacheKey(params: any): string {
  return JSON.stringify(params)
}

function getServiceFromCache(key: string): any | null {
  const cached = serviceCache.get(key)
  if (cached && Date.now() - cached.timestamp < SERVICE_CACHE_TTL) {
    return cached.data
  }
  serviceCache.delete(key)
  return null
}

function setServiceCache(key: string, data: any): void {
  serviceCache.set(key, { data, timestamp: Date.now() })
}

// Advanced rate limiting simulation
const SERVICE_RATE_LIMITS = {
  CREATE: { requests: 15, window: 60000 },
  READ: { requests: 150, window: 60000 },
  BULK: { requests: 5, window: 300000 }
}

async function checkServiceRateLimit(
  operation: string,
  userId: string
): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
  // Simulated rate limiting (use Redis in production)
  const limits = SERVICE_RATE_LIMITS[operation as keyof typeof SERVICE_RATE_LIMITS]
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

export async function POST(request: NextRequest) {
  const startTime = Date.now()
  
  try {
    // Enhanced authentication
    const auth = await verifyAuth(request)
    if (!auth) {
      await logAdvancedServiceAction(
        'CREATE_BLOCKED_NO_AUTH',
        'anonymous',
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

    // Parse request data
    const requestData = await request.json()
    const { hotelId, name, description, price, icon } = requestData

    // Enhanced validation with custom schema
    try {
      const validatedData = enhancedServiceSchema.parse(requestData)
      Object.assign(requestData, validatedData) // Merge validated data
    } catch (validationError: any) {
      await logAdvancedServiceAction(
        'CREATE_BLOCKED_VALIDATION_ERROR',
        userId,
        { validationError: validationError.message },
        {
          hotelId: requestData.hotelId || 'unknown',
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      return apiResponse.badRequest(`Validation error: ${validationError.message}`)
    }

    // Advanced threat detection
    const threatAnalysis = await detectServiceThreats(
      request,
      userId,
      'CREATE_SERVICE',
      requestData
    )

    if (threatAnalysis.threatScore > 75) {
      await logAdvancedServiceAction(
        'CREATE_BLOCKED_HIGH_THREAT',
        userId,
        { threatAnalysis },
        {
          hotelId: requestData.hotelId,
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.forbidden("Service creation blocked due to security concerns")
    }

    // Rate limiting check
    const rateLimit = await checkServiceRateLimit('CREATE', userId)
    if (!rateLimit.allowed) {
      return apiResponse.tooManyRequests("Rate limit exceeded for service creation")
    }

    // Enhanced access control
    const accessCheck = await checkServiceAccess(
      request,
      userId,
      role,
      requestData.hotelId,
      'CREATE'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response
    }

    // Duplicate service name check with enhanced logic
    const existingService = await prisma.service.findFirst({
      where: {
        hotelId: requestData.hotelId,
        name: {
          equals: requestData.name,
          mode: 'insensitive'
        },
        isActive: true
      },
      select: { id: true, name: true, isActive: true }
    })

    if (existingService) {
      await logAdvancedServiceAction(
        'CREATE_BLOCKED_DUPLICATE_NAME',
        userId,
        { 
          serviceName: requestData.name,
          existingServiceId: existingService.id
        },
        {
          hotelId: requestData.hotelId,
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return apiResponse.conflict("Service name already exists for this hotel")
    }

    // Create enhanced service with comprehensive data
    const serviceData = {
      hotelId: requestData.hotelId,
      name: requestData.name,
      description: requestData.description,
      price: requestData.price,
      icon: requestData.icon,
      category: requestData.category,
      isActive: requestData.isActive,
      duration: requestData.duration,
      maxQuantity: requestData.maxQuantity,
      requiresBooking: requestData.requiresBooking,
      advanceBookingRequired: requestData.advanceBookingRequired,
      advanceBookingHours: requestData.advanceBookingHours,
      staffRequired: requestData.staffRequired,
      equipment: requestData.equipment || [],
      restrictions: requestData.restrictions || [],
      availability: requestData.availability,
      pricing: requestData.pricing,
      // Enhanced metadata
      createdBy: userId,
      lastModifiedBy: userId,
      auditTrail: {
        createdAt: new Date(),
        createdBy: userId,
        threatScore: threatAnalysis.threatScore,
        securityFlags: threatAnalysis.threats
      }
    }

    // Create service using enhanced service
    const service = await serviceService.createServiceEnhanced(requestData.hotelId, serviceData)

    // Clear relevant caches
    setServiceCache(`hotel_${requestData.hotelId}_services`, null)

    // Advanced audit logging
    await logAdvancedServiceAction(
      'SERVICE_CREATED',
      userId,
      { 
        serviceId: service.id,
        serviceName: service.name,
        category: service.category,
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: requestData.hotelId,
        serviceId: service.id,
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
          securityChecks: threatAnalysis.threats.length
        },
        auditInfo: {
          accessGranted: accessCheck.reasons,
          role: role,
          timestamp: new Date().toISOString()
        }
      },
      "Service created successfully with enhanced security"
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Create Service Advanced Error] ${duration}ms`, error)
    
    await logAdvancedServiceAction(
      'CREATE_SERVICE_ERROR',
      'system',
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
    return apiResponse.error(`Failed to create service: ${errorMessage}`)
  }
}

export async function GET(request: NextRequest) {
  const startTime = Date.now()
  
  try {
    // Flexible authentication (allow anonymous reads for public services)
    const auth = await verifyAuth(request)
    const userId = auth?.id || 'anonymous'
    const role = auth?.role || 'ANONYMOUS'

    const hotelId = request.nextUrl.searchParams.get("hotelId")
    const category = request.nextUrl.searchParams.get("category")
    const onlyActive = request.nextUrl.searchParams.get("onlyActive") === "true"
    const page = Number.parseInt(request.nextUrl.searchParams.get("page") || "1")
    const pageSize = Math.min(Number.parseInt(request.nextUrl.searchParams.get("pageSize") || "10"), 100)
    const sortBy = request.nextUrl.searchParams.get("sortBy") || "name"
    const sortOrder = request.nextUrl.searchParams.get("sortOrder") || "asc"

    if (!hotelId) {
      return apiResponse.badRequest("Hotel ID is required")
    }

    // Cache key generation for performance
    const cacheKey = getServiceCacheKey({
      hotelId, category, onlyActive, page, pageSize, sortBy, sortOrder,
      userRole: role
    })

    // Check cache first
    const cachedResult = getServiceFromCache(cacheKey)
    if (cachedResult) {
      return apiResponse.success(
        {
          ...cachedResult,
          performance: {
            responseTime: Date.now() - startTime,
            cacheHit: true,
            securityChecks: 0 // No auth required for cache hit
          }
        },
        "Services retrieved from cache successfully"
      )
    }

    // Enhanced access control (more permissive for GET)
    if (role !== 'ADMIN' && role !== 'ANONYMOUS') {
      const accessCheck = await checkServiceAccess(
        request,
        userId,
        role,
        hotelId,
        'GET'
      )

      if (!accessCheck.hasAccess) {
        return accessCheck.response
      }
    }

    // Enhanced query parameters
    const queryOptions: any = {
      include: {
        hotel: {
          select: {
            id: true,
            name: true,
            city: true,
            country: true
          }
        },
        _count: {
          select: {
            roomServices: true,
            bookings: true
          }
        }
      },
      where: {
        hotelId: hotelId
      },
      orderBy: {
        [sortBy]: sortOrder === 'desc' ? 'desc' : 'asc'
      },
      skip: (page - 1) * pageSize,
      take: pageSize
    }

    // Enhanced filtering
    if (category) {
      queryOptions.where.category = category
    }
    
    if (onlyActive) {
      queryOptions.where.isActive = true
    }

    // Get services with enhanced data
    const services = await prisma.service.findMany(queryOptions)

    // Enhanced data enrichment
    const enrichedServices = services.map(service => {
      const averageBookingPrice = service._count.bookings > 0 ? 
        service.price : service.price // Could be enhanced with actual booking data
      
      const availabilityInfo = service.availability ? {
        isAvailableToday: true, // Simplified for demo
        nextAvailableTime: '24/7', // Simplified for demo
        requiresAdvanceBooking: service.advanceBookingRequired
      } : null

      return {
        ...service,
        averageBookingPrice: Math.round(averageBookingPrice * 100) / 100,
        totalRoomConnections: service._count.roomServices,
        totalBookings: service._count.bookings,
        availability: availabilityInfo,
        // Clean up data
        _count: undefined,
        // Security masking for non-admin users
        ...(role !== 'ADMIN' && {
          createdBy: undefined,
          lastModifiedBy: undefined,
          auditTrail: undefined
        })
      }
    })

    // Get total count for pagination
    const total = await prisma.service.count({
      where: queryOptions.where
    })

    // Prepare response with caching
    const result = {
      services: enrichedServices,
      total,
      page,
      pageSize,
      hasMore: (page * pageSize) < total,
      cacheExpiresAt: new Date(Date.now() + SERVICE_CACHE_TTL).toISOString(),
      securityInfo: {
        accessLevel: role,
        dataFiltered: role === 'ANONYMOUS',
        publicAccess: true
      }
    }

    // Cache the result
    setServiceCache(cacheKey, result)

    // Audit logging (for authenticated users)
    if (role !== 'ANONYMOUS') {
      await logAdvancedServiceAction(
        'SERVICES_RETRIEVED',
        userId,
        { 
          query: { hotelId, category, onlyActive },
          results: total,
          performance: { duration: Date.now() - startTime }
        },
        {
          hotelId: hotelId,
          userAgent: request.headers.get('user-agent') || '',
          ipAddress: request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
    }

    return apiResponse.success(
      {
        ...result,
        performance: {
          responseTime: Date.now() - startTime,
          cacheHit: false,
          securityChecks: 0,
          totalProcessed: services.length
        }
      },
      "Services retrieved successfully with enhanced performance"
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Get Services Advanced Error] ${duration}ms`, error)
    
    await logAdvancedServiceAction(
      'SERVICES_RETRIEVAL_ERROR',
      'system',
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
    return apiResponse.error(`Failed to retrieve services: ${errorMessage}`)
  }
}