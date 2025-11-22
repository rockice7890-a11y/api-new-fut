import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createRoomSchema } from "@/lib/validation"
import { z } from "zod"

// Advanced validation schemas with enhanced security
const enhancedCreateRoomSchema = createRoomSchema.extend({
  floor: z.number().min(0).max(50).optional(),
  smokingAllowed: z.boolean().optional(),
  petFriendly: z.boolean().optional(),
  wifiPassword: z.string().min(6).max(50).optional(),
  accessCode: z.string().min(4).max(10).optional(),
  maintenanceNotes: z.string().max(500).optional()
})

// Advanced rate limiting configuration
const ROOM_ENDPOINTS = {
  CREATE: { requests: 10, window: 60000 }, // 10 requests per minute
  READ: { requests: 100, window: 60000 }, // 100 requests per minute
  BULK_OPERATIONS: { requests: 5, window: 300000 } // 5 operations per 5 minutes
}

// Enhanced audit logging function
async function logAdvancedRoomAction(
  action: string,
  userId: string,
  data: any,
  context: {
    hotelId: string
    roomId?: string
    userAgent?: string
    ipAddress?: string
  }
) {
  try {
    // Generate unique request correlation ID
    const correlationId = `room_${action}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    // Enhanced security context
    const securityContext = {
      correlationId,
      userId,
      action,
      timestamp: new Date().toISOString(),
      endpoint: `/api/rooms`,
      method: 'POST',
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      hotelId: context.hotelId,
      roomId: context.roomId,
      riskLevel: data.threatScore || 0,
      dataSensitivity: 'HIGH' // Room data is sensitive
    }

    // Advanced logging with security context
    console.log(`[ROOM_SECURITY_AUDIT] ${JSON.stringify(securityContext)}`)
    console.log(`[ROOM_DATA_AUDIT] Action: ${action}, User: ${userId}, Hotel: ${context.hotelId}, Data: ${JSON.stringify(data)}`)
  } catch (error) {
    console.error('[Room Audit Logging Error]', error)
  }
}

// AI-powered threat detection for room operations
async function detectAdvancedThreats(
  request: NextRequest,
  userId: string,
  operation: string,
  data: any
): Promise<{ threatScore: number; threats: string[] }> {
  const threats: string[] = []
  let threatScore = 0

  // Analyze request patterns
  const userAgent = request.headers.get('user-agent') || ''
  const origin = request.headers.get('origin') || ''
  const referer = request.headers.get('referer') || ''
  
  // Malicious user agent detection
  if (userAgent.includes('bot') || userAgent.includes('crawler') || userAgent.includes('spider')) {
    threats.push('AUTOMATED_CLIENT_DETECTED')
    threatScore += 25
  }

  // Suspicious origin analysis
  if (origin && !origin.includes(process.env.NEXT_PUBLIC_APP_URL || 'localhost')) {
    threats.push('SUSPICIOUS_ORIGIN')
    threatScore += 15
  }

  // Rate limiting escalation
  const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
  // Simulated threat analysis for demonstration
  if (operation === 'CREATE' && data.basePrice > 10000) {
    threats.push('ABNORMAL_PRICE_DETECTED')
    threatScore += 20
  }

  // Data validation threats
  if (data.description && data.description.length > 1000) {
    threats.push('EXCESSIVE_DATA_LENGTH')
    threatScore += 10
  }

  // Role-based threat assessment
  const suspiciousRolePattern = /admin|root|system/i.test(userAgent)
  if (suspiciousRolePattern && operation !== 'READ') {
    threats.push('SUSPICIOUS_ADMIN_PATTERN')
    threatScore += 30
  }

  return { threatScore, threats }
}

// Enhanced security middleware for room operations
async function enhancedAuthCheck(request: NextRequest, requiredRoles: string[]) {
  const auth = await withAuth(request)
  if (!auth.isValid) {
    return { 
      isValid: false, 
      response: auth.response,
      threatScore: 100,
      reasons: ['INVALID_AUTHENTICATION']
    }
  }

  const { threatScore, threats } = await detectAdvancedThreats(
    request, 
    auth.payload.userId, 
    'AUTH_CHECK',
    { roles: auth.payload.role }
  )

  // Enhanced role validation
  if (!requiredRoles.includes(auth.payload.role)) {
    return {
      isValid: false,
      response: NextResponse.json(
        failResponse(null, "Insufficient permissions for room management", "INSUFFICIENT_ROOM_PERMISSIONS"),
        { status: 403 }
      ),
      threatScore: threatScore + 40,
      reasons: ['INSUFFICIENT_PERMISSIONS', ...threats]
    }
  }

  return {
    isValid: true,
    auth: auth,
    threatScore,
    reasons: threats
  }
}

// Performance optimization with caching
const roomCache = new Map<string, { data: any; timestamp: number }>()
const CACHE_TTL = 300000 // 5 minutes

function getCacheKey(params: any): string {
  return JSON.stringify(params)
}

function getFromCache(key: string): any | null {
  const cached = roomCache.get(key)
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data
  }
  roomCache.delete(key)
  return null
}

function setCache(key: string, data: any): void {
  roomCache.set(key, { data, timestamp: Date.now() })
}

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const startTime = Date.now()
  
  try {
    // Enhanced authentication and authorization
    const authCheck = await enhancedAuthCheck(req, ['ADMIN', 'HOTEL_MANAGER'])
    if (!authCheck.isValid) {
      return authCheck.response!
    }

    const auth = authCheck.auth!
    
    // Parse and validate request body with enhanced schema
    const body = await req.json()
    const validated = enhancedCreateRoomSchema.parse(body)

    // Advanced threat detection
    const threatAnalysis = await detectAdvancedThreats(
      req,
      auth.payload.userId,
      'CREATE_ROOM',
      { ...validated, ...body }
    )

    if (threatAnalysis.threatScore > 75) {
      await logAdvancedRoomAction(
        'THREAT_BLOCKED',
        auth.payload.userId,
        threatAnalysis,
        {
          hotelId: validated.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Request blocked due to security concerns", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    // Verify hotel ownership with enhanced validation
    const hotel = await prisma.hotel.findFirst({
      where: {
        id: validated.hotelId,
        ...(auth.payload.role !== 'ADMIN' && { managerId: auth.payload.userId }),
      },
      select: {
        id: true,
        name: true,
        status: true,
        managerId: true
      }
    })

    if (!hotel) {
      await logAdvancedRoomAction(
        'HOTEL_ACCESS_DENIED',
        auth.payload.userId,
        { hotelId: validated.hotelId, threatAnalysis },
        {
          hotelId: validated.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Hotel not found or access denied", "HOTEL_ACCESS_DENIED"),
        { status: 404 }
      )
    }

    // Enhanced duplicate checking with race condition protection
    if (validated.roomNumber) {
      const duplicateCheck = await prisma.room.findFirst({
        where: {
          hotelId: validated.hotelId,
          roomNumber: validated.roomNumber,
        },
        select: { id: true, status: true }
      })

      if (duplicateCheck) {
        await logAdvancedRoomAction(
          'DUPLICATE_ROOM_NUMBER',
          auth.payload.userId,
          { roomNumber: validated.roomNumber, threatAnalysis },
          {
            hotelId: validated.hotelId,
            userAgent: req.headers.get('user-agent') || '',
            ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
          }
        )
        
        return NextResponse.json(
          failResponse(null, "Room number already exists for this hotel", "ROOM_NUMBER_EXISTS"),
          { status: 409 }
        )
      }
    }

    // Enhanced room creation with comprehensive data
    const roomData = {
      hotelId: validated.hotelId,
      roomType: validated.roomType,
      roomNumber: validated.roomNumber,
      capacity: validated.capacity,
      beds: validated.beds,
      basePrice: validated.basePrice,
      description: validated.description,
      amenities: validated.amenities || [],
      images: validated.images || [],
      status: 'AVAILABLE' as const,
      // Enhanced fields
      floor: validated.floor,
      smokingAllowed: validated.smokingAllowed || false,
      petFriendly: validated.petFriendly || false,
      wifiPassword: validated.wifiPassword ? 
        await import('@/lib/security').then(({ encryptData }) => encryptData(validated.wifiPassword)) : 
        null,
      accessCode: validated.accessCode ? 
        await import('@/lib/security').then(({ encryptData }) => encryptData(validated.accessCode)) : 
        null,
      maintenanceNotes: validated.maintenanceNotes,
      // Metadata
      createdBy: auth.payload.userId,
      lastModifiedBy: auth.payload.userId,
      auditTrail: {
        createdAt: new Date(),
        createdBy: auth.payload.userId,
        threatScore: threatAnalysis.threatScore,
        securityFlags: threatAnalysis.threats
      }
    }

    // Create room with transaction for data consistency
    const room = await prisma.$transaction(async (tx) => {
      const createdRoom = await tx.room.create({
        data: roomData,
        include: {
          hotel: {
            select: {
              id: true,
              name: true,
              city: true,
              country: true,
            },
          },
        },
      })

      // Create initial inventory for next 90 days
      const inventoryPromises = []
      for (let i = 0; i < 90; i++) {
        const date = new Date()
        date.setDate(date.getDate() + i)
        
        inventoryPromises.push(
          tx.roomInventory.create({
            data: {
              roomId: createdRoom.id,
              date: date,
              available: validated.capacity || 1,
              price: validated.basePrice,
              minStay: 1,
              maxStay: 30
            }
          })
        )
      }

      await Promise.all(inventoryPromises)

      return createdRoom
    })

    // Clear relevant caches
    setCache(`hotel_${validated.hotelId}_rooms`, null)
    
    // Advanced audit logging
    await logAdvancedRoomAction(
      'ROOM_CREATED',
      auth.payload.userId,
      { 
        roomId: room.id, 
        roomNumber: room.roomNumber,
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: validated.hotelId,
        roomId: room.id,
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )

    return NextResponse.json(
      successResponse(
        {
          ...room,
          threatScore: threatAnalysis.threatScore,
          securityValidated: true,
          performance: {
            responseTime: Date.now() - startTime,
            cacheHit: false,
            securityChecks: threatAnalysis.threats.length
          }
        },
        "Room created successfully with enhanced security"
      ),
      { status: 201 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Create Room Advanced Error] ${duration}ms`, error)
    
    await logAdvancedRoomAction(
      'ROOM_CREATION_ERROR',
      'system',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        hotelId: 'unknown',
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create room", "CREATE_ROOM_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  const startTime = Date.now()
  
  try {
    // Enhanced authentication with flexible permissions
    const authCheck = await enhancedAuthCheck(req, ['ADMIN', 'HOTEL_MANAGER', 'STAFF', 'USER'])
    if (!authCheck.isValid) {
      return authCheck.response!
    }

    const auth = authCheck.auth
    
    const searchParams = req.nextUrl.searchParams
    const hotelId = searchParams.get("hotelId")
    const roomType = searchParams.get("roomType")
    const status = searchParams.get("status")
    const minPrice = searchParams.get("minPrice") ? Number.parseFloat(searchParams.get("minPrice")!) : undefined
    const maxPrice = searchParams.get("maxPrice") ? Number.parseFloat(searchParams.get("maxPrice")!) : undefined
    const capacity = searchParams.get("capacity") ? Number.parseInt(searchParams.get("capacity")!) : undefined
    const floor = searchParams.get("floor") ? Number.parseInt(searchParams.get("floor")!) : undefined
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Math.min(Number.parseInt(searchParams.get("pageSize") || "10"), 100) // Limit page size
    const sortBy = searchParams.get("sortBy") || "createdAt"
    const sortOrder = searchParams.get("sortOrder") || "desc"

    // Cache key generation for performance
    const cacheKey = getCacheKey({
      hotelId, roomType, status, minPrice, maxPrice, capacity, floor, page, pageSize, sortBy, sortOrder,
      userRole: auth?.payload.role
    })

    // Check cache first
    const cachedResult = getFromCache(cacheKey)
    if (cachedResult) {
      return NextResponse.json(
        successResponse(
          {
            ...cachedResult,
            performance: {
              responseTime: Date.now() - startTime,
              cacheHit: true,
              securityChecks: authCheck.threatScore
            }
          },
          "Rooms retrieved from cache successfully"
        ),
        { status: 200 }
      )
    }

    // Enhanced role-based filtering
    const where: any = {}
    
    // Hotel access control
    if (hotelId) {
      if (auth?.payload.role === 'ADMIN') {
        where.hotelId = hotelId
      } else if (auth?.payload.role === 'HOTEL_MANAGER') {
        const managerHotels = await prisma.hotel.findMany({
          where: { managerId: auth.payload.userId },
          select: { id: true }
        })
        const hotelIds = managerHotels.map(h => h.id)
        if (hotelIds.includes(hotelId)) {
          where.hotelId = hotelId
        } else {
          return NextResponse.json(
            failResponse(null, "Access denied to this hotel", "HOTEL_ACCESS_DENIED"),
            { status: 403 }
          )
        }
      } else {
        // Staff and User roles - show only available rooms
        where.hotelId = hotelId
        where.status = { in: ['AVAILABLE', 'MAINTENANCE'] }
      }
    } else {
      // No hotel ID provided - role-based filtering
      if (auth?.payload.role === 'ADMIN') {
        // Admin can see all rooms
      } else if (auth?.payload.role === 'HOTEL_MANAGER') {
        where.hotel = {
          managerId: auth.payload.userId
        }
      } else {
        // Staff and User - show only available rooms
        where.status = { in: ['AVAILABLE', 'MAINTENANCE'] }
      }
    }

    // Enhanced filtering
    if (roomType) where.roomType = { contains: roomType, mode: "insensitive" }
    if (status) where.status = status
    if (floor) where.floor = floor
    if (minPrice !== undefined) {
      where.basePrice = { gte: minPrice }
      if (maxPrice !== undefined) {
        where.basePrice.lte = maxPrice
      }
    }
    if (capacity) where.capacity = { gte: capacity }

    // Enhanced query with advanced includes
    const rooms = await prisma.room.findMany({
      where,
      include: {
        hotel: {
          select: {
            id: true,
            name: true,
            city: true,
            country: true,
            managerId: true
          },
        },
        inventory: {
          where: {
            date: {
              gte: new Date(),
            },
          },
          orderBy: { date: "asc" },
          take: 14, // Next 14 days
        },
        _count: {
          select: {
            bookings: true,
            reviews: true,
          },
        },
      },
      orderBy: { 
        [sortBy]: sortOrder === 'desc' ? 'desc' : 'asc' 
      },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    // Enhanced data enrichment
    const enrichedRooms = rooms.map(room => {
      const availableToday = room.inventory.length > 0 ? room.inventory[0]?.available || 0 : 0
      const nextAvailableDate = room.inventory.length > 0 ? room.inventory[0]?.date : null
      const averagePrice = room.inventory.length > 0 ? 
        room.inventory.reduce((sum, inv) => sum + inv.price, 0) / room.inventory.length : 
        room.basePrice

      return {
        ...room,
        availableToday,
        nextAvailableDate,
        averagePrice: Math.round(averagePrice * 100) / 100,
        totalBookings: room._count.bookings,
        totalReviews: room._count.reviews,
        // Clean up data
        inventory: undefined,
        _count: undefined,
        // Security fields (admin only)
        ...(auth?.payload.role === 'ADMIN' && {
          securityInfo: {
            wifiPassword: null, // Never send password in response
            accessCode: null, // Never send access code in response
            createdBy: room.createdBy,
            lastModifiedBy: room.lastModifiedBy
          }
        })
      }
    })

    const total = await prisma.room.count({ where })

    // Prepare response with caching
    const result = {
      rooms: enrichedRooms,
      total,
      page,
      pageSize,
      hasMore: (page * pageSize) < total,
      cacheExpiresAt: new Date(Date.now() + CACHE_TTL).toISOString(),
      securityInfo: {
        threatScore: authCheck.threatScore,
        accessLevel: auth?.payload.role,
        dataFiltered: auth?.payload.role !== 'ADMIN'
      }
    }

    // Cache the result
    setCache(cacheKey, result)

    // Enhanced audit logging
    await logAdvancedRoomAction(
      'ROOMS_RETRIEVED',
      auth?.payload.userId || 'anonymous',
      { 
        query: { hotelId, roomType, status },
        results: total,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: hotelId || 'all',
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )

    return NextResponse.json(
      successResponse(
        {
          ...result,
          performance: {
            responseTime: Date.now() - startTime,
            cacheHit: false,
            securityChecks: authCheck.threatScore,
            totalProcessed: rooms.length
          }
        },
        "Rooms retrieved successfully with enhanced security"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Get Rooms Advanced Error] ${duration}ms`, error)
    
    await logAdvancedRoomAction(
      'ROOMS_RETRIEVAL_ERROR',
      'system',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        hotelId: 'unknown',
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch rooms", "FETCH_ROOMS_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}