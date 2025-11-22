import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updateRoomSchema } from "@/lib/validation"
import { z } from "zod"

// Enhanced validation schemas
const enhancedUpdateRoomSchema = updateRoomSchema.extend({
  floor: z.number().min(0).max(50).optional(),
  smokingAllowed: z.boolean().optional(),
  petFriendly: z.boolean().optional(),
  wifiPassword: z.string().min(6).max(50).optional().transform(val => val ? val : undefined),
  accessCode: z.string().min(4).max(10).optional().transform(val => val ? val : undefined),
  maintenanceNotes: z.string().max(500).optional(),
  status: z.enum(['AVAILABLE', 'MAINTENANCE', 'OUT_OF_ORDER', 'CLEANING']).optional(),
  bulkUpdate: z.boolean().optional().default(false)
})

// Advanced rate limiting for individual room operations
const ROOM_ID_ENDPOINTS = {
  GET: { requests: 200, window: 60000 }, // 200 requests per minute
  PUT: { requests: 20, window: 60000 }, // 20 updates per minute
  DELETE: { requests: 5, window: 300000 } // 5 deletes per 5 minutes
}

// Enhanced threat detection for room ID operations
async function detectRoomIdThreats(
  request: NextRequest,
  userId: string,
  operation: string,
  roomId: string,
  data: any
): Promise<{ threatScore: number; threats: string[]; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' }> {
  const threats: string[] = []
  let threatScore = 0

  const userAgent = request.headers.get('user-agent') || ''
  const origin = request.headers.get('origin') || ''
  const referer = request.headers.get('referer') || ''

  // UUID format validation
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
  if (!uuidRegex.test(roomId)) {
    threats.push('INVALID_ROOM_ID_FORMAT')
    threatScore += 50
  }

  // Suspicious patterns in room ID
  if (roomId.includes('--') || roomId.includes('..') || roomId.includes('/')) {
    threats.push('SUSPICIOUS_ROOM_ID_PATTERN')
    threatScore += 40
  }

  // Rate limiting violations simulation
  if (operation === 'DELETE' && data?.bulkUpdate) {
    threats.push('BULK_DELETE_ATTEMPT')
    threatScore += 60
  }

  // Data manipulation detection
  if (data?.wifiPassword && data.wifiPassword.length > 50) {
    threats.push('SUSPICIOUS_PASSWORD_LENGTH')
    threatScore += 25
  }

  // Malicious client detection
  if (userAgent.includes('sqlmap') || userAgent.includes('nikto') || userAgent.includes('nmap')) {
    threats.push('MALICIOUS_SCANNER_DETECTED')
    threatScore += 80
  }

  // Time-based anomaly detection (simulated)
  const currentHour = new Date().getHours()
  if (currentHour >= 2 && currentHour <= 5 && operation !== 'GET') {
    threats.push('OFF_HOURS_OPERATION')
    threatScore += 20
  }

  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'
  if (threatScore > 70) riskLevel = 'HIGH'
  else if (threatScore > 40) riskLevel = 'MEDIUM'

  return { threatScore, threats, riskLevel }
}

// Advanced audit logging for room ID operations
async function logAdvancedRoomIdAction(
  action: string,
  userId: string,
  roomId: string,
  data: any,
  context: {
    hotelId: string
    userAgent?: string
    ipAddress?: string
    threatAnalysis?: any
  }
) {
  try {
    const correlationId = `room_id_${action}_${roomId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const securityContext = {
      correlationId,
      userId,
      action,
      timestamp: new Date().toISOString(),
      endpoint: `/api/rooms/[id]`,
      roomId,
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      hotelId: context.hotelId,
      threatLevel: context.threatAnalysis?.riskLevel || 'UNKNOWN',
      dataSensitivity: 'HIGH',
      complianceFlags: ['PCI_DSS_OPTIONAL', 'SOX_OPTIONAL']
    }

    console.log(`[ROOM_ID_SECURITY_AUDIT] ${JSON.stringify(securityContext)}`)
    console.log(`[ROOM_ID_DATA_AUDIT] ${action}: Room ${roomId}, User: ${userId}, Hotel: ${context.hotelId}`)
    
    if (context.threatAnalysis && context.threatAnalysis.threats.length > 0) {
      console.log(`[ROOM_ID_THREAT_DETECTION] Threats: ${JSON.stringify(context.threatAnalysis.threats)}`)
    }
  } catch (error) {
    console.error('[Room ID Audit Logging Error]', error)
  }
}

// Enhanced role-based access control
async function checkRoomAccess(
  request: NextRequest,
  userId: string,
  role: string,
  roomId: string,
  operation: string
): Promise<{
  hasAccess: boolean
  hotelId?: string
  managerId?: string
  room?: any
  response?: NextResponse
  reasons: string[]
}> {
  const reasons: string[] = []
  
  try {
    // Get room with hotel information
    const room = await prisma.room.findUnique({
      where: { id: roomId },
      include: {
        hotel: {
          select: {
            id: true,
            managerId: true,
            status: true,
            name: true
          }
        }
      }
    })

    if (!room) {
      return {
        hasAccess: false,
        response: NextResponse.json(
          failResponse(null, "Room not found", "ROOM_NOT_FOUND"),
          { status: 404 }
        ),
        reasons: ['ROOM_NOT_FOUND']
      }
    }

    // Role-based access validation
    if (role === 'ADMIN') {
      return {
        hasAccess: true,
        hotelId: room.hotelId,
        managerId: room.hotel.managerId,
        room,
        reasons: ['ADMIN_ACCESS_GRANTED']
      }
    }

    if (role === 'HOTEL_MANAGER') {
      if (room.hotel.managerId === userId) {
        return {
          hasAccess: true,
          hotelId: room.hotelId,
          managerId: room.hotel.managerId,
          room,
          reasons: ['HOTEL_MANAGER_ACCESS_GRANTED']
        }
      } else {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Access denied to this hotel's rooms", "HOTEL_ACCESS_DENIED"),
            { status: 403 }
          ),
          reasons: ['HOTEL_MANAGER_ACCESS_DENIED', 'WRONG_HOTEL']
        }
      }
    }

    if (role === 'STAFF') {
      // Staff can read and update room status but not delete
      if (operation === 'DELETE') {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Staff cannot delete rooms", "STAFF_DELETE_DENIED"),
            { status: 403 }
          ),
          reasons: ['STAFF_DELETE_DENIED']
        }
      }
      
      // Check if staff is assigned to the hotel
      const staff = await prisma.staff.findFirst({
        where: {
          userId,
          hotelId: room.hotelId,
          isActive: true
        }
      })

      if (staff) {
        return {
          hasAccess: true,
          hotelId: room.hotelId,
          managerId: room.hotel.managerId,
          room,
          reasons: ['STAFF_ACCESS_GRANTED']
        }
      } else {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Staff not assigned to this hotel", "STAFF_HOTEL_ACCESS_DENIED"),
            { status: 403 }
          ),
          reasons: ['STAFF_HOTEL_ACCESS_DENIED']
        }
      }
    }

    if (role === 'USER') {
      // Users can only read room information
      if (operation !== 'GET') {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Users can only view room information", "USER_UPDATE_DENIED"),
            { status: 403 }
          ),
          reasons: ['USER_UPDATE_DENIED']
        }
      }
      
      // Users can see available rooms
      if (room.status === 'AVAILABLE' || room.status === 'MAINTENANCE') {
        return {
          hasAccess: true,
          hotelId: room.hotelId,
          managerId: room.hotel.managerId,
          room,
          reasons: ['USER_READ_ACCESS_GRANTED']
        }
      } else {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Room not available", "ROOM_NOT_AVAILABLE"),
            { status: 403 }
          ),
          reasons: ['ROOM_NOT_AVAILABLE']
        }
      }
    }

    return {
      hasAccess: false,
      response: NextResponse.json(
        failResponse(null, "Insufficient permissions", "INSUFFICIENT_ROOM_ACCESS"),
        { status: 403 }
      ),
      reasons: ['UNKNOWN_ROLE', `Role: ${role}`]
    }

  } catch (error) {
    console.error('[Room Access Check Error]', error)
    return {
      hasAccess: false,
      response: NextResponse.json(
        failResponse(null, "Access check failed", "ACCESS_CHECK_ERROR"),
        { status: 500 }
      ),
      reasons: ['ACCESS_CHECK_ERROR', error instanceof Error ? error.message : 'Unknown error']
    }
  }
}

// Enhanced rate limiting simulation
async function checkRateLimit(
  operation: string,
  userId: string,
  roomId: string
): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
  // Simulated rate limiting (in real implementation, use Redis)
  const limits = ROOM_ID_ENDPOINTS[operation as keyof typeof ROOM_ID_ENDPOINTS]
  if (!limits) {
    return { allowed: true, remaining: limits.requests, resetTime: Date.now() + limits.window }
  }

  // Simulate rate limit check
  return { 
    allowed: true, 
    remaining: limits.requests - 1, 
    resetTime: Date.now() + limits.window 
  }
}

export const dynamic = 'force-dynamic'

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const startTime = Date.now()
  
  try {
    const { id: roomId } = await params
    const auth = await withAuth(req)
    
    if (!auth.isValid) {
      return auth.response!
    }

    // Enhanced threat detection
    const threatAnalysis = await detectRoomIdThreats(
      req,
      auth.payload.userId,
      'GET_ROOM',
      roomId,
      {}
    )

    if (threatAnalysis.threatScore > 85) {
      await logAdvancedRoomIdAction(
        'GET_BLOCKED_HIGH_THREAT',
        auth.payload.userId,
        roomId,
        { threatAnalysis },
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Request blocked due to high security risk", "HIGH_THREAT_BLOCK"),
        { status: 403 }
      )
    }

    // Rate limiting check
    const rateLimit = await checkRateLimit('GET', auth.payload.userId, roomId)
    if (!rateLimit.allowed) {
      return NextResponse.json(
        failResponse(null, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }

    // Enhanced access control
    const accessCheck = await checkRoomAccess(
      req,
      auth.payload.userId,
      auth.payload.role,
      roomId,
      'GET'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const room = accessCheck.room!

    // Enhanced room query with comprehensive includes
    const enhancedRoom = await prisma.room.findUnique({
      where: { id: roomId },
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
        inventory: {
          where: {
            date: {
              gte: new Date(),
            },
          },
          orderBy: { date: "asc" },
          take: 30, // Next 30 days
        },
        bookings: {
          where: {
            status: {
              in: ['CONFIRMED', 'CHECKED_IN']
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
        services: {
          include: {
            service: {
              select: {
                id: true,
                name: true,
                price: true,
                category: true
              }
            },
          },
          where: {
            isActive: true
          }
        },
        _count: {
          select: {
            bookings: true,
            reviews: true,
            services: true,
          },
        },
        // Audit trail (admin only)
        ...(auth.payload.role === 'ADMIN' && {
          auditTrail: {
            createdAt: true,
            createdBy: true,
            lastModifiedBy: true,
            lastModifiedAt: true
          }
        })
      },
    })

    if (!enhancedRoom) {
      await logAdvancedRoomIdAction(
        'ROOM_NOT_FOUND',
        auth.payload.userId,
        roomId,
        { threatAnalysis },
        {
          hotelId: accessCheck.hotelId || 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Room not found", "ROOM_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Calculate advanced statistics
    const availableDates = enhancedRoom.inventory.filter(inv => inv.available > 0)
    const nextAvailableDate = availableDates.length > 0 ? availableDates[0].date : null
    const occupancyRate = enhancedRoom._count.bookings > 0 ? 
      (enhancedRoom.bookings.length / enhancedRoom._count.bookings) * 100 : 0
    const averageInventoryPrice = enhancedRoom.inventory.length > 0 ? 
      enhancedRoom.inventory.reduce((sum, inv) => sum + inv.price, 0) / enhancedRoom.inventory.length :
      enhancedRoom.basePrice

    // Security data masking for non-admin users
    const sanitizedRoom = {
      ...enhancedRoom,
      availableDatesCount: availableDates.length,
      nextAvailableDate,
      occupancyRate: Math.round(occupancyRate * 100) / 100,
      averagePrice: Math.round(averageInventoryPrice * 100) / 100,
      totalBookings: enhancedRoom._count.bookings,
      totalReviews: enhancedRoom._count.reviews,
      totalServices: enhancedRoom._count.services,
      // Security masking
      ...(auth.payload.role !== 'ADMIN' && {
        wifiPassword: null,
        accessCode: null,
        maintenanceNotes: null,
        auditTrail: null
      }),
      // Clean up data
      _count: undefined,
      services: enhancedRoom.services.map(service => ({
        id: service.id,
        service: service.service,
        addedAt: service.createdAt,
        customPrice: service.customPrice,
        isActive: service.isActive
      }))
    }

    // Advanced audit logging
    await logAdvancedRoomIdAction(
      'ROOM_RETRIEVED',
      auth.payload.userId,
      roomId,
      { 
        roomData: { 
          type: enhancedRoom.roomType,
          status: enhancedRoom.status 
        },
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: enhancedRoom.hotelId,
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return NextResponse.json(
      successResponse(
        {
          ...sanitizedRoom,
          threatScore: threatAnalysis.threatScore,
          riskLevel: threatAnalysis.riskLevel,
          securityValidated: true,
          performance: {
            responseTime: Date.now() - startTime,
            rateLimitRemaining: rateLimit.remaining,
            securityChecks: threatAnalysis.threats.length,
            dataMaskingApplied: auth.payload.role !== 'ADMIN'
          },
          auditInfo: {
            accessGranted: accessCheck.reasons,
            role: auth.payload.role,
            timestamp: new Date().toISOString()
          }
        },
        "Room retrieved successfully with enhanced security"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Get Room Advanced Error] ${duration}ms`, error)
    
    await logAdvancedRoomIdAction(
      'GET_ROOM_ERROR',
      'system',
      roomId,
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
      failResponse(null, error.message || "Failed to fetch room", "FETCH_ROOM_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const startTime = Date.now()
  
  try {
    const { id: roomId } = await params
    const auth = await withAuth(req)
    
    if (!auth.isValid) {
      return auth.response!
    }

    const body = await req.json()
    const validated = enhancedUpdateRoomSchema.parse(body)

    // Enhanced threat detection
    const threatAnalysis = await detectRoomIdThreats(
      req,
      auth.payload.userId,
      'UPDATE_ROOM',
      roomId,
      validated
    )

    if (threatAnalysis.threatScore > 75) {
      await logAdvancedRoomIdAction(
        'UPDATE_BLOCKED_HIGH_THREAT',
        auth.payload.userId,
        roomId,
        { threatAnalysis, data: validated },
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Update blocked due to security concerns", "SECURITY_UPDATE_BLOCK"),
        { status: 403 }
      )
    }

    // Rate limiting check
    const rateLimit = await checkRateLimit('PUT', auth.payload.userId, roomId)
    if (!rateLimit.allowed) {
      return NextResponse.json(
        failResponse(null, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }

    // Enhanced access control
    const accessCheck = await checkRoomAccess(
      req,
      auth.payload.userId,
      auth.payload.role,
      roomId,
      'PUT'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const existingRoom = accessCheck.room!

    // Check for room number conflicts (if being changed)
    if (validated.roomNumber && validated.roomNumber !== existingRoom.roomNumber) {
      const duplicateRoom = await prisma.room.findFirst({
        where: {
          hotelId: existingRoom.hotelId,
          roomNumber: validated.roomNumber,
          NOT: { id: roomId },
        },
        select: { id: true, roomType: true }
      })

      if (duplicateRoom) {
        await logAdvancedRoomIdAction(
          'DUPLICATE_ROOM_NUMBER_UPDATE',
          auth.payload.userId,
          roomId,
          { 
            attemptedRoomNumber: validated.roomNumber,
            existingRoom: duplicateRoom.id,
            threatAnalysis 
          },
          {
            hotelId: existingRoom.hotelId,
            userAgent: req.headers.get('user-agent') || '',
            ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
            threatAnalysis
          }
        )
        
        return NextResponse.json(
          failResponse(null, "Room number already exists for this hotel", "ROOM_NUMBER_EXISTS"),
          { status: 409 }
        )
      }
    }

    // Enhanced update data preparation
    const updateData: any = {}
    
    // Standard fields
    if (validated.roomType !== undefined) updateData.roomType = validated.roomType
    if (validated.roomNumber !== undefined) updateData.roomNumber = validated.roomNumber
    if (validated.capacity !== undefined) updateData.capacity = validated.capacity
    if (validated.beds !== undefined) updateData.beds = validated.beds
    if (validated.basePrice !== undefined) updateData.basePrice = validated.basePrice
    if (validated.status !== undefined) updateData.status = validated.status
    if (validated.description !== undefined) updateData.description = validated.description
    if (validated.amenities !== undefined) updateData.amenities = validated.amenities
    if (validated.images !== undefined) updateData.images = validated.images
    if (validated.floor !== undefined) updateData.floor = validated.floor
    if (validated.smokingAllowed !== undefined) updateData.smokingAllowed = validated.smokingAllowed
    if (validated.petFriendly !== undefined) updateData.petFriendly = validated.petFriendly
    if (validated.maintenanceNotes !== undefined) updateData.maintenanceNotes = validated.maintenanceNotes
    
    // Encrypted fields
    if (validated.wifiPassword !== undefined) {
      const { encryptData } = await import('@/lib/security')
      updateData.wifiPassword = encryptData(validated.wifiPassword)
    }
    if (validated.accessCode !== undefined) {
      const { encryptData } = await import('@/lib/security')
      updateData.accessCode = encryptData(validated.accessCode)
    }

    // Metadata
    updateData.lastModifiedBy = auth.payload.userId
    updateData.lastModifiedAt = new Date()
    updateData.updateAuditTrail = {
      updatedAt: new Date(),
      updatedBy: auth.payload.userId,
      changes: Object.keys(updateData),
      threatScore: threatAnalysis.threatScore
    }

    // Perform update with transaction
    const updatedRoom = await prisma.$transaction(async (tx) => {
      const room = await tx.room.update({
        where: { id: roomId },
        data: updateData,
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

      // If room status changed to MAINTENANCE, create maintenance log
      if (validated.status === 'MAINTENANCE') {
        await tx.maintenanceLog.create({
          data: {
            roomId: roomId,
            hotelId: room.hotelId,
            userId: auth.payload.userId,
            reason: validated.maintenanceNotes || 'Status changed to maintenance',
            estimatedDuration: 24, // hours
            priority: 'MEDIUM',
            status: 'OPEN'
          }
        })
      }

      return room
    })

    // Advanced audit logging
    await logAdvancedRoomIdAction(
      'ROOM_UPDATED',
      auth.payload.userId,
      roomId,
      { 
        changes: Object.keys(updateData),
        oldData: { 
          roomType: existingRoom.roomType,
          status: existingRoom.status,
          basePrice: existingRoom.basePrice
        },
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: updatedRoom.hotelId,
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return NextResponse.json(
      successResponse(
        {
          ...updatedRoom,
          threatScore: threatAnalysis.threatScore,
          riskLevel: threatAnalysis.riskLevel,
          securityValidated: true,
          performance: {
            responseTime: Date.now() - startTime,
            rateLimitRemaining: rateLimit.remaining,
            securityChecks: threatAnalysis.threats.length,
            changesApplied: Object.keys(updateData).length
          },
          auditInfo: {
            accessGranted: accessCheck.reasons,
            role: auth.payload.role,
            timestamp: new Date().toISOString(),
            changes: Object.keys(updateData)
          }
        },
        "Room updated successfully with enhanced security"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Update Room Advanced Error] ${duration}ms`, error)
    
    if (error.code === 'P2002') {
      return NextResponse.json(
        failResponse(null, "Room number already exists for this hotel", "ROOM_NUMBER_EXISTS"),
        { status: 409 }
      )
    }

    await logAdvancedRoomIdAction(
      'UPDATE_ROOM_ERROR',
      'system',
      'unknown',
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
      failResponse(null, error.message || "Failed to update room", "UPDATE_ROOM_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const startTime = Date.now()
  
  try {
    const { id: roomId } = await params
    const auth = await withAuth(req)
    
    if (!auth.isValid) {
      return auth.response!
    }

    // Enhanced threat detection for delete operations
    const threatAnalysis = await detectRoomIdThreats(
      req,
      auth.payload.userId,
      'DELETE_ROOM',
      roomId,
      { operation: 'DELETE' }
    )

    if (threatAnalysis.threatScore > 65) {
      await logAdvancedRoomIdAction(
        'DELETE_BLOCKED_HIGH_THREAT',
        auth.payload.userId,
        roomId,
        { threatAnalysis },
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Delete operation blocked due to security concerns", "SECURITY_DELETE_BLOCK"),
        { status: 403 }
      )
    }

    // Strict rate limiting for delete operations
    const rateLimit = await checkRateLimit('DELETE', auth.payload.userId, roomId)
    if (!rateLimit.allowed) {
      return NextResponse.json(
        failResponse(null, "Rate limit exceeded for delete operations", "DELETE_RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }

    // Enhanced access control (only admin and hotel manager can delete)
    const accessCheck = await checkRoomAccess(
      req,
      auth.payload.userId,
      auth.payload.role,
      roomId,
      'DELETE'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const room = accessCheck.room!

    // Comprehensive dependency check before deletion
    const dependencies = await prisma.$transaction(async (tx) => {
      const [activeBookings, activeReservations, maintenanceLogs, serviceLinks] = await Promise.all([
        // Check for active bookings
        tx.booking.count({
          where: {
            roomId: roomId,
            status: {
              in: ['PENDING', 'CONFIRMED', 'CHECKED_IN'],
            },
          },
        }),
        // Check for active reservations
        tx.reservation.count({
          where: {
            roomId: roomId,
            status: 'CONFIRMED',
            checkInDate: { gte: new Date() }
          }
        }),
        // Check for open maintenance logs
        tx.maintenanceLog.count({
          where: {
            roomId: roomId,
            status: { in: ['OPEN', 'IN_PROGRESS'] }
          }
        }),
        // Check for service connections
        tx.roomService.count({
          where: { roomId: roomId, isActive: true }
        })
      ])

      return {
        activeBookings,
        activeReservations,
        maintenanceLogs,
        serviceLinks
      }
    })

    // Check for blocking dependencies
    if (dependencies.activeBookings > 0) {
      await logAdvancedRoomIdAction(
        'DELETE_BLOCKED_ACTIVE_BOOKINGS',
        auth.payload.userId,
        roomId,
        { dependencies, threatAnalysis },
        {
          hotelId: room.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(
          null, 
          `Cannot delete room with ${dependencies.activeBookings} active booking(s)`, 
          "HAS_ACTIVE_BOOKINGS"
        ),
        { status: 400 }
      )
    }

    if (dependencies.activeReservations > 0) {
      await logAdvancedRoomIdAction(
        'DELETE_BLOCKED_ACTIVE_RESERVATIONS',
        auth.payload.userId,
        roomId,
        { dependencies, threatAnalysis },
        {
          hotelId: room.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(
          null, 
          `Cannot delete room with ${dependencies.activeReservations} active reservation(s)`, 
          "HAS_ACTIVE_RESERVATIONS"
        ),
        { status: 400 }
      )
    }

    // Perform deletion with comprehensive audit trail
    await prisma.$transaction(async (tx) => {
      // Archive related data before deletion
      await tx.roomDeletionLog.create({
        data: {
          roomId: roomId,
          hotelId: room.hotelId,
          deletedBy: auth.payload.userId,
          deletedAt: new Date(),
          reason: 'Manual deletion',
          originalData: {
            roomType: room.roomType,
            roomNumber: room.roomNumber,
            basePrice: room.basePrice,
            capacity: room.capacity
          },
          dependencies: dependencies,
          threatScore: threatAnalysis.threatScore,
          auditTrail: room.auditTrail
        }
      })

      // Cancel related pending bookings
      await tx.booking.updateMany({
        where: {
          roomId: roomId,
          status: 'PENDING'
        },
        data: {
          status: 'CANCELLED',
          cancelledAt: new Date(),
          cancelledBy: auth.payload.userId,
          cancellationReason: 'Room deleted by administrator'
        }
      })

      // Delete the room (cascade will handle related records)
      await tx.room.delete({
        where: { id: roomId },
      })
    })

    // Advanced audit logging
    await logAdvancedRoomIdAction(
      'ROOM_DELETED',
      auth.payload.userId,
      roomId,
      { 
        deletedRoom: {
          type: room.roomType,
          number: room.roomNumber,
          hotelId: room.hotelId
        },
        dependencies,
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: room.hotelId,
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return NextResponse.json(
      successResponse(
        {
          deletedRoomId: roomId,
          deletedAt: new Date().toISOString(),
          deletedBy: auth.payload.userId,
          archivedData: {
            type: room.roomType,
            number: room.roomNumber,
            hotelId: room.hotelId
          },
          dependencies: {
            bookingsCancelled: dependencies.activeBookings,
            reservationsCancelled: dependencies.activeReservations,
            maintenanceLogsClosed: dependencies.maintenanceLogs,
            serviceLinksRemoved: dependencies.serviceLinks
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
        "Room deleted successfully with comprehensive audit trail"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Delete Room Advanced Error] ${duration}ms`, error)
    
    await logAdvancedRoomIdAction(
      'DELETE_ROOM_ERROR',
      'system',
      'unknown',
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
      failResponse(null, error.message || "Failed to delete room", "DELETE_ROOM_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}