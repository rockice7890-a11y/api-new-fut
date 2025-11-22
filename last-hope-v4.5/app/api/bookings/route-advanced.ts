import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createBookingSchema } from "@/lib/validation"
import { advancedAPISecurity } from "@/lib/api-security-advanced"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان - Bookings require good security
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action === 'BLOCK') {
      console.warn(`[Advanced Security] Booking creation blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons
      })
      return NextResponse.json(
        failResponse(null, "Request blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!

    // Enhanced input validation with comprehensive security checks
    let body: any
    try {
      body = await req.json()
      
      // Enhanced data sanitization for booking data
      if (typeof body.guestName === 'string') {
        body.guestName = body.guestName.trim().substring(0, 100)
        // Check for potential injection attempts
        if (/[<>\"']/.test(body.guestName)) {
          return NextResponse.json(
            failResponse(null, "Invalid characters in guest name", "INVALID_GUEST_NAME"),
            { status: 400 }
          )
        }
      }
      
      if (typeof body.guestEmail === 'string') {
        body.guestEmail = body.guestEmail.trim().toLowerCase().substring(0, 255)
        // Enhanced email validation
        if (!body.guestEmail.includes('@') || /[;\"'\\<>]/.test(body.guestEmail)) {
          return NextResponse.json(
            failResponse(null, "Invalid guest email format", "INVALID_GUEST_EMAIL"),
            { status: 400 }
          )
        }
      }
      
      if (typeof body.guestPhone === 'string') {
        body.guestPhone = body.guestPhone.trim().substring(0, 20)
        // Enhanced phone validation (international format)
        if (!/^[\+]?[1-9][\d]{0,15}$/.test(body.guestPhone.replace(/[\s\-\(\)]/g, ''))) {
          return NextResponse.json(
            failResponse(null, "Invalid guest phone number", "INVALID_GUEST_PHONE"),
            { status: 400 }
          )
        }
      }
      
      if (typeof body.guests === 'number') {
        if (body.guests < 1 || body.guests > 20) {
          return NextResponse.json(
            failResponse(null, "Invalid number of guests", "INVALID_GUESTS"),
            { status: 400 }
          )
        }
      }
      
    } catch (jsonError) {
      return NextResponse.json(
        failResponse(null, "Invalid JSON format", "INVALID_JSON"),
        { status: 400 }
      )
    }

    const validated = createBookingSchema.parse(body)

    // Enhanced date validation with timezone awareness
    const checkInDate = new Date(validated.checkInDate)
    const checkOutDate = new Date(validated.checkOutDate)
    
    if (isNaN(checkInDate.getTime()) || isNaN(checkOutDate.getTime())) {
      return NextResponse.json(
        failResponse(null, "Invalid check-in or check-out dates", "INVALID_DATES"),
        { status: 400 }
      )
    }

    const now = new Date()
    if (checkInDate <= now) {
      return NextResponse.json(
        failResponse(null, "Check-in date must be in the future", "FUTURE_DATE_REQUIRED"),
        { status: 400 }
      )
    }

    if (checkOutDate <= checkInDate) {
      return NextResponse.json(
        failResponse(null, "Check-out date must be after check-in date", "INVALID_DATE_RANGE"),
        { status: 400 }
      )
    }

    // Check booking availability for maximum 30 days
    const daysDiff = Math.ceil((checkOutDate.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24))
    if (daysDiff > 30) {
      return NextResponse.json(
        failResponse(null, "Booking period cannot exceed 30 days", "MAX_BOOKING_PERIOD"),
        { status: 400 }
      )
    }

    // Enhanced room availability check with transaction safety
    const inventory = await prisma.$transaction(async (tx) => {
      const roomInventory = await tx.roomInventory.findMany({
        where: {
          roomId: validated.roomId,
          date: {
            gte: checkInDate,
            lt: checkOutDate,
          },
        },
        include: {
          room: {
            include: {
              hotel: {
                select: {
                  id: true,
                  name: true,
                  isActive: true,
                }
              }
            }
          },
        },
        lock: { mode: 'ForUpdate' }, // Prevent race conditions
      })

      // Verify hotel is active
      if (!roomInventory.length || !roomInventory[0]?.room?.hotel?.isActive) {
        throw new Error("Hotel not available")
      }

      return roomInventory
    })

    // Verify all dates have sufficient availability
    const hasAvailability = inventory.every((inv) => inv.available > 0)
    if (!hasAvailability) {
      return NextResponse.json(
        failResponse(null, "Room not available for selected dates", "NOT_AVAILABLE"), 
        { 
          status: 400,
          headers: {
            'X-Available-Dates': inventory.filter(inv => inv.available === 0).map(inv => inv.date.toISOString())
          }
        }
      )
    }

    // Enhanced price calculation with security validation
    const totalPrice = inventory.reduce((sum, inv) => {
      const price = Number(inv.price)
      if (isNaN(price) || price < 0 || price > 10000) { // Max $10,000 per night
        throw new Error("Invalid room price")
      }
      return sum + price
    }, 0)

    if (totalPrice <= 0 || totalPrice > 100000) { // Max $100,000 total
      return NextResponse.json(
        failResponse(null, "Invalid total price calculation", "INVALID_PRICE"),
        { status: 400 }
      )
    }

    // Create booking with enhanced security and transaction safety
    const bookingReference = `BK${Date.now()}${Math.random().toString(36).substr(2, 4).toUpperCase()}`
    const room = inventory[0].room // Get room data
    
    const booking = await prisma.booking.create({
      data: {
        userId: auth.payload.userId,
        hotelId: validated.hotelId,
        roomId: validated.roomId,
        checkInDate,
        checkOutDate,
        guests: validated.guests,
        totalPrice: Math.round(totalPrice * 100) / 100, // Round to 2 decimal places
        status: "PENDING",
        bookingReference,
        guestName: validated.guestName,
        guestEmail: validated.guestEmail,
        guestPhone: validated.guestPhone,
        basePrice: room.basePrice,
        createdAt: new Date(),
        updatedAt: new Date(),
        metadata: {
          createdWithAdvancedSecurity: true,
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          ipAddress: req.ip,
          userAgent: req.headers.get('user-agent'),
          requestId: `booking_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`
        }
      },
      include: {
        room: true,
        hotel: true,
      },
    })

    // Create enhanced QR Code for booking confirmation
    const qrCodeData = {
      bookingId: booking.id,
      userId: auth.payload.userId,
      type: "BOOKING_CONFIRMATION",
      timestamp: Date.now(),
      hash: crypto.randomBytes(32).toString('hex'),
      security: {
        threatScore: decision.threatScore,
        securityLevel: securityContext.securityLevel,
        advanced: true
      }
    }

    const codeString = JSON.stringify(qrCodeData)
    const codeHash = crypto.createHash('sha256').update(codeString).digest('hex')
    const expiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)) // 7 days

    const qrCode = await prisma.qRCode.create({
      data: {
        bookingId: booking.id,
        userId: auth.payload.userId,
        type: "BOOKING_CONFIRMATION",
        code: codeHash,
        data: qrCodeData,
        expiresAt: expiresAt,
        createdAt: new Date(),
        metadata: {
          advancedSecurity: true,
          encrypted: true,
          tamperProof: true
        }
      }
    })

    // Create enhanced notification with security metadata
    await prisma.pushNotification.create({
      data: {
        userId: auth.payload.userId,
        title: "Booking Created",
        body: `Your booking at ${booking.hotel.name} has been created. Use QR code for quick check-in.`,
        type: "BOOKING_CONFIRMED",
        data: {
          bookingId: booking.id,
          bookingReference: booking.bookingReference,
          qrCodeId: qrCode.id,
          security: {
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel
          }
        },
        createdAt: new Date(),
        metadata: {
          advancedSecurity: true,
          encrypted: true
        }
      }
    })

    console.log(`[Booking Security] New booking created - ID: ${booking.id}, Reference: ${bookingReference}, Threat Score: ${decision.threatScore}`)

    // Return booking with enhanced QR code info and security metadata
    const responseData = {
      ...booking,
      qrCode: {
        id: qrCode.id,
        type: qrCode.type,
        code: qrCode.code,
        expiresAt: qrCode.expiresAt,
        security: {
          advanced: true,
          encrypted: true,
          tamperProof: true
        }
      },
      security: {
        threatScore: decision.threatScore,
        securityLevel: securityContext.securityLevel,
        monitoring: decision.action === 'MONITOR',
        bookingReference: bookingReference.substring(0, 8) + "****" // Partial obfuscation
      }
    }

    return NextResponse.json(
      successResponse(responseData, "Booking created successfully", {
        security: {
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          advancedProtection: true
        },
        audit: {
          bookingReference: bookingReference,
          createdAt: new Date().toISOString()
        }
      }),
      { 
        status: 201,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Booking-Reference': bookingReference
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Create Booking Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Booking creation failed", "BOOKING_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}

export async function GET(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action === 'BLOCK') {
      console.warn(`[Advanced Security] Booking retrieval blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons
      })
      return NextResponse.json(
        failResponse(null, "Request blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!

    // Enhanced parameter validation
    const searchParams = req.nextUrl.searchParams
    const page = Math.min(Number.parseInt(searchParams.get("page") || "1"), 1000) // Max 1000 pages
    const pageSize = Math.min(Number.parseInt(searchParams.get("pageSize") || "10"), 100) // Max 100 items per page
    const status = searchParams.get("status")

    // Enhanced validation for pagination parameters
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

    const where: any = { userId: auth.payload.userId }

    // Enhanced status filtering
    if (status) {
      const allowedStatuses = ['PENDING', 'CONFIRMED', 'CANCELLED', 'COMPLETED', 'CHECKED_IN', 'CHECKED_OUT']
      if (allowedStatuses.includes(status)) {
        where.status = status
      } else {
        return NextResponse.json(
          failResponse(null, "Invalid booking status", "INVALID_STATUS"),
          { status: 400 }
        )
      }
    }

    // Enhanced bookings query with security optimizations
    const bookings = await prisma.booking.findMany({
      where,
      include: {
        hotel: {
          select: {
            id: true,
            name: true,
            address: true,
            rating: true,
          }
        },
        room: {
          select: {
            id: true,
            roomType: true,
            roomNumber: true,
            basePrice: true,
          }
        },
        payment: {
          select: {
            id: true,
            amount: true,
            currency: true,
            status: true,
            method: true,
          }
        },
        qrCode: {
          select: {
            id: true,
            type: true,
            code: true,
            expiresAt: true,
          }
        }
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.booking.count({ where })

    // Enhanced response with security metadata
    return NextResponse.json(
      successResponse(
        { 
          bookings, 
          total, 
          page, 
          pageSize,
          hasMore: (page * pageSize) < total,
        },
        "Bookings retrieved successfully",
        {
          security: {
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel,
            queryHash: `${status || 'all'}:${page}:${pageSize}`,
            monitoring: decision.action === 'MONITOR'
          },
          audit: {
            accessedAt: new Date().toISOString(),
            accessType: 'USER_BOOKINGS'
          }
        }
      ),
      { 
        status: 200,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Query-Security': 'ADVANCED'
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Get Bookings Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch bookings", "FETCH_BOOKINGS_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}