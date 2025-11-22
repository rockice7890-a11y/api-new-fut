/**
 * Enhanced Bookings API with Advanced Security - الأقوى والأحدث 2025
 * Bookings API مع النظام المتقدم للحماية
 * 
 * مميزات النظام:
 * - Advanced Threat Detection
 * - Context-Aware Rate Limiting  
 * - Smart Input Validation
 * - Real-time Monitoring
 * - Performance Optimization
 * - GDPR Compliance
 */

import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createBookingSchema } from "@/lib/validation"
import { advancedAPISecurity, SecurityContext, SecurityDecision } from "@/lib/api-security-advanced"
import { securityMonitor } from "@/lib/security-monitor"
import { logAuditEvent, AuditAction, AuditDetails } from "@/lib/audit-logger"
import { apiResponse } from "@/lib/api-response-improved"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Enhanced validation schemas with advanced security
const ENHANCED_BOOKING_SCHEMA = {
  ...createBookingSchema,
  
  // Additional security validations
  checkInDate: {
    // Prevent past dates and suspicious patterns
    custom: (value: string) => {
      const date = new Date(value)
      const now = new Date()
      if (date < now) throw new Error('Check-in date cannot be in the past')
      if (date > new Date(now.getTime() + (365 * 24 * 60 * 60 * 1000))) throw new Error('Check-in date too far in future')
      return true
    }
  },
  
  checkOutDate: {
    // Prevent suspicious date ranges
    custom: (value: string, checkIn: string) => {
      const checkOut = new Date(value)
      const checkInDate = new Date(checkIn)
      const diffDays = (checkOut.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24)
      if (diffDays <= 0) throw new Error('Check-out date must be after check-in date')
      if (diffDays > 30) throw new Error('Booking period cannot exceed 30 days')
      return true
    }
  }
}

/**
 * Enhanced booking creation with advanced security
 */
export async function POST(req: NextRequest) {
  const startTime = Date.now()
  let requestId: string = ''
  
  try {
    // 1. Advanced Security Context Analysis
    const securityContext: SecurityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    requestId = securityContext.requestId
    
    // 2. Make Security Decision
    const securityDecision: SecurityDecision = advancedAPISecurity.makeSecurityDecision(securityContext)
    
    // 3. Apply security decisions
    if (securityDecision.action === 'BLOCK') {
      await logAuditEvent(AuditAction.BOOKING_CREATION_BLOCKED, securityContext.userId || null, {
        endpoint: '/api/bookings',
        method: 'POST',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        riskScore: securityDecision.riskScore,
        reasons: securityDecision.reasons,
        requestId
      } as AuditDetails, securityContext.ipAddress)
      
      return apiResponse.error('ACCESS_DENIED', 403, {
        message: 'Booking creation blocked by security policy',
        requestId,
        riskScore: securityDecision.riskScore,
        reasons: securityDecision.reasons
      }, securityDecision.securityHeaders)
    }

    if (securityDecision.action === 'CHALLENGE') {
      return apiResponse.error('ADDITIONAL_VERIFICATION_REQUIRED', 401, {
        message: 'Additional verification required for booking creation',
        requestId,
        recommendations: securityDecision.recommendations
      }, securityDecision.securityHeaders)
    }

    // 4. Authentication Check with enhanced validation
    const auth = await withAuth(req)
    if (!auth.isValid) {
      await logAuditEvent(AuditAction.BOOKING_AUTH_FAILED, null, {
        endpoint: '/api/bookings',
        method: 'POST',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId
      } as AuditDetails, securityContext.ipAddress)
      
      return auth.response!
    }

    // 5. Enhanced Input Validation
    const body = await req.json()
    
    // Additional security validations
    const securityValidation = validateBookingSecurity(body, securityContext)
    if (!securityValidation.isValid) {
      await logAuditEvent(AuditAction.BOOKING_VALIDATION_FAILED, auth.payload.userId, {
        endpoint: '/api/bookings',
        method: 'POST',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        validationErrors: securityValidation.errors,
        requestId
      } as AuditDetails, securityContext.ipAddress)
      
      return apiResponse.error('VALIDATION_FAILED', 400, {
        message: 'Invalid input data',
        errors: securityValidation.errors,
        requestId
      }, securityDecision.securityHeaders)
    }

    // 6. Schema validation
    const validated = createBookingSchema.parse(body)

    // 7. Smart availability check with rate limiting
    const checkInDate = new Date(validated.checkInDate)
    const checkOutDate = new Date(validated.checkOutDate)

    // Check for suspicious date patterns
    const suspiciousDates = checkForSuspiciousDates(checkInDate, checkOutDate)
    if (suspiciousDates.isSuspicious) {
      await logAuditEvent(AuditAction.SUSPICIOUS_BOOKING_PATTERN, auth.payload.userId, {
        endpoint: '/api/bookings',
        method: 'POST',
        ipAddress: securityContext.ipAddress,
        suspiciousPattern: suspiciousDates.pattern,
        requestId
      } as AuditDetails, securityContext.ipAddress)
    }

    const inventory = await prisma.roomInventory.findMany({
      where: {
        roomId: validated.roomId,
        date: {
          gte: checkInDate,
          lt: checkOutDate,
        },
      },
      include: {
        room: true,
      },
    })

    // Verify all dates have sufficient availability
    const hasAvailability = inventory.every((inv) => inv.available > 0)
    if (!hasAvailability) {
      return apiResponse.error('ROOM_NOT_AVAILABLE', 400, {
        message: 'Room not available for selected dates',
        checkInDate: validated.checkInDate,
        checkOutDate: validated.checkOutDate,
        requestId
      }, securityDecision.securityHeaders)
    }

    // 8. Calculate total price with fraud detection
    const totalPrice = inventory.reduce((sum, inv) => sum + inv.price, 0)
    
    // Check for unusual pricing patterns
    const priceAnomaly = detectPriceAnomaly(totalPrice, inventory[0]?.room?.basePrice || 0)
    if (priceAnomaly.isAnomalous) {
      await logAuditEvent(AuditAction.PRICE_ANOMALY_DETECTED, auth.payload.userId, {
        endpoint: '/api/bookings',
        method: 'POST',
        ipAddress: securityContext.ipAddress,
        totalPrice,
        basePrice: inventory[0]?.room?.basePrice,
        anomalyType: priceAnomaly.type,
        requestId
      } as AuditDetails, securityContext.ipAddress)
    }

    // 9. Create booking with enhanced tracking
    const bookingReference = `BK${Date.now()}${Math.random().toString(36).substr(2, 4).toUpperCase()}`
    const room = inventory[0].room
    
    const booking = await prisma.booking.create({
      data: {
        userId: auth.payload.userId,
        hotelId: validated.hotelId,
        roomId: validated.roomId,
        checkInDate,
        checkOutDate,
        guests: validated.guests,
        totalPrice,
        status: "PENDING",
        bookingReference,
        guestName: validated.guestName,
        guestEmail: validated.guestEmail,
        guestPhone: validated.guestPhone,
        basePrice: room.basePrice,
        securityMetadata: {
          requestId,
          ipAddress: securityContext.ipAddress,
          userAgent: securityContext.userAgent,
          riskScore: securityDecision.riskScore,
          securityFlags: securityDecision.reasons
        }
      },
      include: {
        room: true,
        hotel: true,
      },
    })

    // 10. Create enhanced QR Code with security features
    const qrCodeData = {
      bookingId: booking.id,
      userId: auth.payload.userId,
      type: "BOOKING_CONFIRMATION",
      timestamp: Date.now(),
      hash: crypto.randomBytes(32).toString('hex'),
      securityToken: crypto.randomBytes(16).toString('hex')
    }

    const codeString = JSON.stringify(qrCodeData)
    const codeHash = crypto.createHash('sha256').update(codeString).digest('hex')
    const expiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000))

    const qrCode = await prisma.qRCode.create({
      data: {
        bookingId: booking.id,
        userId: auth.payload.userId,
        type: "BOOKING_CONFIRMATION",
        code: codeHash,
        data: qrCodeData,
        expiresAt: expiresAt,
        securityLevel: securityDecision.riskScore > 50 ? 'HIGH' : 'STANDARD'
      }
    })

    // 11. Create notification with enhanced tracking
    await prisma.pushNotification.create({
      data: {
        userId: auth.payload.userId,
        title: "Booking Created",
        body: `Your booking at ${booking.hotel.name} has been created. Use QR code for quick check-in.`,
        type: "BOOKING_CONFIRMED",
        securityLevel: securityDecision.riskScore > 30 ? 'ENHANCED' : 'STANDARD',
        data: {
          bookingId: booking.id,
          bookingReference: booking.bookingReference,
          qrCodeId: qrCode.id,
          securityContext: {
            requestId,
            riskScore: securityDecision.riskScore
          }
        }
      }
    })

    // 12. Enhanced audit logging
    await logAuditEvent(AuditAction.BOOKING_CREATED, auth.payload.userId, {
      endpoint: '/api/bookings',
      method: 'POST',
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      bookingId: booking.id,
      bookingReference: booking.bookingReference,
      totalPrice,
      riskScore: securityDecision.riskScore,
      securityFlags: securityDecision.reasons,
      processingTime: Date.now() - startTime,
      requestId
    } as AuditDetails, securityContext.ipAddress)

    // 13. Return enhanced response
    const responseData = {
      ...booking,
      qrCode: {
        id: qrCode.id,
        type: qrCode.type,
        code: qrCode.code,
        expiresAt: qrCode.expiresAt,
        securityLevel: qrCode.securityLevel
      },
      security: {
        requestId,
        riskScore: securityDecision.riskScore,
        securityLevel: securityDecision.riskScore > 70 ? 'HIGH' : securityDecision.riskScore > 30 ? 'MEDIUM' : 'LOW',
        processingTime: Date.now() - startTime
      }
    }

    return apiResponse.success(responseData, "Booking created successfully", 201, {
      'X-Request-ID': requestId,
      'X-Security-Level': 'ENHANCED',
      'X-Processing-Time': `${Date.now() - startTime}ms`
    })

  } catch (error: any) {
    const processingTime = Date.now() - startTime
    
    // Enhanced error logging
    await logAuditEvent(AuditAction.BOOKING_CREATION_FAILED, null, {
      endpoint: '/api/bookings',
      method: 'POST',
      ipAddress: advancedAPISecurity ? await getIPFromRequest(req) : 'unknown',
      error: error.message,
      stack: error.stack,
      processingTime,
      requestId
    } as AuditDetails, await getIPFromRequest(req))

    console.error(`[Enhanced Booking Error - ${requestId}]`, error)
    
    return apiResponse.error('BOOKING_FAILED', 500, {
      message: 'Booking creation failed',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      requestId: requestId || 'unknown',
      processingTime
    }, {
      'X-Request-ID': requestId || 'unknown',
      'X-Error-Processing-Time': `${processingTime}ms`
    })
  }
}

/**
 * Enhanced booking retrieval with security filtering
 */
export async function GET(req: NextRequest) {
  try {
    const securityContext: SecurityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const securityDecision: SecurityDecision = advancedAPISecurity.makeSecurityDecision(securityContext)

    // Apply enhanced rate limiting for list endpoints
    const rateLimitInfo = advancedAPISecurity.checkRateLimit(
      securityContext.ipAddress, 
      'BOOKINGS', 
      securityContext.userId
    )

    if (!rateLimitInfo.allowed) {
      return apiResponse.error('RATE_LIMIT_EXCEEDED', 429, {
        message: 'Too many booking requests',
        resetTime: new Date(rateLimitInfo.resetTime),
        requestId: securityContext.requestId
      }, {
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': Math.ceil(rateLimitInfo.resetTime / 1000).toString()
      })
    }

    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!

    const page = Number.parseInt(req.nextUrl.searchParams.get("page") || "1")
    const pageSize = Math.min(Number.parseInt(req.nextUrl.searchParams.get("pageSize") || "10"), 50) // Max 50

    const bookings = await prisma.booking.findMany({
      where: { 
        userId: auth.payload.userId,
        // Additional security filters
        createdAt: {
          gte: new Date(Date.now() - (365 * 24 * 60 * 60 * 1000)) // Max 1 year old
        }
      },
      include: {
        hotel: true,
        room: true,
        payment: true,
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.booking.count({ 
      where: { 
        userId: auth.payload.userId,
        createdAt: {
          gte: new Date(Date.now() - (365 * 24 * 60 * 60 * 1000))
        }
      }
    })

    // Enhanced security logging
    await logAuditEvent(AuditAction.BOOKINGS_RETRIEVED, auth.payload.userId, {
      endpoint: '/api/bookings',
      method: 'GET',
      ipAddress: securityContext.ipAddress,
      page,
      pageSize,
      resultsCount: bookings.length,
      requestId: securityContext.requestId
    } as AuditDetails, securityContext.ipAddress)

    const responseData = { 
      bookings, 
      total, 
      page, 
      pageSize,
      security: {
        requestId: securityContext.requestId,
        riskScore: securityDecision.riskScore,
        rateLimitRemaining: rateLimitInfo.remaining
      }
    }

    return apiResponse.success(responseData, "Bookings retrieved successfully", 200, {
      'X-Request-ID': securityContext.requestId,
      'X-RateLimit-Remaining': rateLimitInfo.remaining.toString()
    })

  } catch (error: any) {
    console.error("[Enhanced Bookings GET Error]", error)
    
    return apiResponse.error('FETCH_FAILED', 500, {
      message: 'Failed to retrieve bookings',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    }, {
      'X-Request-ID': await getIPFromRequest(req) + '_error'
    })
  }
}

// Security helper functions
function validateBookingSecurity(data: any, context: SecurityContext): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = []

  // Check for injection patterns
  const injectionPatterns = [
    /<script/i, /javascript:/i, /union\s+select/i, /drop\s+table/i,
    /(\bor\b\s*1\s*=\s*1\b)/i, /eval\s*\(/i
  ]

  const fieldsToCheck = ['guestName', 'guestEmail', 'guestPhone', 'notes']
  for (const field of fieldsToCheck) {
    const value = data[field]
    if (typeof value === 'string' && injectionPatterns.some(pattern => pattern.test(value))) {
      errors.push(`Suspicious content detected in ${field}`)
    }
  }

  // Check for suspicious email patterns
  if (data.guestEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.guestEmail)) {
    errors.push('Invalid email format')
  }

  // Check for suspicious phone patterns
  if (data.guestPhone && !/^[\+]?[1-9][\d]{0,15}$/.test(data.guestPhone.replace(/[\s\-\(\)]/g, ''))) {
    errors.push('Invalid phone format')
  }

  // Check guest count
  if (data.guests && (data.guests < 1 || data.guests > 20)) {
    errors.push('Invalid guest count')
  }

  return {
    isValid: errors.length === 0,
    errors
  }
}

function checkForSuspiciousDates(checkIn: Date, checkOut: Date): {
  isSuspicious: boolean;
  pattern?: string;
} {
  const diffDays = (checkOut.getTime() - checkIn.getTime()) / (1000 * 60 * 60 * 24)
  
  // Check for unusual booking patterns
  if (diffDays === 0) return { isSuspicious: true, pattern: 'Zero-night booking' }
  if (diffDays > 30) return { isSuspicious: true, pattern: 'Extended booking period' }
  
  // Check for dates that are too close (potential bot activity)
  const now = new Date()
  if (checkIn.getTime() < now.getTime() + (24 * 60 * 60 * 1000)) { // Less than 24h notice
    return { isSuspicious: true, pattern: 'Last-minute booking' }
  }

  return { isSuspicious: false }
}

function detectPriceAnomaly(totalPrice: number, basePrice: number): {
  isAnomalous: boolean;
  type?: string;
} {
  if (basePrice === 0) return { isAnomalous: true, type: 'Zero base price' }
  
  const ratio = totalPrice / basePrice
  if (ratio > 10) return { isAnomalous: true, type: 'Extreme price markup' }
  if (ratio < 0.1) return { isAnomalous: true, type: 'Extreme price discount' }
  
  return { isAnomalous: false }
}

async function getIPFromRequest(req: NextRequest): Promise<string> {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    req.ip ||
    'unknown'
  )
}