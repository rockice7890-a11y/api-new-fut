import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"
import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'

// Advanced Security Configuration
const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self';",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

// Enhanced Validation Schema with Advanced Security
const validatePromotionSchema = z.object({
  promoCode: z.string().min(1).max(50).regex(/^[A-Z0-9_]+$/, "Invalid promo code format").refine((val) => {
    // Prevent SQL injection patterns
    return !/['";\\]|union|select|insert|delete|update|drop|create|alter/i.test(val)
  }, "Promo code contains potentially malicious content"),
  hotelId: z.string().optional(),
  bookingDetails: z.object({
    totalAmount: z.number().positive().max(1000000, "Amount exceeds maximum allowed"),
    checkInDate: z.string().datetime().optional(),
    checkOutDate: z.string().datetime().optional(),
    nights: z.number().positive().max(365, "Nights exceed maximum allowed").optional(),
    userId: z.string().min(1, "User ID is required"),
    bookingValue: z.number().positive().max(1000000, "Booking value exceeds maximum allowed")
  })
}).refine((data) => {
  // Cross-field validation
  if (data.bookingDetails.checkInDate && data.bookingDetails.checkOutDate) {
    const checkIn = new Date(data.bookingDetails.checkInDate)
    const checkOut = new Date(data.bookingDetails.checkOutDate)
    return checkIn < checkOut
  }
  return true
}, {
  message: "Check-out date must be after check-in date",
  path: ["bookingDetails", "checkOutDate"]
})

// Advanced Security Analysis Classes
class PromotionValidationSecurityManager {
  private static readonly SUSPICIOUS_PROMO_PATTERNS = [
    /admin/i, /test/i, /demo/i, /hack/i, /exploit/i, /sql/i,
    /<script/i, /javascript:/i, /data:/i, /vbscript:/i
  ]

  private static readonly MALICIOUS_INDICATORS = [
    'union select', 'drop table', 'insert into', 'update set',
    'delete from', 'create table', 'alter table', 'exec',
    'eval(', 'function(', 'constructor(', 'prototype('
  ]

  static async performAdvancedThreatAnalysis(
    request: NextRequest,
    data: any,
    userId: string
  ): Promise<{
    isThreat: boolean
    threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    riskScore: number
    violations: string[]
    recommendations: string[]
  }> {
    const violations: string[] = []
    const recommendations: string[] = []
    let riskScore = 0
    let threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'

    const clientIP = request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""
    const contentStr = JSON.stringify(data).toLowerCase()

    // 1. Promo Code Pattern Analysis
    const promoCode = data.promoCode?.toString() || ""
    for (const pattern of this.SUSPICIOUS_PROMO_PATTERNS) {
      if (pattern.test(promoCode)) {
        violations.push(`Suspicious promo code pattern: ${pattern.source}`)
        riskScore += 40
        threatLevel = 'HIGH'
      }
    }

    // 2. Malicious Indicators Detection
    for (const indicator of this.MALICIOUS_INDICATORS) {
      if (contentStr.includes(indicator)) {
        violations.push(`Malicious indicator detected: ${indicator}`)
        riskScore += 50
        threatLevel = 'CRITICAL'
      }
    }

    // 3. User Agent Security Analysis
    if (userAgent.includes('bot') || userAgent.includes('crawler') || 
        userAgent.includes('scraper') || userAgent.includes('python') ||
        userAgent.includes('curl') || userAgent.includes('wget')) {
      violations.push("Automated tool user agent detected")
      riskScore += 25
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // 4. Rate Limiting and Frequency Analysis
    const recentValidations = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/validate' },
        action: 'VALIDATE',
        createdAt: { gte: new Date(Date.now() - 60000) } // Last minute
      },
      take: 20
    })

    if (recentValidations.length > 15) {
      violations.push("Excessive validation requests")
      riskScore += 30
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // 5. Amount Anomaly Detection
    const amount = data.bookingDetails?.totalAmount || 0
    if (amount > 100000) {
      violations.push("Unusually high booking amount")
      riskScore += 20
    }
    if (amount < 1) {
      violations.push("Suspiciously low booking amount")
      riskScore += 15
    }

    // 6. IP Geolocation Risk Assessment
    const knownHighRiskIPs = ['192.168.1.1', '10.0.0.1', '172.16.0.1'] // Simulated
    if (knownHighRiskIPs.includes(clientIP)) {
      violations.push("Request from high-risk IP range")
      riskScore += 35
      threatLevel = 'HIGH'
    }

    // 7. Time-based Anomaly Detection
    const currentHour = new Date().getHours()
    if ((currentHour < 2 || currentHour > 22) && recentValidations.length > 5) {
      violations.push("Off-hours high validation activity")
      riskScore += 20
    }

    // 8. User Behavior Pattern Analysis
    const recentFails = recentValidations.filter(v => !v.success)
    if (recentValidations.length > 10 && (recentFails.length / recentValidations.length) > 0.7) {
      violations.push("High failure rate in validations")
      riskScore += 25
    }

    // 9. Booking Pattern Validation
    const bookingValue = data.bookingDetails?.bookingValue || 0
    const totalAmount = data.bookingDetails?.totalAmount || 0
    if (totalAmount > 0 && bookingValue > 0) {
      const ratio = totalAmount / bookingValue
      if (ratio > 10 || ratio < 0.1) {
        violations.push("Suspicious booking amount ratios")
        riskScore += 20
      }
    }

    // Generate recommendations
    if (riskScore >= 80 || threatLevel === 'CRITICAL') {
      recommendations.push("Block user immediately")
      recommendations.push("Report to security team")
      recommendations.push("Review account for fraud")
    } else if (riskScore >= 50) {
      recommendations.push("Enable enhanced monitoring")
      recommendations.push("Require additional verification")
      recommendations.push("Limit future validations")
    } else if (riskScore >= 25) {
      recommendations.push("Log for manual review")
      recommendations.push("Monitor future activity closely")
    }

    const isThreat = threatLevel === 'HIGH' || threatLevel === 'CRITICAL' || riskScore >= 60

    return { isThreat, threatLevel, riskScore, violations, recommendations }
  }

  static sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      // Remove potentially dangerous content
      return input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/['";\\]/g, '')
        .trim()
        .substring(0, 1000) // Limit length
    } else if (Array.isArray(input)) {
      return input.map(item => this.sanitizeInput(item))
    } else if (typeof input === 'object' && input !== null) {
      const sanitized: any = {}
      for (const [key, value] of Object.entries(input)) {
        // Sanitize keys as well
        const sanitizedKey = key.replace(/[<>\"';]/g, '').substring(0, 50)
        sanitized[sanitizedKey] = this.sanitizeInput(value)
      }
      return sanitized
    }
    return input
  }

  static validateBusinessRules(data: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = []

    // Promo code format validation
    if (data.promoCode) {
      const promoCode = data.promoCode.toString()
      if (promoCode.length < 3 || promoCode.length > 20) {
        errors.push("Promo code must be between 3 and 20 characters")
      }
      if (!/^[A-Z0-9_]+$/.test(promoCode)) {
        errors.push("Promo code can only contain letters, numbers, and underscores")
      }
    }

    // Booking validation
    if (data.bookingDetails) {
      const { totalAmount, bookingValue, nights } = data.bookingDetails

      if (totalAmount && bookingValue) {
        if (Math.abs(totalAmount - bookingValue) > (bookingValue * 0.1)) {
          errors.push("Booking amounts are inconsistent")
        }
      }

      if (nights && nights > 30) {
        errors.push("Booking duration exceeds maximum allowed (30 days)")
      }
    }

    return { isValid: errors.length === 0, errors }
  }
}

class AdvancedSessionValidator {
  static async createSecureValidationSession(
    request: NextRequest,
    userId: string,
    promoCode: string
  ): Promise<{
    sessionId: string
    fingerprint: string
    riskScore: number
    isValid: boolean
  }> {
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""
    
    // Generate session fingerprint
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${clientIP}:${userAgent}:${userId}:${promoCode}:${Date.now()}`)
      .digest('hex')

    // Analyze validation patterns
    const recentValidations = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/validate' },
        action: 'VALIDATE',
        createdAt: { gte: new Date(Date.now() - 300000) } // Last 5 minutes
      },
      orderBy: { createdAt: 'desc' },
      take: 15
    })

    let riskScore = 0
    
    // Check for repeated promo code attempts
    const samePromoAttempts = recentValidations.filter(v => {
      try {
        const newValues = JSON.parse(v.newValues || '{}')
        return newValues.promoCode === promoCode
      } catch {
        return false
      }
    })
    
    if (samePromoAttempts.length > 5) {
      riskScore += 30
    }

    // Check for rapid-fire validations
    if (recentValidations.length > 20) {
      riskScore += 25
    }

    // Check for validation failures
    const failures = recentValidations.filter(v => !v.success)
    if (failures.length > recentValidations.length * 0.6) {
      riskScore += 35
    }

    const isValid = riskScore < 60

    return {
      sessionId: uuidv4(),
      fingerprint,
      riskScore,
      isValid
    }
  }

  static async logValidationEvent(
    event: string,
    userId: string,
    request: NextRequest,
    promoCode: string,
    details: any
  ) {
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""

    await prisma.auditLog.create({
      data: {
        userId,
        action: event,
        resource: 'PROMOTION_VALIDATION',
        endpoint: '/api/promotion-campaigns/validate',
        method: 'POST',
        ipAddress: clientIP,
        userAgent,
        newValues: JSON.stringify({
          promoCode,
          ...details
        }),
        success: true,
        createdAt: new Date()
      }
    })
  }
}

class FraudDetectionEngine {
  static async analyzeValidationFraud(
    userId: string,
    promoCode: string,
    bookingDetails: any
  ): Promise<{
    fraudScore: number
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'
    indicators: string[]
    shouldBlock: boolean
  }> {
    let fraudScore = 0
    const indicators: string[] = []
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'

    // 1. Historical Fraud Analysis
    const userHistory = await prisma.auditLog.findMany({
      where: {
        userId,
        resource: 'PROMOTION_VALIDATION',
        createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // Last 30 days
      },
      orderBy: { createdAt: 'desc' }
    })

    if (userHistory.length > 100) {
      fraudScore += 30
      indicators.push("Excessive validation history")
    }

    // 2. Promotional Code Abuse Detection
    const promoCodeAbuse = userHistory.filter(log => {
      try {
        const newValues = JSON.parse(log.newValues || '{}')
        return newValues.promoCode === promoCode
      } catch {
        return false
      }
    })

    if (promoCodeAbuse.length > 10) {
      fraudScore += 40
      indicators.push("Potential promo code abuse")
      riskLevel = 'HIGH'
    }

    // 3. Booking Pattern Analysis
    const recentBookings = await prisma.booking.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 5
    })

    if (recentBookings.length > 0) {
      const avgBookingValue = recentBookings.reduce((sum, b) => sum + b.totalPrice, 0) / recentBookings.length
      const currentBookingValue = bookingDetails.totalAmount || 0

      if (currentBookingValue > avgBookingValue * 3) {
        fraudScore += 25
        indicators.push("Unusually high booking amount")
        riskLevel = riskLevel === 'LOW' ? 'MEDIUM' : riskLevel
      }
    }

    // 4. Time-based Fraud Patterns
    const validationTimes = userHistory.slice(0, 10).map(log => log.createdAt)
    if (validationTimes.length > 5) {
      let rapidValidations = 0
      for (let i = 1; i < validationTimes.length; i++) {
        const timeDiff = Math.abs(validationTimes[i-1].getTime() - validationTimes[i].getTime())
        if (timeDiff < 30000) { // Less than 30 seconds
          rapidValidations++
        }
      }
      
      if (rapidValidations > 3) {
        fraudScore += 30
        indicators.push("Rapid successive validations")
        riskLevel = 'HIGH'
      }
    }

    // 5. Geographic Anomaly Detection (simplified)
    const recentIPs = [...new Set(userHistory.slice(0, 10).map(log => log.ipAddress))]
    if (recentIPs.length > 5) {
      fraudScore += 20
      indicators.push("Multiple IP addresses for same user")
      riskLevel = riskLevel === 'LOW' ? 'MEDIUM' : riskLevel
    }

    const shouldBlock = riskLevel === 'HIGH' || fraudScore >= 70

    return { fraudScore, riskLevel, indicators, shouldBlock }
  }
}

// Main Advanced Security Route Handler
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION & SECURITY
    const authHeader = request.headers.get("authorization")
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Authentication required for promotion validation", "AUTHENTICATION_REQUIRED"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // Basic token validation (extracted from middleware for this specific route)
    const token = authHeader.split(" ")[1]
    if (!token || token.length < 10) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Invalid authentication token", "INVALID_TOKEN"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 2. COMPREHENSIVE THREAT ANALYSIS
    const rawBody = await request.json()
    const threatAnalysis = await PromotionValidationSecurityManager.performAdvancedThreatAnalysis(
      request,
      rawBody,
      'anonymous' // Will be extracted from token after validation
    )

    if (threatAnalysis.isThreat) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_THREAT_DETECTED',
        'unknown',
        request,
        rawBody.promoCode || 'unknown',
        { threatAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Security threat detected. Validation blocked.", "SECURITY_VIOLATION"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 3. ENHANCED RATE LIMITING
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const rateLimitKey = `validate_promo:${clientIP}`
    const rateLimitCheck = rateLimit(rateLimitKey, 30, 60000) // 30 requests per minute
    
    if (!rateLimitCheck.success) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_RATE_LIMIT_EXCEEDED',
        'unknown',
        request,
        rawBody.promoCode || 'unknown',
        { rateLimitKey, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Rate limit exceeded for promotion validation", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 4. DATA SANITIZATION
    const sanitizedData = PromotionValidationSecurityManager.sanitizeInput(rawBody)

    // 5. ADVANCED VALIDATION
    const validated = validatePromotionSchema.parse(sanitizedData)
    
    // 6. BUSINESS LOGIC VALIDATION
    const businessValidation = PromotionValidationSecurityManager.validateBusinessRules(validated)
    if (!businessValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Business validation failed", "BUSINESS_LOGIC_ERROR", businessValidation.errors),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 7. USER ID EXTRACTION (simplified - in real implementation, use proper JWT decoding)
    const userId = validated.bookingDetails.userId

    // 8. FRAUD DETECTION ANALYSIS
    const fraudAnalysis = await FraudDetectionEngine.analyzeValidationFraud(
      userId,
      validated.promoCode,
      validated.bookingDetails
    )

    if (fraudAnalysis.shouldBlock) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_FRAUD_BLOCKED',
        userId,
        request,
        validated.promoCode,
        { fraudAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Potential fraud detected. Validation blocked.", "FRAUD_DETECTED"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 9. SESSION VALIDATION
    const sessionValidation = await AdvancedSessionValidator.createSecureValidationSession(
      request,
      userId,
      validated.promoCode
    )

    if (!sessionValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Session validation failed", "INVALID_SESSION"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 10. SECURE PROMOTION LOOKUP
    const promotion = await prisma.promotionCampaign.findFirst({
      where: {
        promoCode: validated.promoCode,
        status: 'ACTIVE',
        validFrom: { lte: new Date() },
        validUntil: { gte: new Date() }
      },
      include: {
        hotel: {
          select: { id: true, name: true }
        }
      }
    })

    // 11. COMPREHENSIVE VALIDATION CHECKS
    if (!promotion) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_INVALID_PROMO',
        userId,
        request,
        validated.promoCode,
        { reason: 'promo_not_found', requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Invalid or expired promo code", "INVALID_PROMO_CODE"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 12. HOTEL-SPECIFIC VALIDATION
    if (validated.hotelId && promotion.hotelId && promotion.hotelId !== validated.hotelId) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_HOTEL_MISMATCH',
        userId,
        request,
        validated.promoCode,
        { expectedHotelId: promotion.hotelId, providedHotelId: validated.hotelId, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promo code not valid for this hotel", "INVALID_HOTEL"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 13. USAGE LIMIT VALIDATION
    if (promotion.maxUses && promotion.totalUsed >= promotion.maxUses) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_USAGE_LIMIT_REACHED',
        userId,
        request,
        validated.promoCode,
        { maxUses: promotion.maxUses, totalUsed: promotion.totalUsed, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promo code usage limit reached", "USAGE_LIMIT_REACHED"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 14. USER-SPECIFIC USAGE VALIDATION
    if (promotion.maxUsesPerUser) {
      const userUsage = await prisma.promotionUsage.count({
        where: {
          campaignId: promotion.id,
          userId: validated.bookingDetails.userId
        }
      })
      
      if (userUsage >= promotion.maxUsesPerUser) {
        await AdvancedSessionValidator.logValidationEvent(
          'VALIDATION_USER_LIMIT_REACHED',
          userId,
          request,
          validated.promoCode,
          { maxUsesPerUser: promotion.maxUsesPerUser, userUsage, requestId }
        )

        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "You have reached the maximum uses for this promo code", "USER_USAGE_LIMIT_REACHED"),
            { status: 400 }
          ),
          securityHeaders
        )
      }
    }

    // 15. DAILY USAGE LIMIT VALIDATION
    if (promotion.maxUsesPerDay) {
      const today = new Date()
      today.setHours(0, 0, 0, 0)
      const tomorrow = new Date(today)
      tomorrow.setDate(tomorrow.getDate() + 1)

      const dailyUsage = await prisma.promotionUsage.count({
        where: {
          campaignId: promotion.id,
          usedAt: {
            gte: today,
            lt: tomorrow
          }
        }
      })

      if (dailyUsage >= promotion.maxUsesPerDay) {
        await AdvancedSessionValidator.logValidationEvent(
          'VALIDATION_DAILY_LIMIT_REACHED',
          userId,
          request,
          validated.promoCode,
          { maxUsesPerDay: promotion.maxUsesPerDay, dailyUsage, requestId }
        )

        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Daily usage limit reached for this promo code", "DAILY_USAGE_LIMIT_REACHED"),
            { status: 400 }
          ),
          securityHeaders
        )
      }
    }

    // 16. BOOKING VALUE VALIDATION
    if (promotion.minBookingValue && validated.bookingDetails.bookingValue < promotion.minBookingValue) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_MIN_VALUE_NOT_MET',
        userId,
        request,
        validated.promoCode,
        { minBookingValue: promotion.minBookingValue, providedValue: validated.bookingDetails.bookingValue, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Minimum booking value of ${promotion.minBookingValue} required`, "MIN_BOOKING_VALUE_NOT_MET"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    if (promotion.maxBookingValue && validated.bookingDetails.bookingValue > promotion.maxBookingValue) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_MAX_VALUE_EXCEEDED',
        userId,
        request,
        validated.promoCode,
        { maxBookingValue: promotion.maxBookingValue, providedValue: validated.bookingDetails.bookingValue, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Maximum booking value of ${promotion.maxBookingValue} allowed`, "MAX_BOOKING_VALUE_EXCEEDED"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 17. NIGHTS VALIDATION
    if (promotion.minNights && validated.bookingDetails.nights && validated.bookingDetails.nights < promotion.minNights) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_MIN_NIGHTS_NOT_MET',
        userId,
        request,
        validated.promoCode,
        { minNights: promotion.minNights, providedNights: validated.bookingDetails.nights, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Minimum stay of ${promotion.minNights} nights required`, "MIN_NIGHTS_NOT_MET"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    if (promotion.maxNights && validated.bookingDetails.nights && validated.bookingDetails.nights > promotion.maxNights) {
      await AdvancedSessionValidator.logValidationEvent(
        'VALIDATION_MAX_NIGHTS_EXCEEDED',
        userId,
        request,
        validated.promoCode,
        { maxNights: promotion.maxNights, providedNights: validated.bookingDetails.nights, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Maximum stay of ${promotion.maxNights} nights allowed`, "MAX_NIGHTS_EXCEEDED"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 18. DISCOUNT CALCULATION
    let discountAmount = 0
    let discountType = promotion.type

    switch (promotion.type) {
      case 'PERCENTAGE_OFF':
        discountAmount = (validated.bookingDetails.bookingValue * promotion.value) / 100
        if (promotion.maxDiscount && discountAmount > promotion.maxDiscount) {
          discountAmount = promotion.maxDiscount
        }
        break
      case 'FIXED_AMOUNT_OFF':
        discountAmount = Math.min(promotion.value, validated.bookingDetails.bookingValue)
        break
      case 'DISCOUNT':
        discountAmount = Math.min(promotion.value, validated.bookingDetails.bookingValue)
        break
      case 'FB_CREDIT':
      case 'SPA_CREDIT':
        discountAmount = promotion.value
        break
      default:
        discountAmount = 0
    }

    const processingTime = Date.now() - startTime

    // 19. COMPREHENSIVE AUDIT LOGGING
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'VALIDATE',
        resource: 'PROMOTION_VALIDATION',
        endpoint: '/api/promotion-campaigns/validate',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          promoCode: validated.promoCode,
          discountAmount,
          finalAmount: validated.bookingDetails.bookingValue - discountAmount,
          hotelId: promotion.hotelId,
          isValid: true
        }),
        success: true,
        processingTime,
        sessionId: sessionValidation.sessionId,
        fingerprint: sessionValidation.fingerprint,
        riskScore: sessionValidation.riskScore,
        fraudScore: fraudAnalysis.fraudScore,
        threatLevel: threatAnalysis.threatLevel
      }
    })

    // 20. SECURE RESPONSE
    const response = addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            promotion: {
              id: promotion.id,
              name: promotion.name,
              type: promotion.type,
              value: promotion.value,
              promoCode: promotion.promoCode
            },
            discountAmount,
            discountType,
            finalAmount: validated.bookingDetails.bookingValue - discountAmount,
            savings: discountAmount,
            isValid: true,
            securityMetrics: {
              requestId,
              processingTime,
              sessionRiskScore: sessionValidation.riskScore,
              fraudScore: fraudAnalysis.fraudScore,
              fraudRiskLevel: fraudAnalysis.riskLevel,
              threatLevel: threatAnalysis.threatLevel,
              threatRiskScore: threatAnalysis.riskScore,
              isSecure: true
            }
          },
          "تم التحقق من رمز العرض بنجاح"
        )
      ),
      securityHeaders
    )

    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-Security-Level', 'ADVANCED')
    response.headers.set('X-Processing-Time', processingTime.toString())
    response.headers.set('X-Threat-Level', threatAnalysis.threatLevel)
    response.headers.set('X-Fraud-Risk', fraudAnalysis.riskLevel)

    return response

  } catch (error: any) {
    const processingTime = Date.now() - startTime
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"

    // Log security incident for errors
    await prisma.auditLog.create({
      data: {
        userId: 'unknown',
        action: 'ERROR',
        resource: 'PROMOTION_VALIDATION',
        endpoint: '/api/promotion-campaigns/validate',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        errorDetails: error.message,
        success: false,
        processingTime
      }
    })

    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse({ errors: error.errors }, "بيانات التحقق من العرض غير صحيحة", "VALIDATION_ERROR"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "فشل في التحقق من رمز العرض", "VALIDATION_ERROR"),
        { status: 500 }
      ),
      securityHeaders
    )
  }
}