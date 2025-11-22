import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { DiscountService } from "@/lib/services/discount.service"
import { prisma } from "@/lib/prisma"
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

// Enhanced Validation Schema
const discountValidationSchema = z.object({
  hotelId: z.string().min(1, "Hotel ID is required"),
  code: z.string().min(1).max(50).regex(/^[A-Z0-9_]+$/, "Invalid discount code format").refine((val) => {
    // Prevent injection attacks
    return !/['";\\]|union|select|insert|delete|update|drop|create|alter/i.test(val)
  }, "Discount code contains potentially malicious content"),
  bookingDetails: z.object({
    totalPrice: z.number().positive().max(1000000, "Total price exceeds maximum allowed"),
    checkInDate: z.string().datetime().optional(),
    checkOutDate: z.string().datetime().optional(),
    roomType: z.string().max(100).optional(),
    guests: z.number().int().min(1).max(20, "Guest count exceeds maximum allowed").optional()
  })
}).refine((data) => {
  // Validate date consistency if provided
  if (data.bookingDetails.checkInDate && data.bookingDetails.checkOutDate) {
    const checkIn = new Date(data.bookingDetails.checkInDate)
    const checkOut = new Date(data.bookingDetails.checkOutDate)
    return checkIn < checkOut && (checkOut.getTime() - checkIn.getTime()) <= (365 * 24 * 60 * 60 * 1000) // Max 1 year
  }
  return true
}, {
  message: "Invalid date range or duration",
  path: ["bookingDetails", "checkOutDate"]
})

// Advanced Security Management Classes
class DiscountSecurityManager {
  private static readonly SUSPICIOUS_CODE_PATTERNS = [
    /admin/i, /test/i, /demo/i, /hack/i, /exploit/i, /sql/i,
    /<script/i, /javascript:/i, /data:/i, /vbscript:/i
  ]

  private static readonly MALICIOUS_PATTERNS = [
    'union select', 'drop table', 'insert into', 'update set',
    'delete from', 'create table', 'alter table', 'exec(',
    'eval(', 'function(', 'constructor(', 'prototype('
  ]

  static async performAdvancedSecurityAnalysis(
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

    // 1. Code Pattern Analysis
    const discountCode = data.code?.toString() || ""
    for (const pattern of this.SUSPICIOUS_CODE_PATTERNS) {
      if (pattern.test(discountCode)) {
        violations.push(`Suspicious discount code pattern: ${pattern.source}`)
        riskScore += 35
        threatLevel = 'HIGH'
      }
    }

    // 2. Malicious Pattern Detection
    for (const pattern of this.MALICIOUS_PATTERNS) {
      if (contentStr.includes(pattern)) {
        violations.push(`Malicious pattern detected: ${pattern}`)
        riskScore += 50
        threatLevel = 'CRITICAL'
      }
    }

    // 3. User Agent Security Check
    if (userAgent.includes('bot') || userAgent.includes('crawler') || 
        userAgent.includes('scraper') || userAgent.includes('python') ||
        userAgent.includes('curl') || userAgent.includes('wget') ||
        userAgent.includes('postman')) {
      violations.push("Automated client detected")
      riskScore += 25
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // 4. Frequency and Rate Analysis
    const recentValidations = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/discounts/validate' },
        createdAt: { gte: new Date(Date.now() - 60000) } // Last minute
      },
      take: 25
    })

    if (recentValidations.length > 20) {
      violations.push("Excessive discount validation requests")
      riskScore += 30
      threatLevel = 'MEDIUM'
    }

    // 5. Amount and Value Anomaly Detection
    const totalPrice = data.bookingDetails?.totalPrice || 0
    if (totalPrice > 500000) {
      violations.push("Unusually high booking total price")
      riskScore += 25
    }
    if (totalPrice < 1) {
      violations.push("Suspiciously low total price")
      riskScore += 20
    }

    // 6. IP Risk Assessment
    const highRiskIPRanges = ['192.168.1.', '10.0.0.', '172.16.0.', '127.0.0.'] // Simulated
    const isHighRiskIP = highRiskIPRanges.some(range => clientIP.startsWith(range))
    if (isHighRiskIP) {
      violations.push("Request from internal/suspicious IP range")
      riskScore += 30
      threatLevel = 'HIGH'
    }

    // 7. Temporal Anomaly Detection
    const currentHour = new Date().getHours()
    if ((currentHour < 3 || currentHour > 23) && recentValidations.length > 5) {
      violations.push("Off-hours high validation activity")
      riskScore += 20
    }

    // 8. Booking Pattern Analysis
    const guests = data.bookingDetails?.guests || 0
    const roomType = data.bookingDetails?.roomType || ""
    if (guests > 10) {
      violations.push("Unusually large group booking")
      riskScore += 15
    }
    if (roomType && roomType.length > 50) {
      violations.push("Suspicious room type description length")
      riskScore += 10
    }

    // Generate security recommendations
    if (riskScore >= 80 || threatLevel === 'CRITICAL') {
      recommendations.push("Block user immediately")
      recommendations.push("Report to security team")
      recommendations.push("Review account status")
    } else if (riskScore >= 50) {
      recommendations.push("Enable enhanced validation")
      recommendations.push("Require additional verification")
      recommendations.push("Monitor closely")
    } else if (riskScore >= 25) {
      recommendations.push("Log for review")
      recommendations.push("Apply additional scrutiny")
    }

    const isThreat = threatLevel === 'HIGH' || threatLevel === 'CRITICAL' || riskScore >= 60

    return { isThreat, threatLevel, riskScore, violations, recommendations }
  }

  static sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      return input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/['";\\]/g, '')
        .trim()
        .substring(0, 500)
    } else if (Array.isArray(input)) {
      return input.map(item => this.sanitizeInput(item))
    } else if (typeof input === 'object' && input !== null) {
      const sanitized: any = {}
      for (const [key, value] of Object.entries(input)) {
        const sanitizedKey = key.replace(/[<>\"';]/g, '').substring(0, 30)
        sanitized[sanitizedKey] = this.sanitizeInput(value)
      }
      return sanitized
    }
    return input
  }
}

class AdvancedSessionSecurity {
  static async createSecureValidationSession(
    request: NextRequest,
    userId: string,
    discountCode: string
  ): Promise<{
    sessionId: string
    fingerprint: string
    riskScore: number
    isValid: boolean
  }> {
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""
    
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${clientIP}:${userAgent}:${userId}:${discountCode}`)
      .digest('hex')

    // Analyze validation patterns
    const recentSessions = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/discounts/validate' },
        createdAt: { gte: new Date(Date.now() - 180000) } // Last 3 minutes
      },
      orderBy: { createdAt: 'desc' },
      take: 20
    })

    let riskScore = 0
    
    // Check for rapid re-validation attempts
    const sameCodeAttempts = recentSessions.filter(s => {
      try {
        const newValues = JSON.parse(s.newValues || '{}')
        return newValues.code === discountCode
      } catch {
        return false
      }
    })
    
    if (sameCodeAttempts.length > 3) {
      riskScore += 30
    }

    // Check for high frequency
    if (recentSessions.length > 15) {
      riskScore += 25
    }

    // Check for high failure rate
    const failures = recentSessions.filter(s => !s.success)
    if (recentSessions.length > 0 && (failures.length / recentSessions.length) > 0.7) {
      riskScore += 35
    }

    const isValid = riskScore < 65

    return {
      sessionId: uuidv4(),
      fingerprint,
      riskScore,
      isValid
    }
  }

  static async logSecurityEvent(
    event: string,
    userId: string,
    request: NextRequest,
    discountCode: string,
    details: any
  ) {
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""

    await prisma.auditLog.create({
      data: {
        userId,
        action: event,
        resource: 'DISCOUNT_VALIDATION',
        endpoint: '/api/discounts/validate',
        method: 'POST',
        ipAddress: clientIP,
        userAgent,
        newValues: JSON.stringify({
          discountCode,
          ...details
        }),
        success: true,
        createdAt: new Date()
      }
    })
  }
}

class DiscountFraudDetector {
  static async analyzeFraudPatterns(
    userId: string,
    discountCode: string,
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

    // 1. Historical Discount Usage Analysis
    const discountHistory = await prisma.auditLog.findMany({
      where: {
        userId,
        resource: 'DISCOUNT_VALIDATION',
        createdAt: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } // Last 7 days
      },
      orderBy: { createdAt: 'desc' }
    })

    if (discountHistory.length > 50) {
      fraudScore += 25
      indicators.push("Excessive discount validation history")
    }

    // 2. Code Abuse Detection
    const sameCodeValidations = discountHistory.filter(log => {
      try {
        const newValues = JSON.parse(log.newValues || '{}')
        return newValues.code === discountCode
      } catch {
        return false
      }
    })

    if (sameCodeValidations.length > 5) {
      fraudScore += 40
      indicators.push("Potential discount code abuse")
      riskLevel = 'HIGH'
    }

    // 3. Booking Value Analysis
    const recentBookings = await prisma.booking.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 3
    })

    if (recentBookings.length > 0) {
      const avgBookingValue = recentBookings.reduce((sum, b) => sum + b.totalPrice, 0) / recentBookings.length
      const currentValue = bookingDetails.totalPrice || 0

      if (currentValue > avgBookingValue * 5) {
        fraudScore += 30
        indicators.push("Unusually high booking value")
        riskLevel = riskLevel === 'LOW' ? 'MEDIUM' : riskLevel
      }
    }

    // 4. Time Pattern Analysis
    const validationTimes = discountHistory.slice(0, 8).map(log => log.createdAt)
    if (validationTimes.length > 3) {
      let rapidValidations = 0
      for (let i = 1; i < validationTimes.length; i++) {
        const timeDiff = Math.abs(validationTimes[i-1].getTime() - validationTimes[i].getTime())
        if (timeDiff < 15000) { // Less than 15 seconds
          rapidValidations++
        }
      }
      
      if (rapidValidations > 2) {
        fraudScore += 35
        indicators.push("Rapid successive validations")
        riskLevel = 'HIGH'
      }
    }

    // 5. Geographic Consistency Check
    const recentIPs = [...new Set(discountHistory.slice(0, 5).map(log => log.ipAddress))]
    if (recentIPs.length > 3) {
      fraudScore += 20
      indicators.push("Multiple IP addresses for discount validation")
      riskLevel = riskLevel === 'LOW' ? 'MEDIUM' : riskLevel
    }

    const shouldBlock = riskLevel === 'HIGH' || fraudScore >= 70

    return { fraudScore, riskLevel, indicators, shouldBlock }
  }
}

// Enhanced Authentication with Security
class SecureAuthenticator {
  static async authenticateWithSecurity(request: NextRequest): Promise<{
    isValid: boolean
    user?: any
    error?: string
  }> {
    try {
      // Enhanced token validation
      const authHeader = request.headers.get("authorization")
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return { isValid: false, error: "Missing or invalid authorization header" }
      }

      const token = authHeader.split(" ")[1]
      if (!token || token.length < 10) {
        return { isValid: false, error: "Invalid token format" }
      }

      // Call the existing authenticateRequest but with additional validation
      const authResult = await authenticateRequest(request)
      if (!authResult) {
        return { isValid: false, error: "Authentication failed" }
      }

      return { isValid: true, user: authResult }
    } catch (error) {
      return { isValid: false, error: "Authentication error" }
    }
  }
}

// Main Advanced Security Route Handler
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION
    const authResult = await SecureAuthenticator.authenticateWithSecurity(request)
    if (!authResult.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { 
            status: "error", 
            message: "Unauthorized access to discount validation", 
            code: "UNAUTHORIZED_ACCESS" 
          },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = authResult.user.id

    // 2. COMPREHENSIVE THREAT ANALYSIS
    const rawBody = await request.json()
    const threatAnalysis = await DiscountSecurityManager.performAdvancedSecurityAnalysis(
      request,
      rawBody,
      userId
    )

    if (threatAnalysis.isThreat) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'DISCOUNT_THREAT_DETECTED',
        userId,
        request,
        rawBody.code || 'unknown',
        { threatAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { 
            status: "error", 
            message: "Security threat detected. Validation blocked.", 
            code: "SECURITY_VIOLATION" 
          },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 3. ENHANCED RATE LIMITING
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const rateLimitKey = `discount_validate:${clientIP}`
    const rateLimitCheck = rateLimit(rateLimitKey, 20, 60000) // 20 requests per minute
    
    if (!rateLimitCheck.success) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'DISCOUNT_RATE_LIMIT_EXCEEDED',
        userId,
        request,
        rawBody.code || 'unknown',
        { rateLimitKey, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { 
            status: "error", 
            message: "Rate limit exceeded for discount validation", 
            code: "RATE_LIMIT_EXCEEDED" 
          },
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 4. DATA SANITIZATION
    const sanitizedData = DiscountSecurityManager.sanitizeInput(rawBody)

    // 5. ADVANCED VALIDATION
    const validated = discountValidationSchema.parse(sanitizedData)
    
    // 6. FRAUD DETECTION
    const fraudAnalysis = await DiscountFraudDetector.analyzeFraudPatterns(
      userId,
      validated.code,
      validated.bookingDetails
    )

    if (fraudAnalysis.shouldBlock) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'DISCOUNT_FRAUD_BLOCKED',
        userId,
        request,
        validated.code,
        { fraudAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { 
            status: "error", 
            message: "Potential fraud detected. Validation blocked.", 
            code: "FRAUD_DETECTED" 
          },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 7. SESSION VALIDATION
    const sessionValidation = await AdvancedSessionSecurity.createSecureValidationSession(
      request,
      userId,
      validated.code
    )

    if (!sessionValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { 
            status: "error", 
            message: "Session validation failed", 
            code: "INVALID_SESSION" 
          },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 8. CALL EXISTING DISCOUNT SERVICE WITH SECURITY CONTEXT
    try {
      const validation = await DiscountService.validateDiscount(
        validated.hotelId, 
        validated.code, 
        validated.bookingDetails
      )

      if (!validation.valid) {
        await AdvancedSessionSecurity.logSecurityEvent(
          'DISCOUNT_VALIDATION_FAILED',
          userId,
          request,
          validated.code,
          { 
            reason: validation.error,
            requestId,
            securityContext: {
              threatScore: threatAnalysis.riskScore,
              fraudScore: fraudAnalysis.fraudScore,
              sessionRisk: sessionValidation.riskScore
            }
          }
        )

        return addSecurityHeaders(
          NextResponse.json(
            { 
              status: "error", 
              message: validation.error || "Discount validation failed", 
              code: "VALIDATION_FAILED" 
            },
            { status: 400 }
          ),
          securityHeaders
        )
      }

      const discountAmount = await DiscountService.calculateDiscount(
        validation.discount, 
        validated.bookingDetails.totalPrice
      )

      const processingTime = Date.now() - startTime

      // 9. COMPREHENSIVE AUDIT LOGGING
      await prisma.auditLog.create({
        data: {
          userId,
          action: 'VALIDATE',
          resource: 'DISCOUNT_VALIDATION',
          endpoint: '/api/discounts/validate',
          method: 'POST',
          ipAddress: clientIP,
          userAgent: request.headers.get('user-agent') || '',
          newValues: JSON.stringify({
            discountCode: validated.code,
            hotelId: validated.hotelId,
            discountAmount,
            totalPrice: validated.bookingDetails.totalPrice,
            isValid: true,
            securityContext: {
              threatLevel: threatAnalysis.threatLevel,
              fraudRiskLevel: fraudAnalysis.riskLevel,
              sessionRiskScore: sessionValidation.riskScore
            }
          }),
          success: true,
          processingTime,
          sessionId: sessionValidation.sessionId,
          fingerprint: sessionValidation.fingerprint,
          riskScore: sessionValidation.riskScore,
          fraudScore: fraudAnalysis.fraudScore
        }
      })

      // 10. SECURE RESPONSE
      const response = addSecurityHeaders(
        NextResponse.json({
          status: "success",
          data: {
            discount: validation.discount,
            discountAmount,
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
          message: "تم التحقق من الخصم بنجاح"
        }),
        securityHeaders
      )

      // 11. SECURITY RESPONSE HEADERS
      response.headers.set('X-Request-ID', requestId)
      response.headers.set('X-Security-Level', 'ADVANCED')
      response.headers.set('X-Processing-Time', processingTime.toString())
      response.headers.set('X-Threat-Level', threatAnalysis.threatLevel)
      response.headers.set('X-Fraud-Risk', fraudAnalysis.riskLevel)

      return response

    } catch (serviceError: any) {
      // Service-level error handling
      const processingTime = Date.now() - startTime
      
      await AdvancedSessionSecurity.logSecurityEvent(
        'DISCOUNT_SERVICE_ERROR',
        userId,
        request,
        validated.code,
        { 
          error: serviceError.message,
          requestId,
          securityContext: {
            threatScore: threatAnalysis.riskScore,
            fraudScore: fraudAnalysis.fraudScore
          }
        }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { 
            status: "error", 
            message: serviceError.message || "Discount service error", 
            code: "SERVICE_ERROR" 
          },
          { status: 500 }
        ),
        securityHeaders
      )
    }

  } catch (error: any) {
    const processingTime = Date.now() - startTime
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"

    // Log security incident
    await prisma.auditLog.create({
      data: {
        userId: 'unknown',
        action: 'ERROR',
        resource: 'DISCOUNT_VALIDATION',
        endpoint: '/api/discounts/validate',
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
          { 
            status: "error", 
            message: "بيانات التحقق من الخصم غير صحيحة", 
            code: "VALIDATION_ERROR",
            errors: error.errors 
          },
          { status: 400 }
        ),
        securityHeaders
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        { 
          status: "error", 
          message: error.message || "فشل في التحقق من الخصم", 
          code: "DISCOUNT_VALIDATION_ERROR" 
        },
        { status: 500 }
      ),
      securityHeaders
    )
  }
}