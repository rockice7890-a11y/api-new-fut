import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { WishlistService } from "@/lib/services/wishlist.service"
import { prisma } from "@/lib/prisma"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"
import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'

// Advanced Security Configuration
const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self';",
  'Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

// Enhanced Validation Schema
const addToWishlistSchema = z.object({
  hotelId: z.string().min(1, "Hotel ID is required").refine((val) => {
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    return uuidRegex.test(val)
  }, "Invalid hotel ID format"),
  notes: z.string().max(500, "Notes exceed maximum length").refine((val) => {
    if (!val) return true
    // Prevent script injection
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val) && !/on\w+=/i.test(val)
  }, "Invalid characters in notes").optional()
})

// Advanced Security Management Classes
class WishlistSecurityManager {
  private static readonly SUSPICIOUS_PATTERNS = [
    /hack/i, /exploit/i, /injection/i, /bypass/i, /admin/i, /root/i,
    /eval/i, /script/i, /<script/i, /javascript:/i, /data:/i
  ]

  private static readonly MALICIOUS_KEYWORDS = [
    'malware', 'virus', 'trojan', 'backdoor', 'payload', 'shell',
    'exploit', 'zero-day', 'buffer overflow', 'sql injection', 'xss'
  ]

  static async performAdvancedThreatAnalysis(
    request: NextRequest,
    data: any,
    userId: string,
    action: string
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

    // 1. Content Pattern Analysis
    for (const pattern of this.SUSPICIOUS_PATTERNS) {
      if (pattern.test(contentStr)) {
        violations.push(`Suspicious pattern detected: ${pattern.source}`)
        riskScore += 25
        threatLevel = 'HIGH'
      }
    }

    // 2. Malicious Keywords Detection
    for (const keyword of this.MALICIOUS_KEYWORDS) {
      if (contentStr.includes(keyword)) {
        violations.push(`Malicious keyword detected: ${keyword}`)
        riskScore += 35
        threatLevel = 'CRITICAL'
      }
    }

    // 3. User Agent Security Analysis
    if (userAgent.includes('bot') || userAgent.includes('crawler') || 
        userAgent.includes('scraper') || userAgent.includes('python') ||
        userAgent.includes('curl') || userAgent.includes('wget')) {
      violations.push("Automated client detected")
      riskScore += 20
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // 4. Rate Limiting and Frequency Analysis
    const recentWishlistActions = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/wishlist' },
        action: { in: ['GET', 'CREATE'] },
        createdAt: { gte: new Date(Date.now() - 60000) } // Last minute
      },
      take: 20
    })

    if (action === 'CREATE' && recentWishlistActions.length > 10) {
      violations.push("Excessive wishlist operations")
      riskScore += 25
      threatLevel = 'MEDIUM'
    }

    if (action === 'GET' && recentWishlistActions.length > 50) {
      violations.push("Excessive wishlist retrieval requests")
      riskScore += 20
    }

    // 5. Hotel ID Validation
    if (data.hotelId) {
      // Basic format validation is done in schema, additional security checks here
      if (data.hotelId.length !== 36) { // Standard UUID length
        violations.push("Invalid hotel ID format")
        riskScore += 15
      }
      
      // Check for potential SQL injection patterns in UUID
      if (/[;'"]/g.test(data.hotelId)) {
        violations.push("Suspicious characters in hotel ID")
        riskScore += 30
        threatLevel = 'HIGH'
      }
    }

    // 6. Notes Field Security (if present)
    if (data.notes) {
      const notes = data.notes.toString()
      if (notes.length > 500) {
        violations.push("Notes field exceeds maximum length")
        riskScore += 10
      }
      
      // Check for HTML/script tags
      if (/<[a-z][\s\S]*>/i.test(notes)) {
        violations.push("HTML tags detected in notes")
        riskScore += 25
        threatLevel = 'MEDIUM'
      }
    }

    // 7. IP Geolocation Risk Assessment
    const highRiskIPRanges = ['192.168.1.', '10.0.0.', '172.16.0.'] // Simulated
    const isHighRiskIP = highRiskIPRanges.some(range => clientIP.startsWith(range))
    if (isHighRiskIP) {
      violations.push("Request from internal/suspicious IP range")
      riskScore += 25
      threatLevel = 'HIGH'
    }

    // 8. Time-based Anomaly Detection
    const currentHour = new Date().getHours()
    if ((currentHour < 3 || currentHour > 23) && recentWishlistActions.length > 5) {
      violations.push("Off-hours high wishlist activity")
      riskScore += 15
    }

    // 9. Authentication Security
    const authHeader = request.headers.get("authorization")
    if (authHeader?.includes('Bearer undefined') || 
        authHeader?.includes('null') || 
        authHeader?.length < 20) {
      violations.push("Invalid or malformed authentication token")
      riskScore += 30
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // 10. Behavioral Pattern Analysis
    const userHistory = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/wishlist' },
        createdAt: { gte: new Date(Date.now() - 300000) } // Last 5 minutes
      },
      take: 15
    })

    if (action === 'CREATE') {
      const sameHotelAdds = userHistory.filter(h => {
        try {
          const newValues = JSON.parse(h.newValues || '{}')
          return newValues.hotelId === data.hotelId
        } catch {
          return false
        }
      })
      
      if (sameHotelAdds.length > 2) {
        violations.push("Repeated attempts to add same hotel")
        riskScore += 20
      }
    }

    // Generate recommendations
    if (riskScore >= 70 || threatLevel === 'CRITICAL') {
      recommendations.push("Block user immediately")
      recommendations.push("Report to security team")
      recommendations.push("Review account status")
    } else if (riskScore >= 40) {
      recommendations.push("Enable enhanced monitoring")
      recommendations.push("Require additional verification")
    } else if (riskScore >= 20) {
      recommendations.push("Log for manual review")
      recommendations.push("Apply additional scrutiny")
    }

    const isThreat = threatLevel === 'HIGH' || threatLevel === 'CRITICAL' || riskScore >= 50

    return { isThreat, threatLevel, riskScore, violations, recommendations }
  }

  static sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      return input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/[<>\"']/g, '')
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

  static validateBusinessLogic(data: any, action: string): { isValid: boolean; errors: string[] } {
    const errors: string[] = []

    if (action === 'CREATE') {
      // Hotel ID validation
      if (data.hotelId) {
        // Additional business logic validation
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        if (!uuidRegex.test(data.hotelId)) {
          errors.push("Invalid hotel ID format")
        }
      }

      // Notes validation
      if (data.notes && data.notes.length > 500) {
        errors.push("Notes cannot exceed 500 characters")
      }
    }

    return { isValid: errors.length === 0, errors }
  }
}

class AdvancedSessionSecurity {
  static async createSecureWishlistSession(
    request: NextRequest,
    userId: string,
    action: string,
    hotelId?: string
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
      .update(`${clientIP}:${userAgent}:${userId}:${action}:${hotelId || 'none'}:${Date.now()}`)
      .digest('hex')

    // Analyze wishlist access patterns
    const recentSessions = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/wishlist' },
        createdAt: { gte: new Date(Date.now() - 180000) } // Last 3 minutes
      },
      orderBy: { createdAt: 'desc' },
      take: 20
    })

    let riskScore = 0
    
    // Check for rapid wishlist operations
    if (recentSessions.length > 15) {
      riskScore += 25
    }

    // Check for repeated hotel additions
    if (action === 'CREATE' && hotelId) {
      const sameHotelAdds = recentSessions.filter(s => {
        try {
          const newValues = JSON.parse(s.newValues || '{}')
          return newValues.hotelId === hotelId
        } catch {
          return false
        }
      })
      
      if (sameHotelAdds.length > 2) {
        riskScore += 30
      }
    }

    // Check for high failure rate
    const failures = recentSessions.filter(s => !s.success)
    if (recentSessions.length > 0 && (failures.length / recentSessions.length) > 0.5) {
      riskScore += 20
    }

    const isValid = riskScore < 60

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
    details: any
  ) {
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""

    await prisma.auditLog.create({
      data: {
        userId,
        action: event,
        resource: 'WISHLIST',
        endpoint: '/api/wishlist',
        method: 'GET',
        ipAddress: clientIP,
        userAgent,
        newValues: JSON.stringify(details),
        success: true,
        createdAt: new Date()
      }
    })
  }
}

class WishlistFraudDetector {
  static async analyzeWishlistFraud(
    userId: string,
    action: string,
    hotelId?: string
  ): Promise<{
    fraudScore: number
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'
    indicators: string[]
    shouldBlock: boolean
  }> {
    let fraudScore = 0
    const indicators: string[] = []
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'

    // 1. Historical Wishlist Analysis
    const wishlistHistory = await prisma.auditLog.findMany({
      where: {
        userId,
        resource: 'WISHLIST',
        createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
      },
      orderBy: { createdAt: 'desc' }
    })

    if (action === 'CREATE' && wishlistHistory.length > 100) {
      fraudScore += 30
      indicators.push("Excessive wishlist additions")
      riskLevel = 'MEDIUM'
    }

    // 2. Duplicate Addition Detection
    if (action === 'CREATE' && hotelId) {
      const sameHotelAdds = wishlistHistory.filter(log => {
        try {
          const newValues = JSON.parse(log.newValues || '{}')
          return newValues.hotelId === hotelId
        } catch {
          return false
        }
      })

      if (sameHotelAdds.length > 5) {
        fraudScore += 40
        indicators.push("Potential duplicate hotel additions")
        riskLevel = 'HIGH'
      }
    }

    // 3. Time Pattern Analysis
    const recentActions = wishlistHistory.slice(0, 10).map(log => log.createdAt)
    if (recentActions.length > 3) {
      let rapidActions = 0
      for (let i = 1; i < recentActions.length; i++) {
        const timeDiff = Math.abs(recentActions[i-1].getTime() - recentActions[i].getTime())
        if (timeDiff < 10000) { // Less than 10 seconds
          rapidActions++
        }
      }
      
      if (rapidActions > 3) {
        fraudScore += 35
        indicators.push("Rapid successive wishlist operations")
        riskLevel = 'HIGH'
      }
    }

    // 4. Geographic Consistency
    const recentIPs = [...new Set(wishlistHistory.slice(0, 5).map(log => log.ipAddress))]
    if (recentIPs.length > 3) {
      fraudScore += 20
      indicators.push("Multiple IP addresses for wishlist operations")
      riskLevel = riskLevel === 'LOW' ? 'MEDIUM' : riskLevel
    }

    // 5. Success Rate Analysis
    const recentOperations = wishlistHistory.slice(0, 20)
    if (recentOperations.length > 0) {
      const successRate = recentOperations.filter(op => op.success).length / recentOperations.length
      if (successRate < 0.3) {
        fraudScore += 25
        indicators.push("Low success rate in wishlist operations")
        riskLevel = 'MEDIUM'
      }
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

      // Call the existing authenticateRequest
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

// Advanced GET /api/wishlist
export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION
    const authResult = await SecureAuthenticator.authenticateWithSecurity(request)
    if (!authResult.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          apiResponse.unauthorized("Unauthorized access to wishlist", "UNAUTHORIZED_ACCESS")
        ),
        securityHeaders
      )
    }

    const userId = authResult.user.id

    // 2. SESSION VALIDATION
    const sessionValidation = await AdvancedSessionSecurity.createSecureWishlistSession(
      request,
      userId,
      'GET'
    )

    if (!sessionValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Session validation failed", code: "INVALID_SESSION" },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 3. FRAUD DETECTION
    const fraudAnalysis = await WishlistFraudDetector.analyzeWishlistFraud(userId, 'GET')
    if (fraudAnalysis.shouldBlock) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'WISHLIST_FRAUD_BLOCKED_GET',
        userId,
        request,
        { fraudAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Potential fraud detected", code: "FRAUD_DETECTED" },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 4. RATE LIMITING
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const rateLimitKey = `wishlist_get:${clientIP}`
    const rateLimitCheck = rateLimit(rateLimitKey, 50, 60000) // 50 requests per minute
    
    if (!rateLimitCheck.success) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'WISHLIST_RATE_LIMIT_EXCEEDED_GET',
        userId,
        request,
        { rateLimitKey, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Rate limit exceeded", code: "RATE_LIMIT_EXCEEDED" },
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 5. SECURE WISHLIST RETRIEVAL
    const wishlist = await WishlistService.getUserWishlist(userId)
    
    const processingTime = Date.now() - startTime

    // 6. COMPREHENSIVE AUDIT LOGGING
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'GET',
        resource: 'WISHLIST',
        endpoint: '/api/wishlist',
        method: 'GET',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          wishlistCount: wishlist?.length || 0,
          securityContext: {
            fraudScore: fraudAnalysis.fraudScore,
            sessionRisk: sessionValidation.riskScore
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

    // 7. SECURE RESPONSE
    const response = addSecurityHeaders(
      NextResponse.json(
        apiResponse.success(
          {
            wishlist,
            securityMetrics: {
              requestId,
              processingTime,
              sessionRiskScore: sessionValidation.riskScore,
              fraudScore: fraudAnalysis.fraudScore,
              fraudRiskLevel: fraudAnalysis.riskLevel,
              isSecure: true
            }
          },
          "تم استرجاع قائمة الأمنيات بنجاح"
        )
      ),
      securityHeaders
    )

    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-Security-Level', 'ADVANCED')
    response.headers.set('X-Processing-Time', processingTime.toString())
    response.headers.set('X-Fraud-Risk', fraudAnalysis.riskLevel)

    return response

  } catch (error) {
    const processingTime = Date.now() - startTime
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"

    await prisma.auditLog.create({
      data: {
        userId: 'unknown',
        action: 'ERROR',
        resource: 'WISHLIST',
        endpoint: '/api/wishlist',
        method: 'GET',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        errorDetails: error instanceof Error ? error.message : String(error),
        success: false,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        apiResponse.error(error instanceof Error ? error.message : "فشل في استرجاع قائمة الأمنيات")
      ),
      securityHeaders
    )
  }
}

// Advanced POST /api/wishlist
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION
    const authResult = await SecureAuthenticator.authenticateWithSecurity(request)
    if (!authResult.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          apiResponse.unauthorized("Unauthorized access to wishlist", "UNAUTHORIZED_ACCESS")
        ),
        securityHeaders
      )
    }

    const userId = authResult.user.id

    // 2. COMPREHENSIVE THREAT ANALYSIS
    const rawBody = await request.json()
    const threatAnalysis = await WishlistSecurityManager.performAdvancedThreatAnalysis(
      request,
      rawBody,
      userId,
      'CREATE'
    )

    if (threatAnalysis.isThreat) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'WISHLIST_THREAT_DETECTED_CREATE',
        userId,
        request,
        { threatAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Security threat detected. Wishlist operation blocked.", code: "SECURITY_VIOLATION" },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 3. FRAUD DETECTION
    const hotelId = rawBody.hotelId
    const fraudAnalysis = await WishlistFraudDetector.analyzeWishlistFraud(userId, 'CREATE', hotelId)
    if (fraudAnalysis.shouldBlock) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'WISHLIST_FRAUD_BLOCKED_CREATE',
        userId,
        request,
        { fraudAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Potential fraud detected", code: "FRAUD_DETECTED" },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 4. SESSION VALIDATION
    const sessionValidation = await AdvancedSessionSecurity.createSecureWishlistSession(
      request,
      userId,
      'CREATE',
      hotelId
    )

    if (!sessionValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Session validation failed", code: "INVALID_SESSION" },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 5. ENHANCED RATE LIMITING
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const rateLimitKey = `wishlist_create:${userId}:${clientIP}`
    const rateLimitCheck = rateLimit(rateLimitKey, 30, 3600000) // 30 per hour
    
    if (!rateLimitCheck.success) {
      await AdvancedSessionSecurity.logSecurityEvent(
        'WISHLIST_RATE_LIMIT_EXCEEDED_CREATE',
        userId,
        request,
        { rateLimitKey, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Rate limit exceeded for wishlist additions", code: "RATE_LIMIT_EXCEEDED" },
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 6. DATA SANITIZATION
    const sanitizedData = WishlistSecurityManager.sanitizeInput(rawBody)

    // 7. ADVANCED VALIDATION
    const validated = addToWishlistSchema.parse(sanitizedData)

    // 8. BUSINESS LOGIC VALIDATION
    const businessValidation = WishlistSecurityManager.validateBusinessLogic(validated, 'CREATE')
    if (!businessValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Business logic validation failed", code: "BUSINESS_LOGIC_ERROR", errors: businessValidation.errors },
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 9. SECURE WISHLIST OPERATION
    try {
      const result = await WishlistService.addToWishlist(userId, validated.hotelId)
      
      const processingTime = Date.now() - startTime

      // 10. COMPREHENSIVE AUDIT LOGGING
      await prisma.auditLog.create({
        data: {
          userId,
          action: 'CREATE',
          resource: 'WISHLIST',
          endpoint: '/api/wishlist',
          method: 'POST',
          ipAddress: clientIP,
          userAgent: request.headers.get('user-agent') || '',
          newValues: JSON.stringify({
            hotelId: validated.hotelId,
            hasNotes: !!validated.notes,
            securityContext: {
              threatLevel: threatAnalysis.threatLevel,
              fraudScore: fraudAnalysis.fraudScore,
              sessionRisk: sessionValidation.riskScore
            }
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

      // 11. SECURE RESPONSE
      const response = addSecurityHeaders(
        NextResponse.json(
          apiResponse.success(
            {
              result,
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
            "تم إضافة الفندق إلى قائمة الأمنيات بنجاح"
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

    } catch (serviceError: any) {
      // Service-level error handling
      const processingTime = Date.now() - startTime
      
      await AdvancedSessionSecurity.logSecurityEvent(
        'WISHLIST_SERVICE_ERROR',
        userId,
        request,
        { 
          error: serviceError.message,
          requestId,
          hotelId: validated.hotelId,
          securityContext: {
            threatScore: threatAnalysis.riskScore,
            fraudScore: fraudAnalysis.fraudScore
          }
        }
      )

      return addSecurityHeaders(
        NextResponse.json(
          apiResponse.error(serviceError.message || "فشل في إضافة الفندق إلى قائمة الأمنيات")
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
        resource: 'WISHLIST',
        endpoint: '/api/wishlist',
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
          apiResponse.badRequest("بيانات قائمة الأمنيات غير صحيحة", "VALIDATION_ERROR", error.errors)
        ),
        securityHeaders
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        apiResponse.error(error.message || "فشل في إضافة الفندق إلى قائمة الأمنيات")
      ),
      securityHeaders
    )
  }
}