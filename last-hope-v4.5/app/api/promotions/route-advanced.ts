import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { PromotionService } from "@/lib/services/promotion.service"
import { apiResponse } from "@/lib/api-response"
import { prisma } from "@/lib/prisma"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"
import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'

// AI-Powered Threat Detection Interface
interface ThreatAnalysis {
  isThreat: boolean
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  reasons: string[]
  recommendations: string[]
}

// Enhanced Validation Schemas
const createPromotionSchema = z.object({
  hotelId: z.string().min(1, "Hotel ID is required"),
  imageUrl: z.string().url("Invalid image URL"),
  title: z.string().min(1, "Title is required").max(200, "Title too long"),
  description: z.string().max(1000, "Description too long").optional(),
  displayOrder: z.number().int().min(0).max(999).optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  isActive: z.boolean().default(true)
})

const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

// Advanced Security Utilities
class AdvancedSecurityManager {
  private static readonly MAX_IMAGE_SIZE = 10 * 1024 * 1024 // 10MB
  private static readonly ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']
  private static readonly SUSPICIOUS_KEYWORDS = ['hack', 'exploit', 'injection', 'bypass', 'admin', 'root', 'eval', 'script']

  static async performThreatAnalysis(
    request: NextRequest,
    data: any,
    userId: string
  ): Promise<ThreatAnalysis> {
    const reasons: string[] = []
    const recommendations: string[] = []
    let threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    let isThreat = false

    // Analyze request patterns
    const clientIP = request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""
    
    // Suspicious User-Agent detection
    if (userAgent.includes('bot') || userAgent.includes('crawler') || userAgent.includes('scraper')) {
      reasons.push("Automated user-agent detected")
      threatLevel = 'MEDIUM'
    }

    // Content analysis
    const contentStr = JSON.stringify(data).toLowerCase()
    
    // Check for suspicious keywords
    for (const keyword of this.SUSPICIOUS_KEYWORDS) {
      if (contentStr.includes(keyword)) {
        reasons.push(`Suspicious keyword detected: ${keyword}`)
        threatLevel = 'HIGH'
        isThreat = true
        break
      }
    }

    // Check for potential injection attempts
    if (contentStr.includes('<script') || contentStr.includes('javascript:') || contentStr.includes('data:')) {
      reasons.push("Potential script injection detected")
      threatLevel = 'CRITICAL'
      isThreat = true
    }

    // Rate limiting analysis
    const rateLimitCheck = rateLimit(`promotion_analysis:${clientIP}`, 1000, 60000)
    if (!rateLimitCheck.success) {
      reasons.push("High request frequency detected")
      threatLevel = 'MEDIUM'
    }

    // Session analysis
    const authHeader = request.headers.get("authorization")
    if (authHeader?.includes('Bearer undefined') || authHeader?.includes('null')) {
      reasons.push("Invalid or malformed authentication token")
      threatLevel = 'MEDIUM'
      isThreat = true
    }

    if (isThreat || threatLevel === 'HIGH' || threatLevel === 'CRITICAL') {
      recommendations.push("Monitor user activity closely")
      recommendations.push("Consider temporary account restriction")
    }

    return { isThreat, threatLevel, reasons, recommendations }
  }

  static validateImageSecurity(imageUrl: string): boolean {
    try {
      const url = new URL(imageUrl)
      
      // Block local/internal URLs
      if (url.hostname === 'localhost' || 
          url.hostname === '127.0.0.1' || 
          url.hostname === '0.0.0.0') {
        return false
      }

      // Only allow HTTPS
      if (url.protocol !== 'https:') {
        return false
      }

      // Check for suspicious domains
      const suspiciousDomains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
      if (suspiciousDomains.includes(url.hostname)) {
        return false
      }

      return true
    } catch {
      return false
    }
  }

  static sanitizeInput(input: any): any {
    if (typeof input === 'string') {
      // Remove potentially dangerous characters
      return input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .trim()
    } else if (Array.isArray(input)) {
      return input.map(item => this.sanitizeInput(item))
    } else if (typeof input === 'object' && input !== null) {
      const sanitized: any = {}
      for (const [key, value] of Object.entries(input)) {
        sanitized[key] = this.sanitizeInput(value)
      }
      return sanitized
    }
    return input
  }
}

// Enhanced Session Management
class AdvancedSessionManager {
  static async validateAndEnhanceSession(request: NextRequest, userId: string): Promise<{
    isValid: boolean
    sessionId: string
    riskScore: number
    fingerprint: string
  }> {
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const userAgent = request.headers.get("user-agent") || ""
    
    // Generate session fingerprint
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${clientIP}:${userAgent}:${userId}`)
      .digest('hex')

    // Check for session anomalies
    const recentSessions = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/api/promotions' },
        createdAt: { gte: new Date(Date.now() - 60000) } // Last minute
      },
      take: 10
    })

    let riskScore = 0
    
    // Multiple IPs in short time
    const uniqueIPs = new Set(recentSessions.map(s => s.ipAddress))
    if (uniqueIPs.size > 3) riskScore += 30

    // High frequency of requests
    if (recentSessions.length > 20) riskScore += 40

    // Check for rapid success/failure patterns
    const failures = recentSessions.filter(s => !s.success)
    if (failures.length > recentSessions.length * 0.7) riskScore += 20

    const isValid = riskScore < 70

    return {
      isValid,
      sessionId: uuidv4(),
      riskScore,
      fingerprint
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
        resource: 'PROMOTION_IMAGE',
        endpoint: '/api/promotions',
        method: 'POST',
        ipAddress: clientIP,
        userAgent,
        newValues: JSON.stringify(details),
        success: true,
        createdAt: new Date()
      }
    })
  }
}

// Behavioral Analysis Engine
class BehavioralAnalysisEngine {
  static async analyzeUserBehavior(userId: string, action: string): Promise<{
    isNormal: boolean
    anomalyScore: number
    flags: string[]
  }> {
    const now = new Date()
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000)
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)

    // Get user activity patterns
    const [hourlyActivity, dailyActivity] = await Promise.all([
      prisma.auditLog.count({
        where: {
          userId,
          endpoint: { contains: '/api/promotions' },
          createdAt: { gte: oneHourAgo }
        }
      }),
      prisma.auditLog.count({
        where: {
          userId,
          endpoint: { contains: '/api/promotions' },
          createdAt: { gte: oneDayAgo }
        }
      })
    ])

    let anomalyScore = 0
    const flags: string[] = []

    // Unusual hourly activity
    if (hourlyActivity > 50) {
      anomalyScore += 30
      flags.push("High hourly promotion activity")
    }

    // Unusual daily pattern
    if (dailyActivity > 200) {
      anomalyScore += 40
      flags.push("Excessive daily promotion management")
    }

    // Time-based anomalies
    const currentHour = now.getHours()
    if (currentHour < 6 || currentHour > 22) {
      // Late night/early morning activity
      if (hourlyActivity > 10) {
        anomalyScore += 20
        flags.push("Off-hours high activity")
      }
    }

    const isNormal = anomalyScore < 50

    return { isNormal, anomalyScore, flags }
  }
}

// Main Advanced Security Route Handler
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION & AUTHORIZATION
    const auth = await withAuth(request, ['ADMIN', 'HOTEL_MANAGER'])
    if (!auth.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Unauthorized access to promotion management", "UNAUTHORIZED_ACCESS"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = auth.payload.userId
    const userRole = auth.payload.role

    // 2. ADVANCED THREAT DETECTION
    const rawData = await request.json()
    const threatAnalysis = await AdvancedSecurityManager.performThreatAnalysis(
      request,
      rawData,
      userId
    )

    if (threatAnalysis.isThreat || threatAnalysis.threatLevel === 'CRITICAL') {
      // Log security incident
      await AdvancedSessionManager.logSecurityEvent(
        'SECURITY_THREAT_DETECTED',
        userId,
        request,
        { threatAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Security threat detected. Access denied.", "SECURITY_VIOLATION"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 3. SESSION VALIDATION & ENHANCEMENT
    const sessionValidation = await AdvancedSessionManager.validateAndEnhanceSession(request, userId)
    if (!sessionValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Session validation failed", "INVALID_SESSION"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 4. BEHAVIORAL ANALYSIS
    const behaviorAnalysis = await BehavioralAnalysisEngine.analyzeUserBehavior(userId, 'CREATE_PROMOTION')
    if (!behaviorAnalysis.isNormal) {
      // Enhanced monitoring for anomalous behavior
      await AdvancedSessionManager.logSecurityEvent(
        'ANOMALOUS_BEHAVIOR_DETECTED',
        userId,
        request,
        { behaviorAnalysis, requestId }
      )
    }

    // 5. DATA VALIDATION & SANITIZATION
    const sanitizedData = AdvancedSecurityManager.sanitizeInput(rawData)
    const validated = createPromotionSchema.parse(sanitizedData)

    // 6. IMAGE SECURITY VALIDATION
    if (!AdvancedSecurityManager.validateImageSecurity(validated.imageUrl)) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Invalid or unsafe image URL", "INVALID_IMAGE_URL"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 7. AUTHORIZATION VALIDATION
    if (userRole === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { managerId: userId },
        select: { id: true }
      })

      if (!userHotels.some(h => h.id === validated.hotelId)) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Access denied to this hotel", "ACCESS_DENIED"),
            { status: 403 }
          ),
          securityHeaders
        )
      }
    }

    // 8. RATE LIMITING
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`create_promotion:${userId}:${clientIP}`, 20, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Rate limit exceeded for promotion creation", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 9. ENHANCED HOTEL VERIFICATION
    const hotel = await prisma.hotel.findUnique({
      where: { id: validated.hotelId },
      select: { id: true, name: true, managerId: true }
    })

    if (!hotel) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Hotel not found", "HOTEL_NOT_FOUND"),
          { status: 404 }
        ),
        securityHeaders
      )
    }

    // 10. SECURE PROMOTION CREATION
    const promotion = await prisma.promotionImage.create({
      data: {
        id: uuidv4(),
        hotelId: validated.hotelId,
        imageUrl: validated.imageUrl,
        title: validated.title,
        description: validated.description || null,
        displayOrder: validated.displayOrder || 0,
        startDate: validated.startDate ? new Date(validated.startDate) : null,
        endDate: validated.endDate ? new Date(validated.endDate) : null,
        isActive: validated.isActive,
        createdAt: new Date(),
        updatedAt: new Date()
      },
      include: {
        hotel: {
          select: { name: true, city: true }
        }
      }
    })

    // 11. COMPREHENSIVE AUDIT LOGGING
    const processingTime = Date.now() - startTime
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'CREATE',
        resource: 'PROMOTION_IMAGE',
        resourceId: promotion.id,
        endpoint: '/api/promotions',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          hotelId: promotion.hotelId,
          title: promotion.title,
          hasImage: !!promotion.imageUrl,
          isActive: promotion.isActive
        }),
        success: true,
        processingTime,
        sessionId: sessionValidation.sessionId,
        fingerprint: sessionValidation.fingerprint,
        riskScore: sessionValidation.riskScore,
        anomalyScore: behaviorAnalysis.anomalyScore,
        threatLevel: threatAnalysis.threatLevel
      }
    })

    // 12. PERFORMANCE OPTIMIZATION
    const response = addSecurityHeaders(
      NextResponse.json(
        successResponse(
          { 
            promotion,
            securityMetrics: {
              requestId,
              processingTime,
              riskScore: sessionValidation.riskScore,
              threatLevel: threatAnalysis.threatLevel,
              anomalyScore: behaviorAnalysis.anomalyScore,
              isSecure: true
            }
          },
          "تم إضافة صورة العرض الترويجي بنجاح"
        )
      ),
      securityHeaders
    )

    // 13. SECURITY RESPONSE HEADERS
    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-Security-Level', 'ADVANCED')
    response.headers.set('X-Processing-Time', processingTime.toString())

    return response

  } catch (error: any) {
    const processingTime = Date.now() - startTime
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"

    // Log security incident for errors
    await prisma.auditLog.create({
      data: {
        userId: auth?.payload?.userId || 'unknown',
        action: 'ERROR',
        resource: 'PROMOTION_IMAGE',
        endpoint: '/api/promotions',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        errorDetails: error.message,
        success: false,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "فشل في إضافة العرض الترويجي", "PROMOTION_CREATE_ERROR"),
        { status: 500 }
      ),
      securityHeaders
    )
  }
}

export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. AUTHENTICATION
    const auth = await withAuth(request, ['ADMIN', 'HOTEL_MANAGER', 'CUSTOMER'])
    if (!auth.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Unauthorized access to promotions", "UNAUTHORIZED_ACCESS"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = auth.payload.userId
    const userRole = auth.payload.role

    // 2. SESSION VALIDATION
    const sessionValidation = await AdvancedSessionManager.validateAndEnhanceSession(request, userId)
    if (!sessionValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Session validation failed", "INVALID_SESSION"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 3. RATE LIMITING
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`get_promotions:${userId}:${clientIP}`, 100, 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 4. PARAMETER VALIDATION
    const { searchParams } = new URL(request.url)
    const hotelId = searchParams.get("hotelId")
    const onlyActive = searchParams.get("onlyActive") !== "false"
    const page = parseInt(searchParams.get("page") || "1")
    const limit = parseInt(searchParams.get("limit") || "20")

    if (!hotelId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Hotel ID is required", "MISSING_HOTEL_ID"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 5. AUTHORIZATION VALIDATION
    if (userRole === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { managerId: userId },
        select: { id: true }
      })

      if (!userHotels.some(h => h.id === hotelId)) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Access denied to this hotel's promotions", "ACCESS_DENIED"),
            { status: 403 }
          ),
          securityHeaders
        )
      }
    }

    // 6. SECURE DATA RETRIEVAL
    const whereClause: any = { hotelId }
    if (onlyActive) {
      const now = new Date()
      whereClause.AND = [
        {
          OR: [
            { startDate: null },
            { startDate: { lte: now } }
          ]
        },
        {
          OR: [
            { endDate: null },
            { endDate: { gte: now } }
          ]
        }
      ]
      whereClause.isActive = true
    }

    const [promotions, total] = await Promise.all([
      prisma.promotionImage.findMany({
        where: whereClause,
        include: {
          hotel: {
            select: { name: true, city: true }
          }
        },
        orderBy: [
          { displayOrder: 'asc' },
          { createdAt: 'desc' }
        ],
        skip: (page - 1) * limit,
        take: limit
      }),
      prisma.promotionImage.count({ where: whereClause })
    ])

    const processingTime = Date.now() - startTime

    // 7. COMPREHENSIVE AUDIT LOGGING
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'RETRIEVE',
        resource: 'PROMOTION_IMAGE',
        endpoint: '/api/promotions',
        method: 'GET',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          hotelId,
          onlyActive,
          resultsCount: promotions.length
        }),
        success: true,
        processingTime,
        sessionId: sessionValidation.sessionId
      }
    })

    // 8. SECURE RESPONSE
    const response = addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            promotions,
            pagination: {
              page,
              limit,
              total,
              totalPages: Math.ceil(total / limit)
            },
            securityMetrics: {
              requestId,
              processingTime,
              riskScore: sessionValidation.riskScore,
              isSecure: true
            }
          },
          "تم استرجاع العروض الترويجية بنجاح"
        )
      ),
      securityHeaders
    )

    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-Security-Level', 'ADVANCED')
    response.headers.set('X-Processing-Time', processingTime.toString())

    return response

  } catch (error: any) {
    const processingTime = Date.now() - startTime
    const clientIP = request.headers.get("x-forwarded-for") || "unknown"

    await prisma.auditLog.create({
      data: {
        userId: auth?.payload?.userId || 'unknown',
        action: 'ERROR',
        resource: 'PROMOTION_IMAGE',
        endpoint: '/api/promotions',
        method: 'GET',
        ipAddress: clientIP,
        userAgent: request.headers.get('user-agent') || '',
        errorDetails: error.message,
        success: false,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "فشل في استرجاع العروض الترويجية", "PROMOTIONS_FETCH_ERROR"),
        { status: 500 }
      ),
      securityHeaders
    )
  }
}