import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"
import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'

// Advanced Security Configuration
const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; font-src 'self' data:",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

// Enhanced Validation Schemas with Advanced Security
const createPromotionSchema = z.object({
  hotelId: z.string().optional(),
  name: z.string().min(1).max(200).refine((val) => {
    // Prevent script injection
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in campaign name"),
  description: z.string().max(1000).refine((val) => {
    if (!val) return true
    // Sanitize description
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in description").optional(),
  type: z.enum([
    'DISCOUNT', 'BUY_GET_FREE', 'PERCENTAGE_OFF', 'FIXED_AMOUNT_OFF',
    'FREE_NIGHT', 'ROOM_UPGRADE', 'FB_CREDIT', 'SPA_CREDIT',
    'TRANSPORT', 'EARLY_CHECKIN', 'LATE_CHECKOUT', 'LOYALTY_MULTIPLIER'
  ]),
  target: z.enum([
    'ALL_USERS', 'NEW_USERS', 'LOYAL_CUSTOMERS', 'CORPORATE',
    'BIRTHDAY_USERS', 'REFERRALS', 'HIGH_VALUE', 'LOW_ACTIVITY',
    'SPECIFIC_USER', 'USER_SEGMENT'
  ]),
  targetCriteria: z.object({}).passthrough().optional(),
  value: z.number().positive().max(1000000, "Value exceeds maximum allowed"),
  maxDiscount: z.number().positive().max(1000000, "Max discount exceeds maximum allowed").optional(),
  minBookingValue: z.number().min(0).max(1000000, "Min booking value exceeds maximum allowed").optional(),
  maxBookingValue: z.number().positive().max(1000000, "Max booking value exceeds maximum allowed").optional(),
  validFrom: z.string().transform((str) => new Date(str)),
  validUntil: z.string().transform((str) => new Date(str)),
  maxUses: z.number().positive().max(1000000, "Max uses exceeds maximum allowed").optional(),
  maxUsesPerUser: z.number().positive().max(1000, "Per user limit exceeds maximum allowed").optional(),
  maxUsesPerDay: z.number().positive().max(10000, "Daily limit exceeds maximum allowed").optional(),
  maxUsesPerWeek: z.number().positive().max(50000, "Weekly limit exceeds maximum allowed").optional(),
  canStackWithOther: z.boolean().default(false),
  stackablePromotions: z.array(z.string()).max(10, "Too many stackable promotions").optional(),
  eligibleCountries: z.array(z.string()).max(50, "Too many countries").optional(),
  minNights: z.number().positive().max(365, "Minimum nights exceeds maximum allowed").optional(),
  maxNights: z.number().positive().max(365, "Maximum nights exceeds maximum allowed").optional(),
  totalBudget: z.number().positive().max(10000000, "Total budget exceeds maximum allowed").optional(),
  promoCode: z.string().max(50).regex(/^[A-Z0-9_]+$/, "Invalid promo code format").optional(),
  affiliateCode: z.string().max(50).regex(/^[A-Z0-9_]+$/, "Invalid affiliate code format").optional(),
  bannerImage: z.string().url().optional(),
  termsConditions: z.string().max(2000).refine((val) => {
    if (!val) return true
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in terms and conditions").optional()
})

const updatePromotionSchema = z.object({
  name: z.string().min(1).max(200).refine((val) => {
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in campaign name").optional(),
  description: z.string().max(1000).refine((val) => {
    if (!val) return true
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in description").optional(),
  status: z.enum(['DRAFT', 'SCHEDULED', 'ACTIVE', 'PAUSED', 'EXPIRED', 'CANCELLED']).optional(),
  value: z.number().positive().max(1000000, "Value exceeds maximum allowed").optional(),
  maxDiscount: z.number().positive().max(1000000, "Max discount exceeds maximum allowed").optional(),
  minBookingValue: z.number().min(0).max(1000000, "Min booking value exceeds maximum allowed").optional(),
  maxBookingValue: z.number().positive().max(1000000, "Max booking value exceeds maximum allowed").optional(),
  validFrom: z.string().transform((str) => new Date(str)).optional(),
  validUntil: z.string().transform((str) => new Date(str)).optional(),
  maxUses: z.number().positive().max(1000000, "Max uses exceeds maximum allowed").optional(),
  maxUsesPerUser: z.number().positive().max(1000, "Per user limit exceeds maximum allowed").optional(),
  maxUsesPerDay: z.number().positive().max(10000, "Daily limit exceeds maximum allowed").optional(),
  maxUsesPerWeek: z.number().positive().max(50000, "Weekly limit exceeds maximum allowed").optional(),
  canStackWithOther: z.boolean().optional(),
  stackablePromotions: z.array(z.string()).max(10, "Too many stackable promotions").optional(),
  eligibleCountries: z.array(z.string()).max(50, "Too many countries").optional(),
  minNights: z.number().positive().max(365, "Minimum nights exceeds maximum allowed").optional(),
  maxNights: z.number().positive().max(365, "Maximum nights exceeds maximum allowed").optional(),
  totalBudget: z.number().positive().max(10000000, "Total budget exceeds maximum allowed").optional(),
  bannerImage: z.string().url().optional(),
  termsConditions: z.string().max(2000).refine((val) => {
    if (!val) return true
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in terms and conditions").optional()
})

// Advanced Security Analysis Classes
class PromotionCampaignSecurityManager {
  private static readonly SUSPICIOUS_PATTERNS = [
    /hack/i, /exploit/i, /injection/i, /bypass/i, /admin/i, /root/i, 
    /eval/i, /script/i, /<script/i, /javascript:/i, /data:/i
  ]

  private static readonly MALICIOUS_KEYWORDS = [
    'malware', 'virus', 'trojan', 'backdoor', 'payload', 'shell',
    'exploit', 'zero-day', 'buffer overflow', 'sql injection', 'xss'
  ]

  static async performComprehensiveThreatAnalysis(
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
        riskScore += 30
        threatLevel = 'CRITICAL'
      }
    }

    // 3. User Agent Analysis
    if (userAgent.includes('bot') || userAgent.includes('crawler') || 
        userAgent.includes('scraper') || userAgent.includes('python-requests')) {
      violations.push("Automated user agent detected")
      riskScore += 20
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // 4. Rate Limiting Analysis
    const rateLimitCheck = rateLimit(`threat_analysis:${clientIP}`, 1000, 60000)
    if (!rateLimitCheck.success) {
      violations.push("High frequency requests detected")
      riskScore += 15
    }

    // 5. Historical Behavior Analysis
    const recentActivity = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/api/promotion-campaigns' },
        createdAt: { gte: new Date(Date.now() - 300000) } // Last 5 minutes
      },
      take: 50
    })

    if (recentActivity.length > 30) {
      violations.push("Excessive activity in short time")
      riskScore += 25
    }

    // 6. IP Geolocation Analysis (simulated)
    const knownSuspiciousIPs = ['192.168.1.1', '10.0.0.1'] // Simulated list
    if (knownSuspiciousIPs.includes(clientIP)) {
      violations.push("Request from known suspicious IP")
      riskScore += 40
      threatLevel = 'HIGH'
    }

    // 7. Data Validation Anomalies
    if (action === 'CREATE') {
      const budget = data.totalBudget
      const maxUses = data.maxUses
      
      if (budget && maxUses && (budget / maxUses) < 0.01) {
        violations.push("Suspicious budget to usage ratio")
        riskScore += 20
      }
    }

    // 8. Authentication Token Analysis
    const authHeader = request.headers.get("authorization")
    if (authHeader?.includes('Bearer undefined') || 
        authHeader?.includes('null') || 
        authHeader?.length < 20) {
      violations.push("Invalid or malformed authentication token")
      riskScore += 35
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // Generate recommendations
    if (riskScore >= 70) {
      recommendations.push("Consider blocking user temporarily")
      recommendations.push("Enable enhanced monitoring")
      recommendations.push("Notify security team")
    } else if (riskScore >= 40) {
      recommendations.push("Increase monitoring level")
      recommendations.push("Review user permissions")
    }

    const isThreat = threatLevel === 'HIGH' || threatLevel === 'CRITICAL' || riskScore >= 50

    return { isThreat, threatLevel, riskScore, violations, recommendations }
  }

  static sanitizeData(data: any): any {
    if (typeof data === 'string') {
      return data
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .replace(/[<>\"']/g, '')
        .trim()
    } else if (Array.isArray(data)) {
      return data.map(item => this.sanitizeData(item))
    } else if (typeof data === 'object' && data !== null) {
      const sanitized: any = {}
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitizeData(value)
      }
      return sanitized
    }
    return data
  }

  static validateBusinessLogic(data: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = []

    // Date range validation
    if (data.validFrom && data.validUntil) {
      const from = new Date(data.validFrom)
      const until = new Date(data.validUntil)
      
      if (from >= until) {
        errors.push("Valid from date must be before valid until date")
      }
      
      // Prevent campaigns that are too long (max 1 year)
      const diffTime = Math.abs(until.getTime() - from.getTime())
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
      if (diffDays > 365) {
        errors.push("Campaign duration cannot exceed 365 days")
      }
    }

    // Budget validation
    if (data.totalBudget && data.maxUses) {
      const costPerUse = data.totalBudget / data.maxUses
      if (costPerUse > 10000) {
        errors.push("Cost per use exceeds reasonable limits")
      }
    }

    // Promo code validation
    if (data.promoCode) {
      if (!/^[A-Z0-9_]{3,50}$/.test(data.promoCode)) {
        errors.push("Promo code must be 3-50 characters, alphanumeric with underscores only")
      }
    }

    return { isValid: errors.length === 0, errors }
  }
}

class AdvancedSessionSecurityManager {
  static async createSecureSession(
    request: NextRequest,
    userId: string,
    action: string
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
      .update(`${clientIP}:${userAgent}:${userId}:${Date.now()}`)
      .digest('hex')

    // Analyze session for anomalies
    const recentSessions = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/api/promotion-campaigns' },
        createdAt: { gte: new Date(Date.now() - 300000) } // Last 5 minutes
      },
      orderBy: { createdAt: 'desc' },
      take: 20
    })

    let riskScore = 0
    
    // Check for IP switching
    const uniqueIPs = new Set(recentSessions.map(s => s.ipAddress))
    if (uniqueIPs.size > 3) riskScore += 30
    
    // Check for rapid success/failure patterns
    const failures = recentSessions.filter(s => !s.success)
    if (failures.length > recentSessions.length * 0.8) riskScore += 25
    
    // Check for unusual timing
    const currentHour = new Date().getHours()
    if (currentHour < 6 || currentHour > 23) {
      if (recentSessions.length > 10) riskScore += 20
    }

    const isValid = riskScore < 70

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
        resource: 'PROMOTION_CAMPAIGN',
        endpoint: '/api/promotion-campaigns',
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

class BehavioralAnalyticsEngine {
  static async analyzeUserPatterns(userId: string): Promise<{
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'
    anomalies: string[]
    recommendation: string
  }> {
    const now = new Date()
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000)
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)

    const [hourlyActivity, dailyActivity, recentErrors] = await Promise.all([
      prisma.auditLog.count({
        where: {
          userId,
          endpoint: { contains: '/api/promotion-campaigns' },
          createdAt: { gte: oneHourAgo }
        }
      }),
      prisma.auditLog.count({
        where: {
          userId,
          endpoint: { contains: '/api/promotion-campaigns' },
          createdAt: { gte: oneDayAgo }
        }
      }),
      prisma.auditLog.count({
        where: {
          userId,
          endpoint: { contains: '/api/promotion-campaigns' },
          success: false,
          createdAt: { gte: oneHourAgo }
        }
      })
    ])

    const anomalies: string[] = []
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'

    // Check for unusual activity patterns
    if (hourlyActivity > 100) {
      anomalies.push("Excessive hourly activity")
      riskLevel = 'HIGH'
    } else if (hourlyActivity > 50) {
      anomalies.push("High hourly activity")
      riskLevel = 'MEDIUM'
    }

    if (dailyActivity > 500) {
      anomalies.push("Excessive daily activity")
      riskLevel = 'HIGH'
    }

    // Check error rate
    const errorRate = hourlyActivity > 0 ? (recentErrors / hourlyActivity) : 0
    if (errorRate > 0.8) {
      anomalies.push("High error rate detected")
      riskLevel = 'HIGH'
    } else if (errorRate > 0.5) {
      anomalies.push("Elevated error rate")
      riskLevel = 'MEDIUM'
    }

    const recommendation = riskLevel === 'HIGH' ? 
      "Immediate security review required" :
      riskLevel === 'MEDIUM' ? 
      "Enhanced monitoring recommended" : 
      "Normal behavior patterns"

    return { riskLevel, anomalies, recommendation }
  }
}

// Advanced GET /api/promotion-campaigns - Get promotion campaigns
export async function GET(req: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION
    const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
    if (!auth.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Unauthorized access to promotion campaigns", "UNAUTHORIZED_ACCESS"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = auth.payload.userId

    // 2. ADVANCED SESSION VALIDATION
    const sessionSecurity = await AdvancedSessionSecurityManager.createSecureSession(req, userId, 'GET')
    if (!sessionSecurity.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Session validation failed", "INVALID_SESSION"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 3. BEHAVIORAL ANALYSIS
    const behaviorAnalysis = await BehavioralAnalyticsEngine.analyzeUserPatterns(userId)
    if (behaviorAnalysis.riskLevel === 'HIGH') {
      await AdvancedSessionSecurityManager.logSecurityEvent(
        'HIGH_RISK_BEHAVIOR_DETECTED',
        userId,
        req,
        { behaviorAnalysis, requestId }
      )
    }

    // 4. RATE LIMITING
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`get_promotion_campaigns:${userId}:${clientIP}`, 200, 60000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 5. PARAMETER VALIDATION & SANITIZATION
    const searchParams = req.nextUrl.searchParams
    const page = Math.min(Math.max(parseInt(searchParams.get('page') || '1'), 1), 100)
    const pageSize = Math.min(Math.max(parseInt(searchParams.get('pageSize') || '20'), 1), 100)
    
    const hotelId = searchParams.get('hotelId')
    const type = searchParams.get('type')
    const status = searchParams.get('status')
    const target = searchParams.get('target')
    const activeOnly = searchParams.get('activeOnly') === 'true'
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    const search = PromotionCampaignSecurityManager.sanitizeData(searchParams.get('search'))

    // 6. BUILD SECURE WHERE CLAUSE
    const where: any = {}
    
    // Role-based filtering
    if (auth.payload.role === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { managerId: userId },
        select: { id: true }
      })
      where.hotelId = { in: userHotels.map(h => h.id) }
    }
    
    if (hotelId) where.hotelId = hotelId
    if (type) where.type = type
    if (status) where.status = status
    if (target) where.target = target
    
    // Active campaigns only
    if (activeOnly) {
      const now = new Date()
      where.status = { in: ['ACTIVE', 'SCHEDULED'] }
      where.validFrom = { lte: now }
      where.validUntil = { gte: now }
    }
    
    // Date range filtering
    if (startDate || endDate) {
      where.OR = []
      if (startDate) {
        const start = new Date(startDate)
        if (!isNaN(start.getTime())) {
          where.OR.push({
            AND: [
              { validFrom: { lte: start } },
              { validUntil: { gte: start } }
            ]
          })
        }
      }
      if (endDate) {
        const end = new Date(endDate)
        if (!isNaN(end.getTime())) {
          where.OR.push({
            AND: [
              { validFrom: { lte: end } },
              { validUntil: { gte: end } }
            ]
          })
        }
      }
    }
    
    // Search filtering
    if (search) {
      where.OR = [
        ...(where.OR || []),
        { name: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
        { promoCode: { contains: search, mode: 'insensitive' } }
      ]
    }

    // 7. SECURE DATA RETRIEVAL
    const [promotions, total, summary] = await Promise.all([
      prisma.promotionCampaign.findMany({
        where,
        include: {
          hotel: {
            select: { name: true, city: true }
          },
          _count: {
            select: {
              promotionUsages: true
            }
          }
        },
        orderBy: [
          { status: 'asc' },
          { createdAt: 'desc' }
        ],
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.promotionCampaign.count({ where }),
      prisma.promotionCampaign.groupBy({
        by: ['status'],
        where,
        _count: true,
        _sum: {
          totalUsed: true,
          spentBudget: true
        }
      })
    ])

    const totalCampaigns = total
    const activeCampaigns = summary.find(s => s.status === 'ACTIVE')?._count || 0
    const totalUsage = summary.reduce((sum, item) => sum + (item._sum.totalUsed || 0), 0)
    const processingTime = Date.now() - startTime

    // 8. COMPREHENSIVE AUDIT LOGGING
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'RETRIEVE',
        resource: 'PROMOTION_CAMPAIGN',
        endpoint: '/api/promotion-campaigns',
        method: 'GET',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          page,
          pageSize,
          filters: { hotelId, type, status, target, activeOnly, startDate, endDate, search },
          resultsCount: promotions.length,
          totalCampaigns,
          activeCampaigns
        }),
        success: true,
        processingTime,
        sessionId: sessionSecurity.sessionId,
        fingerprint: sessionSecurity.fingerprint,
        riskScore: sessionSecurity.riskScore,
        behaviorRiskLevel: behaviorAnalysis.riskLevel
      }
    })

    // 9. SECURE RESPONSE
    const response = addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            promotions,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: {
              totalCampaigns,
              activeCampaigns,
              totalUsage
            },
            securityMetrics: {
              requestId,
              processingTime,
              sessionRiskScore: sessionSecurity.riskScore,
              behaviorRiskLevel: behaviorAnalysis.riskLevel,
              anomaliesDetected: behaviorAnalysis.anomalies.length,
              isSecure: true
            }
          },
          "تم استرجاع الحملات الترويجية بنجاح"
        )
      ),
      securityHeaders
    )

    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-Security-Level', 'ADVANCED')
    response.headers.set('X-Processing-Time', processingTime.toString())
    response.headers.set('X-Risk-Level', behaviorAnalysis.riskLevel)

    return response

  } catch (error: any) {
    const processingTime = Date.now() - startTime
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"

    await prisma.auditLog.create({
      data: {
        userId: auth?.payload?.userId || 'unknown',
        action: 'ERROR',
        resource: 'PROMOTION_CAMPAIGN',
        endpoint: '/api/promotion-campaigns',
        method: 'GET',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        errorDetails: error.message,
        success: false,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "فشل في استرجاع الحملات الترويجية", "FETCH_PROMOTION_CAMPAIGNS_ERROR"),
        { status: 500 }
      ),
      securityHeaders
    )
  }
}

// Advanced POST /api/promotion-campaigns - Create new promotion campaign
export async function POST(req: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION
    const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
    if (!auth.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Unauthorized access to promotion campaign creation", "UNAUTHORIZED_ACCESS"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = auth.payload.userId

    // 2. COMPREHENSIVE THREAT ANALYSIS
    const rawBody = await req.json()
    const threatAnalysis = await PromotionCampaignSecurityManager.performComprehensiveThreatAnalysis(
      req,
      rawBody,
      userId,
      'CREATE'
    )

    if (threatAnalysis.isThreat) {
      await AdvancedSessionSecurityManager.logSecurityEvent(
        'THREAT_DETECTED_CAMPAIGN_CREATE',
        userId,
        req,
        { threatAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Security threat detected. Campaign creation blocked.", "SECURITY_VIOLATION"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 3. SESSION VALIDATION
    const sessionSecurity = await AdvancedSessionSecurityManager.createSecureSession(req, userId, 'CREATE')
    if (!sessionSecurity.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Session validation failed", "INVALID_SESSION"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 4. BEHAVIORAL ANALYSIS
    const behaviorAnalysis = await BehavioralAnalyticsEngine.analyzeUserPatterns(userId)
    if (behaviorAnalysis.riskLevel === 'HIGH') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "High-risk behavior detected. Please contact support.", "BEHAVIORAL_VIOLATION"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 5. RATE LIMITING
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`create_promotion_campaign:${userId}:${clientIP}`, 25, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Rate limit exceeded for campaign creation", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 6. DATA SANITIZATION & VALIDATION
    const sanitizedData = PromotionCampaignSecurityManager.sanitizeData(rawBody)
    const validated = createPromotionSchema.parse(sanitizedData)

    // 7. BUSINESS LOGIC VALIDATION
    const businessValidation = PromotionCampaignSecurityManager.validateBusinessLogic(validated)
    if (!businessValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Business logic validation failed", "BUSINESS_LOGIC_ERROR", businessValidation.errors),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 8. HOTEL ACCESS VALIDATION
    if (validated.hotelId && auth.payload.role === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { 
          managerId: userId,
          id: validated.hotelId
        },
        select: { id: true }
      })
      
      if (userHotels.length === 0) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Access denied to this hotel", "ACCESS_DENIED"),
            { status: 403 }
          ),
          securityHeaders
        )
      }
    }

    // 9. PROMO CODE UNIQUENESS VALIDATION
    if (validated.promoCode) {
      const existingPromotion = await prisma.promotionCampaign.findFirst({
        where: { promoCode: validated.promoCode }
      })
      
      if (existingPromotion) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Promo code already exists", "PROMO_CODE_EXISTS"),
            { status: 409 }
          ),
          securityHeaders
        )
      }
    }

    // 10. SECURE DATE VALIDATION
    if (validated.validFrom >= validated.validUntil) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Valid from date must be before valid until date", "INVALID_DATE_RANGE"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 11. STATUS AUTOMATION
    const now = new Date()
    let status: 'DRAFT' | 'ACTIVE' | 'SCHEDULED' = 'DRAFT'
    if (validated.validFrom <= now && validated.validUntil >= now) {
      status = 'ACTIVE'
    } else if (validated.validFrom > now) {
      status = 'SCHEDULED'
    }

    // 12. SECURE CAMPAIGN CREATION
    const promotion = await prisma.promotionCampaign.create({
      data: {
        id: uuidv4(),
        ...validated,
        hotelId: validated.hotelId || null,
        status,
        costPerUse: validated.totalBudget && validated.maxUses ? 
          validated.totalBudget / validated.maxUses : 0,
        createdBy: userId,
        createdAt: new Date(),
        updatedAt: new Date()
      },
      include: {
        hotel: {
          select: { name: true, city: true }
        }
      }
    })

    const processingTime = Date.now() - startTime

    // 13. COMPREHENSIVE AUDIT LOGGING
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'CREATE',
        resource: 'PROMOTION_CAMPAIGN',
        resourceId: promotion.id,
        endpoint: '/api/promotion-campaigns',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          name: promotion.name,
          type: promotion.type,
          value: promotion.value,
          status: promotion.status,
          hasPromoCode: !!promotion.promoCode,
          totalBudget: promotion.totalBudget
        }),
        success: true,
        processingTime,
        sessionId: sessionSecurity.sessionId,
        fingerprint: sessionSecurity.fingerprint,
        riskScore: sessionSecurity.riskScore,
        threatViolations: threatAnalysis.violations.length,
        behaviorRiskLevel: behaviorAnalysis.riskLevel
      }
    })

    // 14. SECURE RESPONSE
    const response = addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            promotion,
            securityMetrics: {
              requestId,
              processingTime,
              sessionRiskScore: sessionSecurity.riskScore,
              threatLevel: threatAnalysis.threatLevel,
              threatRiskScore: threatAnalysis.riskScore,
              behaviorRiskLevel: behaviorAnalysis.riskLevel,
              violationsCount: threatAnalysis.violations.length,
              isSecure: true
            }
          },
          "تم إنشاء الحملة الترويجية بنجاح"
        ),
        { status: 201 }
      ),
      securityHeaders
    )

    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-Security-Level', 'ADVANCED')
    response.headers.set('X-Processing-Time', processingTime.toString())
    response.headers.set('X-Threat-Level', threatAnalysis.threatLevel)

    return response

  } catch (error: any) {
    const processingTime = Date.now() - startTime
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"

    await prisma.auditLog.create({
      data: {
        userId: auth?.payload?.userId || 'unknown',
        action: 'ERROR',
        resource: 'PROMOTION_CAMPAIGN',
        endpoint: '/api/promotion-campaigns',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        errorDetails: error.message,
        success: false,
        processingTime
      }
    })

    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse({ errors: error.errors }, "بيانات الحملة الترويجية غير صحيحة", "VALIDATION_ERROR"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "فشل في إنشاء الحملة الترويجية", "CREATE_PROMOTION_CAMPAIGN_ERROR"),
        { status: 500 }
      ),
      securityHeaders
    )
  }
}

// Advanced PUT /api/promotion-campaigns - Update promotion campaign
export async function PUT(req: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // Similar security implementation as POST but for UPDATE operations
    const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
    if (!auth.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Unauthorized access to promotion campaign update", "UNAUTHORIZED_ACCESS"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = auth.payload.userId
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"

    // Validate promotion ID
    const searchParams = req.nextUrl.searchParams
    const promotionId = searchParams.get('id')
    
    if (!promotionId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Campaign ID is required", "MISSING_CAMPAIGN_ID"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // Security validations (similar pattern as POST)
    const rawBody = await req.json()
    const threatAnalysis = await PromotionCampaignSecurityManager.performComprehensiveThreatAnalysis(
      req,
      rawBody,
      userId,
      'UPDATE'
    )

    if (threatAnalysis.isThreat) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Security threat detected", "SECURITY_VIOLATION"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // Rate limiting
    const rateLimitCheck = rateLimit(`update_promotion_campaign:${userId}:${clientIP}`, 50, 3600000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // Verify promotion exists and user has access
    const existingPromotion = await prisma.promotionCampaign.findUnique({
      where: { id: promotionId },
      include: { hotel: true }
    })

    if (!existingPromotion) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Campaign not found", "CAMPAIGN_NOT_FOUND"),
          { status: 404 }
        ),
        securityHeaders
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && 
        existingPromotion.hotel && 
        existingPromotion.hotel.managerId !== userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this campaign", "ACCESS_DENIED"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // Validate and sanitize update data
    const sanitizedData = PromotionCampaignSecurityManager.sanitizeData(rawBody)
    const validated = updatePromotionSchema.parse(sanitizedData)

    // Prevent changes to locked campaigns
    if (['EXPIRED', 'CANCELLED'].includes(existingPromotion.status)) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Cannot update expired or cancelled campaigns", "INVALID_OPERATION"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    const updateData: any = { ...validated, updatedAt: new Date() }

    // Auto-update status based on dates
    if (validated.validFrom || validated.validUntil) {
      const now = new Date()
      const validFrom = validated.validFrom || existingPromotion.validFrom
      const validUntil = validated.validUntil || existingPromotion.validUntil
      
      if (validFrom <= now && validUntil >= now) {
        updateData.status = 'ACTIVE'
      } else if (validFrom > now) {
        updateData.status = 'SCHEDULED'
      }
    }

    // Recalculate cost per use if budget or max uses changed
    if (validated.totalBudget || validated.maxUses) {
      const totalBudget = validated.totalBudget || existingPromotion.totalBudget
      const maxUses = validated.maxUses || existingPromotion.maxUses
      updateData.costPerUse = totalBudget && maxUses ? totalBudget / maxUses : 0
    }

    // Secure update operation
    const updatedPromotion = await prisma.promotionCampaign.update({
      where: { id: promotionId },
      data: updateData,
      include: {
        hotel: {
          select: { name: true, city: true }
        }
      }
    })

    const processingTime = Date.now() - startTime

    // Comprehensive audit logging
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'UPDATE',
        resource: 'PROMOTION_CAMPAIGN',
        resourceId: promotionId,
        endpoint: '/api/promotion-campaigns',
        method: 'PUT',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          name: existingPromotion.name,
          status: existingPromotion.status,
          value: existingPromotion.value
        }),
        newValues: JSON.stringify({
          name: updatedPromotion.name,
          status: updatedPromotion.status,
          value: updatedPromotion.value
        }),
        success: true,
        processingTime
      }
    })

    // Secure response
    const response = addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            promotion: updatedPromotion,
            securityMetrics: {
              requestId,
              processingTime,
              isSecure: true
            }
          },
          "تم تحديث الحملة الترويجية بنجاح"
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
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"

    await prisma.auditLog.create({
      data: {
        userId: auth?.payload?.userId || 'unknown',
        action: 'ERROR',
        resource: 'PROMOTION_CAMPAIGN',
        endpoint: '/api/promotion-campaigns',
        method: 'PUT',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        errorDetails: error.message,
        success: false,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "فشل في تحديث الحملة الترويجية", "UPDATE_CAMPAIGN_ERROR"),
        { status: 500 }
      ),
      securityHeaders
    )
  }
}

// Advanced DELETE /api/promotion-campaigns - Cancel promotion campaign
export async function DELETE(req: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
    if (!auth.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Unauthorized access to campaign cancellation", "UNAUTHORIZED_ACCESS"),
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = auth.payload.userId
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"

    // Validate promotion ID
    const searchParams = req.nextUrl.searchParams
    const promotionId = searchParams.get('id')
    
    if (!promotionId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Campaign ID is required", "MISSING_CAMPAIGN_ID"),
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // Rate limiting for DELETE operations
    const rateLimitCheck = rateLimit(`delete_promotion_campaign:${userId}:${clientIP}`, 10, 3600000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Rate limit exceeded for campaign deletion", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // Verify promotion exists and user has access
    const existingPromotion = await prisma.promotionCampaign.findUnique({
      where: { id: promotionId },
      include: { hotel: true }
    })

    if (!existingPromotion) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Campaign not found", "CAMPAIGN_NOT_FOUND"),
          { status: 404 }
        ),
        securityHeaders
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && 
        existingPromotion.hotel && 
        existingPromotion.hotel.managerId !== userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this campaign", "ACCESS_DENIED"),
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // Cancel promotion instead of deleting (soft delete)
    await prisma.promotionCampaign.update({
      where: { id: promotionId },
      data: { 
        status: 'CANCELLED',
        updatedAt: new Date()
      }
    })

    const processingTime = Date.now() - startTime

    // Comprehensive audit logging
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'DELETE',
        resource: 'PROMOTION_CAMPAIGN',
        resourceId: promotionId,
        endpoint: '/api/promotion-campaigns',
        method: 'DELETE',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          status: existingPromotion.status
        }),
        newValues: JSON.stringify({
          status: 'CANCELLED'
        }),
        success: true,
        processingTime
      }
    })

    // Secure response
    const response = addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            securityMetrics: {
              requestId,
              processingTime,
              isSecure: true
            }
          },
          "تم إلغاء الحملة الترويجية بنجاح"
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
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"

    await prisma.auditLog.create({
      data: {
        userId: auth?.payload?.userId || 'unknown',
        action: 'ERROR',
        resource: 'PROMOTION_CAMPAIGN',
        endpoint: '/api/promotion-campaigns',
        method: 'DELETE',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        errorDetails: error.message,
        success: false,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "فشل في إلغاء الحملة الترويجية", "DELETE_CAMPAIGN_ERROR"),
        { status: 500 }
      ),
      securityHeaders
    )
  }
}