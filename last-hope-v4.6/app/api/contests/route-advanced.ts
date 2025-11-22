import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"
import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'

// Advanced Security Configuration
const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self';",
  'Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

// Enhanced Validation Schemas with Advanced Security
const contestSchema = z.object({
  title: z.string().min(1).max(200).refine((val) => {
    // Prevent script injection and malicious content
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val) && !/on\w+=/i.test(val)
  }, "Invalid characters in contest title"),
  description: z.string().max(1000).refine((val) => {
    if (!val) return true
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in description").optional(),
  type: z.enum(['QUIZ', 'TRIVIA', 'PHOTO', 'REVIEW', 'LOYALTY', 'SEASONAL', 'DAILY', 'WEEKLY', 'MONTHLY']),
  rules: z.string().max(2000).refine((val) => {
    if (!val) return true
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in rules").optional(),
  rewardType: z.enum(['POINTS', 'DISCOUNT', 'FREE_STAY', 'ROOM_UPGRADE', 'SPA_SERVICE', 'RESTAURANT', 'GIFT_CARD', 'CASH']).optional(),
  rewardValue: z.number().positive().max(100000, "Reward value exceeds maximum allowed").optional(),
  rewardDescription: z.string().max(500).optional(),
  startDate: z.string().datetime().transform((str) => new Date(str)),
  endDate: z.string().datetime().transform((str) => new Date(str)),
  maxParticipants: z.number().positive().max(10000, "Max participants exceeds maximum allowed").optional(),
  minPointsToJoin: z.number().min(0).max(50000, "Min points requirement exceeds maximum allowed").optional(),
  imageUrl: z.string().url().refine((val) => {
    // Validate image URL security
    try {
      const url = new URL(val)
      return url.protocol === 'https:' && !url.hostname.includes('localhost')
    } catch {
      return false
    }
  }, "Invalid or unsafe image URL").optional(),
  terms: z.string().max(2000).refine((val) => {
    if (!val) return true
    return !/[<>\"']/g.test(val) && !/javascript:/i.test(val)
  }, "Invalid characters in terms").optional()
}).refine((data) => {
  // Date range validation
  return data.startDate < data.endDate
}, {
  message: "End date must be after start date",
  path: ["endDate"]
}).refine((data) => {
  // Contest duration validation (max 1 year)
  const duration = data.endDate.getTime() - data.startDate.getTime()
  const maxDuration = 365 * 24 * 60 * 60 * 1000 // 1 year in milliseconds
  return duration <= maxDuration
}, {
  message: "Contest duration cannot exceed 1 year",
  path: ["endDate"]
})

const participateSchema = z.object({
  contestId: z.string().min(1, "Contest ID is required").refine((val) => {
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    return uuidRegex.test(val)
  }, "Invalid contest ID format")
})

// Advanced Security Analysis Classes
class ContestSecurityManager {
  private static readonly SUSPICIOUS_PATTERNS = [
    /hack/i, /exploit/i, /injection/i, /bypass/i, /admin/i, /root/i,
    /eval/i, /script/i, /<script/i, /javascript:/i, /data:/i
  ]

  private static readonly MALICIOUS_KEYWORDS = [
    'malware', 'virus', 'trojan', 'backdoor', 'payload', 'shell',
    'exploit', 'zero-day', 'buffer overflow', 'sql injection', 'xss'
  ]

  private static readonly SUSPICIOUS_IMAGE_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'shortened.com'
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
        riskScore += 30
        threatLevel = 'HIGH'
      }
    }

    // 2. Malicious Keywords Detection
    for (const keyword of this.MALICIOUS_KEYWORDS) {
      if (contentStr.includes(keyword)) {
        violations.push(`Malicious keyword detected: ${keyword}`)
        riskScore += 40
        threatLevel = 'CRITICAL'
      }
    }

    // 3. User Agent Security Analysis
    if (userAgent.includes('bot') || userAgent.includes('crawler') || 
        userAgent.includes('scraper') || userAgent.includes('python') ||
        userAgent.includes('curl') || userAgent.includes('wget')) {
      violations.push("Automated client detected")
      riskScore += 25
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel
    }

    // 4. Image URL Security Analysis
    if (data.imageUrl) {
      try {
        const url = new URL(data.imageUrl)
        if (this.SUSPICIOUS_IMAGE_DOMAINS.includes(url.hostname)) {
          violations.push("Image from suspicious domain")
          riskScore += 35
          threatLevel = 'HIGH'
        }
        if (url.protocol !== 'https:') {
          violations.push("Non-HTTPS image URL")
          riskScore += 20
        }
      } catch {
        violations.push("Invalid image URL format")
        riskScore += 15
      }
    }

    // 5. Contest Creation Specific Validations
    if (action === 'CREATE') {
      // Reward value validation
      if (data.rewardValue && data.rewardValue > 50000) {
        violations.push("Suspiciously high reward value")
        riskScore += 25
      }

      // Duration validation
      if (data.startDate && data.endDate) {
        const start = new Date(data.startDate)
        const end = new Date(data.endDate)
        const duration = end.getTime() - start.getTime()
        const maxDuration = 365 * 24 * 60 * 60 * 1000 // 1 year

        if (duration > maxDuration) {
          violations.push("Excessive contest duration")
          riskScore += 30
        }

        // Start date should not be in the past for new contests
        const now = new Date()
        if (start < now && (now.getTime() - start.getTime()) > (60 * 60 * 1000)) { // More than 1 hour ago
          violations.push("Contest start date is significantly in the past")
          riskScore += 20
        }
      }

      // Max participants validation
      if (data.maxParticipants && data.maxParticipants > 5000) {
        violations.push("Suspiciously high participant limit")
        riskScore += 20
      }
    }

    // 6. Rate Limiting Analysis
    const rateLimitCheck = rateLimit(`contest_analysis:${clientIP}`, 1000, 60000)
    if (!rateLimitCheck.success) {
      violations.push("High frequency requests detected")
      riskScore += 20
    }

    // 7. IP Risk Assessment
    const highRiskIPs = ['192.168.1.1', '10.0.0.1', '172.16.0.1'] // Simulated
    if (highRiskIPs.includes(clientIP)) {
      violations.push("Request from high-risk IP")
      riskScore += 40
      threatLevel = 'HIGH'
    }

    // 8. Authentication Security
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
      recommendations.push("Block user immediately")
      recommendations.push("Report to security team")
      recommendations.push("Review account privileges")
    } else if (riskScore >= 40) {
      recommendations.push("Enable enhanced monitoring")
      recommendations.push("Require additional verification")
    } else if (riskScore >= 20) {
      recommendations.push("Log for manual review")
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
        .replace(/[<>\"']/g, '')
        .trim()
    } else if (Array.isArray(input)) {
      return input.map(item => this.sanitizeInput(item))
    } else if (typeof input === 'object' && input !== null) {
      const sanitized: any = {}
      for (const [key, value] of Object.entries(input)) {
        const sanitizedKey = key.replace(/[<>\"';]/g, '').substring(0, 50)
        sanitized[sanitizedKey] = this.sanitizeInput(value)
      }
      return sanitized
    }
    return input
  }

  static validateBusinessLogic(data: any, action: string): { isValid: boolean; errors: string[] } {
    const errors: string[] = []

    if (action === 'CREATE') {
      // Date validation
      if (data.startDate && data.endDate) {
        const start = new Date(data.startDate)
        const end = new Date(data.endDate)
        const now = new Date()

        if (end <= start) {
          errors.push("End date must be after start date")
        }

        // Contest should not end before it starts
        if (end <= now) {
          errors.push("Contest end date must be in the future")
        }
      }

      // Reward validation
      if (data.rewardType && data.rewardValue) {
        if (data.rewardType === 'POINTS' && data.rewardValue > 10000) {
          errors.push("Points reward cannot exceed 10,000")
        }
        if (data.rewardType === 'CASH' && data.rewardValue > 5000) {
          errors.push("Cash reward cannot exceed $5,000")
        }
      }
    }

    return { isValid: errors.length === 0, errors }
  }
}

class AdvancedSessionManager {
  static async createSecureSession(
    request: NextRequest,
    userId: string,
    action: string,
    contestId?: string
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
      .update(`${clientIP}:${userAgent}:${userId}:${action}:${contestId || 'none'}:${Date.now()}`)
      .digest('hex')

    // Analyze session patterns
    const recentSessions = await prisma.auditLog.findMany({
      where: {
        userId,
        endpoint: { contains: '/api/contests' },
        createdAt: { gte: new Date(Date.now() - 300000) } // Last 5 minutes
      },
      orderBy: { createdAt: 'desc' },
      take: 25
    })

    let riskScore = 0
    
    // Check for rapid requests
    if (recentSessions.length > 20) {
      riskScore += 30
    }

    // Check for repeated contest access
    if (contestId) {
      const sameContestAccess = recentSessions.filter(s => {
        try {
          const newValues = JSON.parse(s.newValues || '{}')
          return newValues.contestId === contestId
        } catch {
          return false
        }
      })
      
      if (sameContestAccess.length > 5) {
        riskScore += 25
      }
    }

    // Check for high failure rate
    const failures = recentSessions.filter(s => !s.success)
    if (recentSessions.length > 0 && (failures.length / recentSessions.length) > 0.6) {
      riskScore += 35
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
        resource: 'CONTEST',
        endpoint: '/api/contests',
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
  static async analyzeUserContestBehavior(userId: string, action: string): Promise<{
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
          endpoint: { contains: '/api/contests' },
          createdAt: { gte: oneHourAgo }
        }
      }),
      prisma.auditLog.count({
        where: {
          userId,
          endpoint: { contains: '/api/contests' },
          createdAt: { gte: oneDayAgo }
        }
      }),
      prisma.auditLog.count({
        where: {
          userId,
          endpoint: { contains: '/api/contests' },
          success: false,
          createdAt: { gte: oneHourAgo }
        }
      })
    ])

    const anomalies: string[] = []
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'

    // Check activity patterns
    if (hourlyActivity > 50) {
      anomalies.push("Excessive hourly contest activity")
      riskLevel = 'HIGH'
    } else if (hourlyActivity > 25) {
      anomalies.push("High hourly contest activity")
      riskLevel = 'MEDIUM'
    }

    if (dailyActivity > 200) {
      anomalies.push("Excessive daily contest activity")
      riskLevel = 'HIGH'
    }

    // Check error rate
    const errorRate = hourlyActivity > 0 ? (recentErrors / hourlyActivity) : 0
    if (errorRate > 0.8) {
      anomalies.push("High error rate in contest operations")
      riskLevel = 'HIGH'
    } else if (errorRate > 0.5) {
      anomalies.push("Elevated error rate")
      riskLevel = 'MEDIUM'
    }

    // Check time-based patterns
    const currentHour = now.getHours()
    if (currentHour < 4 || currentHour > 22) {
      if (hourlyActivity > 10) {
        anomalies.push("Off-hours high activity")
        riskLevel = 'MEDIUM'
      }
    }

    const recommendation = riskLevel === 'HIGH' ? 
      "Immediate security review required" :
      riskLevel === 'MEDIUM' ? 
      "Enhanced monitoring recommended" : 
      "Normal behavior patterns"

    return { riskLevel, anomalies, recommendation }
  }
}

// Advanced GET /api/contests
export async function GET(req: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION
    const authHeader = req.headers.get('authorization')?.replace('Bearer ', '')
    if (!authHeader) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Authorization required", code: "UNAUTHORIZED_ACCESS" },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const decoded = verifyToken(authHeader)
    if (!decoded) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Invalid token", code: "INVALID_TOKEN" },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const userId = decoded.userId

    // 2. SESSION VALIDATION
    const sessionSecurity = await AdvancedSessionManager.createSecureSession(req, userId, 'GET')
    if (!sessionSecurity.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Session validation failed", code: "INVALID_SESSION" },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 3. RATE LIMITING
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`get_contests:${userId}:${clientIP}`, 100, 60000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Rate limit exceeded", code: "RATE_LIMIT_EXCEEDED" },
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 4. PARAMETER VALIDATION & SANITIZATION
    const { searchParams } = new URL(req.url)
    const page = Math.min(Math.max(parseInt(searchParams.get('page') || '1'), 1), 50)
    const limit = Math.min(Math.max(parseInt(searchParams.get('limit') || '10'), 1), 50)
    const type = searchParams.get('type')
    const status = searchParams.get('status')

    let whereClause: any = {}
    
    if (type && ['QUIZ', 'TRIVIA', 'PHOTO', 'REVIEW', 'LOYALTY', 'SEASONAL', 'DAILY', 'WEEKLY', 'MONTHLY'].includes(type)) {
      whereClause.type = type
    }
    
    if (status) {
      const now = new Date()
      switch (status) {
        case 'active':
          whereClause = {
            ...whereClause,
            isActive: true,
            startDate: { lte: now },
            endDate: { gte: now }
          }
          break
        case 'ended':
          whereClause = {
            ...whereClause,
            endDate: { lt: now }
          }
          break
        case 'upcoming':
          whereClause = {
            ...whereClause,
            isActive: true,
            startDate: { gt: now }
          }
          break
      }
    }

    // 5. SECURE DATA RETRIEVAL
    const [contests, totalCount] = await Promise.all([
      prisma.contest.findMany({
        where: whereClause,
        include: {
          participants: {
            select: {
              id: true,
              userId: true,
              score: true,
              completed: true,
            }
          },
          winners: {
            select: {
              id: true,
              userId: true,
              prizeAwarded: true,
            }
          }
        },
        orderBy: [
          { startDate: 'desc' }
        ],
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.contest.count({ where: whereClause })
    ])

    const processingTime = Date.now() - startTime

    // 6. COMPREHENSIVE AUDIT LOGGING
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'RETRIEVE',
        resource: 'CONTEST',
        endpoint: '/api/contests',
        method: 'GET',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          page,
          limit,
          filters: { type, status },
          resultsCount: contests.length,
          totalCount
        }),
        success: true,
        processingTime,
        sessionId: sessionSecurity.sessionId,
        fingerprint: sessionSecurity.fingerprint,
        riskScore: sessionSecurity.riskScore
      }
    })

    // 7. SECURE RESPONSE
    const response = addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: {
          contests,
          pagination: {
            page,
            limit,
            totalCount,
            totalPages: Math.ceil(totalCount / limit),
          },
          securityMetrics: {
            requestId,
            processingTime,
            sessionRiskScore: sessionSecurity.riskScore,
            isSecure: true
          }
        },
        message: "تم استرجاع المسابقات بنجاح"
      }),
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
        userId: 'unknown',
        action: 'ERROR',
        resource: 'CONTEST',
        endpoint: '/api/contests',
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
        { status: "error", message: "فشل في استرجاع المسابقات", code: "CONTEST_FETCH_ERROR" },
        { status: 500 }
      ),
      securityHeaders
    )
  }
}

// Advanced POST /api/contests (Create contest - Admin only)
export async function POST(req: NextRequest) {
  const startTime = Date.now()
  const requestId = uuidv4()

  try {
    // 1. ENHANCED AUTHENTICATION & AUTHORIZATION
    const token = req.headers.get('authorization')?.replace('Bearer ', '')
    if (!token) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Authorization required", code: "UNAUTHORIZED_ACCESS" },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    const decoded = verifyToken(token)
    if (!decoded || !['ADMIN', 'HOTEL_MANAGER'].includes(decoded.role)) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Insufficient permissions", code: "INSUFFICIENT_PERMISSIONS" },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    const userId = decoded.userId

    // 2. COMPREHENSIVE THREAT ANALYSIS
    const rawBody = await req.json()
    const threatAnalysis = await ContestSecurityManager.performComprehensiveThreatAnalysis(
      req,
      rawBody,
      userId,
      'CREATE'
    )

    if (threatAnalysis.isThreat) {
      await AdvancedSessionManager.logSecurityEvent(
        'CONTEST_THREAT_DETECTED_CREATE',
        userId,
        req,
        { threatAnalysis, requestId }
      )

      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Security threat detected. Contest creation blocked.", code: "SECURITY_VIOLATION" },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 3. SESSION VALIDATION
    const sessionSecurity = await AdvancedSessionManager.createSecureSession(req, userId, 'CREATE')
    if (!sessionSecurity.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Session validation failed", code: "INVALID_SESSION" },
          { status: 401 }
        ),
        securityHeaders
      )
    }

    // 4. BEHAVIORAL ANALYSIS
    const behaviorAnalysis = await BehavioralAnalyticsEngine.analyzeUserContestBehavior(userId, 'CREATE')
    if (behaviorAnalysis.riskLevel === 'HIGH') {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "High-risk behavior detected. Please contact support.", code: "BEHAVIORAL_VIOLATION" },
          { status: 403 }
        ),
        securityHeaders
      )
    }

    // 5. ENHANCED RATE LIMITING
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`create_contest:${userId}:${clientIP}`, 5, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Too many contest creation requests", code: "RATE_LIMIT_EXCEEDED" },
          { status: 429 }
        ),
        securityHeaders
      )
    }

    // 6. DATA SANITIZATION & VALIDATION
    const sanitizedData = ContestSecurityManager.sanitizeInput(rawBody)
    const validated = contestSchema.parse(sanitizedData)

    // 7. BUSINESS LOGIC VALIDATION
    const businessValidation = ContestSecurityManager.validateBusinessLogic(validated, 'CREATE')
    if (!businessValidation.isValid) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Business logic validation failed", code: "BUSINESS_LOGIC_ERROR", errors: businessValidation.errors },
          { status: 400 }
        ),
        securityHeaders
      )
    }

    // 8. SECURE CONTEST CREATION
    const contest = await prisma.contest.create({
      data: {
        id: uuidv4(),
        ...validated,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    })

    const processingTime = Date.now() - startTime

    // 9. COMPREHENSIVE AUDIT LOGGING
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'CREATE',
        resource: 'CONTEST',
        resourceId: contest.id,
        endpoint: '/api/contests',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          title: contest.title,
          type: contest.type,
          rewardType: contest.rewardType,
          rewardValue: contest.rewardValue,
          participantLimit: contest.maxParticipants,
          startDate: contest.startDate,
          endDate: contest.endDate
        }),
        success: true,
        processingTime,
        sessionId: sessionSecurity.sessionId,
        fingerprint: sessionSecurity.fingerprint,
        riskScore: sessionSecurity.riskScore,
        threatLevel: threatAnalysis.threatLevel,
        behaviorRiskLevel: behaviorAnalysis.riskLevel
      }
    })

    // 10. SECURE RESPONSE
    const response = addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { 
          contest,
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
        message: "تم إنشاء المسابقة بنجاح"
      }, { status: 201 }),
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
        userId: 'unknown',
        action: 'ERROR',
        resource: 'CONTEST',
        endpoint: '/api/contests',
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
        NextResponse.json({
          status: "error",
          message: "بيانات المسابقة غير صحيحة",
          code: "VALIDATION_ERROR",
          errors: error.errors
        }, { status: 400 }),
        securityHeaders
      )
    }

    return addSecurityHeaders(
      NextResponse.json({ 
        status: "error", 
        message: error.message || "فشل في إنشاء المسابقة", 
        code: "CONTEST_CREATE_ERROR" 
      }, { status: 500 }),
      securityHeaders
    )
  }
}