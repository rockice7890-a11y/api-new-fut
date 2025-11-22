import { NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"
import { createHash, randomBytes, timingSafeEqual } from "crypto"
import jwt from "jsonwebtoken"

// ===========================================
// ADVANCED SYSTEM MONITORING & ALERTS APIs
// مراقبة النظام المتقدمة - نظام أمان شامل
// ===========================================

export const dynamic = 'force-dynamic'

// Enhanced Security Headers
const SECURITY_HEADERS = {
  'X-DNS-Prefetch-Control': 'off',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
}

// Request Correlation & Tracing
let requestCounter = 0
const generateRequestId = () => {
  requestCounter++
  const timestamp = Date.now()
  const random = randomBytes(8).toString('hex')
  return `monitor-${timestamp}-${requestCounter}-${random}`
}

// Advanced AI Threat Detection
interface ThreatAnalysis {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  threats: string[]
  confidence: number
  recommendedAction: string
  suspiciousIndicators: string[]
}

class MonitoringThreatDetector {
  private threatPatterns = [
    { pattern: /admin|root|system|monitoring|analytics/i, weight: 25, type: 'PRIVILEGE_ESCALATION' },
    { pattern: /union\s+select|drop\s+table|delete\s+from/i, weight: 45, type: 'SQL_INJECTION' },
    { pattern: /<script|javascript:|vbscript:|onload=|onerror=/i, weight: 35, type: 'XSS_ATTEMPT' },
    { pattern: /\.\.\/|\.\.\\/|%2e%2e%2f/i, weight: 30, type: 'PATH_TRAVERSAL' },
    { pattern: /eval\(|exec\(|system\(|shell_exec|ps\(|wp\(/i, weight: 40, type: 'CODE_INJECTION' },
    { pattern: /dashboard|monitoring|alert|performance|metrics/i, weight: 15, type: 'MONITORING_ACCESS' }
  ]

  private accessPatterns = new Map<string, { count: number; lastRequest: Date; endpoints: Set<string>; suspiciousActivity: number }>()

  async analyzeMonitoringRequest(request: NextRequest, user: any, requestId: string, endpoint: string): Promise<ThreatAnalysis> {
    const userAgent = request.headers.get('user-agent') || ''
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const referer = request.headers.get('referer') || ''
    
    let riskScore = 0
    const threats: string[] = []
    const suspiciousIndicators: string[] = []
    
    // Analyze access patterns
    const accessKey = `${user.id}-${ip}`
    const now = new Date()
    const accessPattern = this.accessPatterns.get(accessKey) || { 
      count: 0, 
      lastRequest: now, 
      endpoints: new Set(),
      suspiciousActivity: 0
    }
    
    accessPattern.count++
    accessPattern.endpoints.add(endpoint)
    accessPattern.lastRequest = now
    
    // Detect endpoint enumeration
    if (accessPattern.endpoints.size > 10) { // Accessing more than 10 different endpoints
      riskScore += 20
      threats.push('ENDPOINT_ENUMERATION')
      suspiciousIndicators.push('Accessing multiple monitoring endpoints')
    }

    // Detect rapid access to sensitive endpoints
    const timeDiff = now.getTime() - accessPattern.lastRequest.getTime()
    const requestRate = 1000 / Math.max(timeDiff, 1)
    
    if (requestRate > 5 && ['performance', 'operation-logs', 'alerts'].includes(endpoint)) {
      riskScore += 25
      threats.push('SENSITIVE_ENDPOINT_FREQUENCY')
      suspiciousIndicators.push('High frequency access to sensitive monitoring endpoints')
    }

    // User agent analysis
    if (!userAgent || userAgent.length < 10) {
      riskScore += 10
      threats.push('SUSPICIOUS_USER_AGENT')
      suspiciousIndicators.push('Missing or invalid user agent')
    }

    // Bot detection
    const botPatterns = /bot|crawler|spider|scraper|curl|wget|python|go-http|libwww/i
    if (botPatterns.test(userAgent)) {
      riskScore += 30
      threats.push('AUTOMATED_MONITORING_ACCESS')
      suspiciousIndicators.push('Automated bot accessing monitoring endpoints')
    }

    // Analyze referer
    if (referer && !referer.includes(new URL(request.url).origin)) {
      riskScore += 15
      threats.push('EXTERNAL_MONITORING_ACCESS')
      suspiciousIndicators.push('External referer for monitoring access')
    }

    // Time-based analysis for monitoring access
    const hour = now.getHours()
    if (hour < 6 || hour > 22) {
      riskScore += 10
      if (endpoint === 'alerts') {
        riskScore += 10 // Extra risk for checking alerts outside hours
        suspiciousIndicators.push('Alert checking outside normal hours')
      }
    }

    // Analyze URL parameters for monitoring-specific threats
    const url = new URL(request.url)
    for (const [key, value] of url.searchParams.entries()) {
      for (const threatPattern of this.threatPatterns) {
        if (threatPattern.pattern.test(value)) {
          riskScore += threatPattern.weight
          threats.push(threatPattern.type)
          suspiciousIndicators.push(`Threat pattern detected in parameter: ${key}`)
        }
      }
    }

    // Role-based risk assessment
    if (user.role === 'HOTEL_MANAGER' && endpoint === 'performance') {
      riskScore += 5 // Slight additional scrutiny for performance monitoring
    }

    // Update access pattern
    this.accessPatterns.set(accessKey, accessPattern)

    // Determine risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    let recommendedAction: string

    if (riskScore >= 60) {
      riskLevel = 'CRITICAL'
      recommendedAction = 'BLOCK_REQUEST'
    } else if (riskScore >= 40) {
      riskLevel = 'HIGH'
      recommendedAction = 'ENHANCED_MONITORING'
    } else if (riskScore >= 20) {
      riskLevel = 'MEDIUM'
      recommendedAction = 'LOG_AND_CONTINUE'
    } else {
      riskLevel = 'LOW'
      recommendedAction = 'ALLOW_REQUEST'
    }

    return {
      riskLevel,
      threats,
      confidence: Math.min(riskScore, 100),
      recommendedAction,
      suspiciousIndicators
    }
  }

  cleanupOldEntries() {
    const now = new Date()
    const timeout = 10 * 60 * 1000 // 10 minutes
    
    for (const [key, pattern] of this.accessPatterns.entries()) {
      if (now.getTime() - pattern.lastRequest.getTime() > timeout) {
        this.accessPatterns.delete(key)
      }
    }
  }
}

const monitoringThreatDetector = new MonitoringThreatDetector()

// Enhanced Data Validation Schemas
const AlertSchema = z.object({
  alertType: z.enum(['warning', 'error', 'info', 'success']),
  title: z.string().min(1).max(200),
  message: z.string().min(1).max(2000),
  priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  targetRoles: z.array(z.string().min(1).max(50)).max(5).default(['ADMIN']),
  targetUsers: z.array(z.string().min(1).max(50)).max(10).optional(),
  expiresAt: z.string().datetime().optional(),
  correlationId: z.string().optional(),
  idempotencyKey: z.string().optional()
})

const PerformanceQuerySchema = z.object({
  hotelId: z.string().uuid().optional(),
  metricName: z.string().max(100).optional(),
  moduleName: z.string().max(100).optional(),
  status: z.string().max(50).optional(),
  timeRange: z.string().enum(['1h', '24h', '7d', '30d']).default('24h'),
  page: z.string().transform(Number).min(1).max(1000).default('1'),
  pageSize: z.string().transform(Number).min(1).max(200).default('50'),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
})

const OperationLogsQuerySchema = z.object({
  moduleId: z.string().uuid(),
  page: z.string().transform(Number).min(1).max(1000).default('1'),
  pageSize: z.string().transform(Number).min(1).max(100).default('20'),
  filterBy: z.string().optional(),
  filterValue: z.string().optional()
})

const AlertsQuerySchema = z.object({
  page: z.string().transform(Number).min(1).max(1000).default('1'),
  pageSize: z.string().transform(Number).min(1).max(100).default('20'),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  isActive: z.string().transform(val => val === 'true').optional(),
  alertType: z.enum(['warning', 'error', 'info', 'success']).optional(),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
})

// Sensitive Data Masking
function maskSensitiveMonitoringData(data: any, context: string, userRole: string): any {
  const maskValue = (value: string, visibleChars: number = 2): string => {
    if (!value || typeof value !== 'string') return value
    if (value.length <= visibleChars * 2) return '*'.repeat(value.length)
    return value.substring(0, visibleChars) + '*'.repeat(value.length - visibleChars * 2) + value.substring(value.length - visibleChars)
  }

  const applyRoleBasedMasking = (obj: any): any => {
    if (!obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(applyRoleBasedMasking)

    const masked = { ...obj }
    
    // Hotel Manager sees less detailed data
    if (userRole === 'HOTEL_MANAGER') {
      // Mask user details in logs
      if (masked.performedByUser) {
        masked.performedByUser = {
          id: masked.performedByUser.id,
          firstName: maskValue(masked.performedByUser.firstName, 1),
          lastName: maskValue(masked.performedByUser.lastName, 1),
          email: maskValue(masked.performedByUser.email),
          role: masked.performedByUser.role
        }
      }
      
      // Mask performance metrics details
      if (masked.metricValue !== undefined) {
        masked.metricValue = Math.round(masked.metricValue * 100) / 100
      }
    }
    
    // Admin sees full data but with IP masking
    if (userRole === 'ADMIN') {
      if (masked.ipAddress) {
        masked.ipAddress = maskValue(masked.ipAddress, 2)
      }
      if (masked.userAgent) {
        masked.userAgent = maskValue(masked.userAgent, 10)
      }
    }

    return masked
  }

  return applyRoleBasedMasking(data)
}

// Enhanced Audit Logging for Monitoring
async function logMonitoringSecurityEvent(
  eventType: string,
  user: any,
  request: NextRequest,
  details: any,
  riskLevel: string,
  requestId: string,
  endpoint: string
) {
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'
  const referer = request.headers.get('referer') || 'unknown'
  
  try {
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: `MONITORING_${eventType}`,
        resource: 'OperationalMonitoring',
        resourceId: details.resourceId || null,
        ipAddress: ip,
        userAgent,
        method: 'GET',
        newValues: JSON.stringify({
          ...details,
          endpoint,
          monitoringContext: true
        }),
        metadata: {
          requestId,
          riskLevel,
          timestamp: new Date().toISOString(),
          referer,
          userRole: user.role,
          adminLevel: user.adminLevel,
          endpointType: endpoint
        }
      }
    })

    // Log to security events table with monitoring context
    await prisma.securityEvent.create({
      data: {
        eventType: `MONITORING_${eventType}`,
        severity: riskLevel === 'CRITICAL' ? 'high' : riskLevel === 'HIGH' ? 'medium' : 'low',
        description: `Monitoring access: ${eventType} via ${endpoint}`,
        ipAddress: ip,
        userId: user.id,
        metadata: {
          requestId,
          userRole: user.role,
          endpoint,
          details
        },
        resolved: riskLevel !== 'CRITICAL'
      }
    })
  } catch (error) {
    console.error('Failed to log monitoring security event:', error)
  }
}

// Advanced Rate Limiting for Monitoring
class MonitoringRateLimiter {
  private buckets = new Map<string, { tokens: number; lastRefill: number; maxTokens: number; refillRate: number; endpointUsage: Map<string, number> }>()

  constructor() {
    setInterval(() => this.cleanup(), 5 * 60 * 1000)
  }

  async checkLimit(key: string, endpoint: string, maxTokens: number, refillRate: number, windowMs: number): Promise<{ success: boolean; remaining: number; resetTime: number; endpointLimit?: boolean }> {
    const now = Date.now()
    const bucket = this.buckets.get(key) || { 
      tokens: maxTokens, 
      lastRefill: now, 
      maxTokens, 
      refillRate,
      endpointUsage: new Map()
    }

    // Calculate tokens to add based on time passed
    const timePassed = now - bucket.lastRefill
    const tokensToAdd = (timePassed * bucket.refillRate) / windowMs
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd)
    bucket.lastRefill = now

    // Track endpoint-specific usage
    const endpointCount = bucket.endpointUsage.get(endpoint) || 0
    
    // Endpoint-specific limits
    const endpointLimits = {
      'performance': 20,
      'alerts': 30,
      'operation-logs': 25
    }
    
    const endpointLimit = endpointLimits[endpoint as keyof typeof endpointLimits] || 30
    
    if (endpointCount >= endpointLimit) {
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + (windowMs / bucket.refillRate),
        endpointLimit: true
      }
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1
      bucket.endpointUsage.set(endpoint, endpointCount + 1)
      this.buckets.set(key, bucket)
      
      return { 
        success: true, 
        remaining: Math.floor(bucket.tokens), 
        resetTime: now + (windowMs / bucket.refillRate) 
      }
    }

    return { 
      success: false, 
      remaining: 0, 
      resetTime: bucket.lastRefill + (windowMs / bucket.refillRate),
      endpointLimit: false
    }
  }

  private cleanup() {
    const now = Date.now()
    const timeout = 30 * 60 * 1000 // 30 minutes
    
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > timeout) {
        this.buckets.delete(key)
      }
    }
  }
}

const monitoringRateLimiter = new MonitoringRateLimiter()

// ===========================================
// GET - جلب التنبيهات والإحصائيات (Advanced Security)
// ===========================================
export async function GET(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Monitoring GET request initiated`)

  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) {
    console.log(`[${requestId}] Authentication failed`)
    return NextResponse.json(failResponse(null, "Unauthorized", "AUTH_FAILED"), { 
      status: 401,
      headers: SECURITY_HEADERS 
    })
  }

  console.log(`[${requestId}] User authenticated: ${auth.payload.email} (${auth.payload.role})`)

  const searchParams = req.nextUrl.searchParams
  const endpoint = searchParams.get("type") || "alerts"
  
  console.log(`[${requestId}] Monitoring endpoint: ${endpoint}`)

  // AI Threat Analysis for monitoring
  const threatAnalysis = await monitoringThreatDetector.analyzeMonitoringRequest(req, auth.payload, requestId, endpoint)
  console.log(`[${requestId}] Threat analysis: ${threatAnalysis.riskLevel} risk`)

  // Log security event
  await logMonitoringSecurityEvent('MONITORING_ACCESS', auth.payload, req, {
    requestId,
    endpoint,
    queryParams: Object.fromEntries(searchParams.entries())
  }, threatAnalysis.riskLevel, requestId, endpoint)

  // Advanced Rate Limiting
  const rateLimitKey = `monitoring:${auth.payload.userId}`
  const rateLimitResult = await monitoringRateLimiter.checkLimit(rateLimitKey, endpoint, 60, 60, 60000) // 60 requests per minute
  
  if (!rateLimitResult.success) {
    console.log(`[${requestId}] Rate limit exceeded for ${endpoint}`)
    return NextResponse.json(
      failResponse(null, `Rate limit exceeded for ${endpoint} endpoint. Try again later.`, "RATE_LIMIT_EXCEEDED"), 
      { 
        status: 429,
        headers: {
          ...SECURITY_HEADERS,
          'X-RateLimit-Limit': '60',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': Math.ceil(rateLimitResult.resetTime / 1000).toString(),
          'X-Endpoint': endpoint
        }
      }
    )
  }

  try {
    switch (endpoint) {
      case "performance": {
        console.log(`[${requestId}] Processing performance monitoring`)
        
        const queryData = PerformanceQuerySchema.parse({
          hotelId: searchParams.get("hotelId") || undefined,
          metricName: searchParams.get("metricName") || undefined,
          moduleName: searchParams.get("moduleName") || undefined,
          status: searchParams.get("status") || undefined,
          timeRange: searchParams.get("timeRange") || "24h",
          page: searchParams.get("page") || "1",
          pageSize: searchParams.get("pageSize") || "50",
          sortBy: searchParams.get("sortBy") || undefined,
          sortOrder: searchParams.get("sortOrder") || "desc"
        })

        // Time range calculation
        const now = new Date()
        let startTime = new Date()
        
        const timeRanges = {
          '1h': () => startTime.setHours(now.getHours() - 1),
          '24h': () => startTime.setDate(now.getDate() - 1),
          '7d': () => startTime.setDate(now.getDate() - 7),
          '30d': () => startTime.setDate(now.getDate() - 30)
        }
        
        timeRanges[queryData.timeRange as keyof typeof timeRanges]?.()

        const where: any = {
          measuredAt: {
            gte: startTime,
            lte: now
          }
        }

        if (queryData.hotelId) where.hotelId = queryData.hotelId
        if (queryData.metricName) where.metricName = queryData.metricName
        if (queryData.moduleName) where.moduleName = queryData.moduleName
        if (queryData.status) where.status = queryData.status

        const performance = await prisma.performanceMonitor.findMany({
          where,
          orderBy: { 
            [queryData.sortBy || 'measuredAt']: queryData.sortOrder 
          },
          skip: (queryData.page - 1) * queryData.pageSize,
          take: queryData.pageSize
        })

        const total = await prisma.performanceMonitor.count({ where })

        // Enhanced statistics
        const stats = await prisma.performanceMonitor.groupBy({
          by: ['metricName', 'status'],
          where,
          _count: { metricName: true },
          _avg: { value: true },
          _max: { value: true },
          _min: { value: true }
        })

        // Mask sensitive performance data
        const maskedPerformance = performance.map(perf => 
          maskSensitiveMonitoringData(perf, 'performance', auth.payload.role)
        )

        const executionTime = Date.now() - startTime

        return NextResponse.json(
          successResponse({
            performance: maskedPerformance,
            stats,
            total,
            timeRange: queryData.timeRange,
            page: queryData.page,
            pageSize: queryData.pageSize,
            performance: {
              executionTime,
              requestId,
              threatLevel: threatAnalysis.riskLevel
            }
          }, "Performance metrics retrieved successfully"),
          {
            status: 200,
            headers: {
              ...SECURITY_HEADERS,
              'X-Request-ID': requestId,
              'X-Response-Time': executionTime.toString(),
              'X-Threat-Level': threatAnalysis.riskLevel,
              'X-Endpoint': endpoint
            }
          }
        )
      }

      case "operation-logs": {
        console.log(`[${requestId}] Processing operation logs`)
        
        const queryData = OperationLogsQuerySchema.parse({
          moduleId: searchParams.get("moduleId") || "",
          page: searchParams.get("page") || "1",
          pageSize: searchParams.get("pageSize") || "20",
          filterBy: searchParams.get("filterBy") || undefined,
          filterValue: searchParams.get("filterValue") || undefined
        })

        if (!queryData.moduleId) {
          return NextResponse.json(
            failResponse(null, "Module ID required", "MODULE_ID_REQUIRED"), 
            { status: 400, headers: SECURITY_HEADERS }
          )
        }

        // Permission validation
        if (auth.payload.role === 'HOTEL_MANAGER') {
          const operationalModule = await prisma.operationalModule.findFirst({
            where: {
              id: queryData.moduleId,
              hotelId: await prisma.hotel.findFirst({
                where: { managerId: auth.payload.userId },
                select: { id: true }
              }).then(h => h?.id)
            }
          })

          if (!operationalModule) {
            return NextResponse.json(
              failResponse(null, "Insufficient permissions for this module", "INSUFFICIENT_PERMISSIONS"), 
              { status: 403, headers: SECURITY_HEADERS }
            )
          }
        }

        const where: any = { moduleId: queryData.moduleId }
        
        if (queryData.filterBy && queryData.filterValue) {
          where[queryData.filterBy] = { contains: queryData.filterValue }
        }

        const logs = await prisma.operationLog.findMany({
          where,
          include: {
            performedByUser: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true,
                role: true
              }
            }
          },
          orderBy: { createdAt: 'desc' },
          skip: (queryData.page - 1) * queryData.pageSize,
          take: queryData.pageSize
        })

        const total = await prisma.operationLog.count({ where })

        // Mask sensitive log data
        const maskedLogs = logs.map(log => 
          maskSensitiveMonitoringData(log, 'logs', auth.payload.role)
        )

        const executionTime = Date.now() - startTime

        return NextResponse.json(
          successResponse({
            logs: maskedLogs,
            total,
            page: queryData.page,
            pageSize: queryData.pageSize,
            hasMore: (queryData.page * queryData.pageSize) < total,
            performance: {
              executionTime,
              requestId,
              threatLevel: threatAnalysis.riskLevel
            }
          }, "Operation logs retrieved successfully"),
          {
            status: 200,
            headers: {
              ...SECURITY_HEADERS,
              'X-Request-ID': requestId,
              'X-Response-Time': executionTime.toString(),
              'X-Threat-Level': threatAnalysis.riskLevel,
              'X-Endpoint': endpoint
            }
          }
        )
      }

      default: {
        console.log(`[${requestId}] Processing alerts`)
        
        const queryData = AlertsQuerySchema.parse({
          page: searchParams.get("page") || "1",
          pageSize: searchParams.get("pageSize") || "20",
          priority: searchParams.get("priority") || undefined,
          isActive: searchParams.get("isActive") || undefined,
          alertType: searchParams.get("alertType") || undefined,
          sortBy: searchParams.get("sortBy") || undefined,
          sortOrder: searchParams.get("sortOrder") || "desc"
        })

        const where: any = {}

        // Filter by priority
        if (queryData.priority) where.priority = queryData.priority
        
        // Filter by status
        if (queryData.isActive !== undefined) where.isActive = queryData.isActive
        
        // Filter by alert type
        if (queryData.alertType) where.alertType = queryData.alertType

        // Role-based filtering
        if (auth.payload.role !== 'ADMIN' && auth.payload.adminLevel !== 'SUPER_ADMIN') {
          where.OR = [
            { targetRoles: { has: auth.payload.role } },
            { targetUsers: { has: auth.payload.userId } }
          ]
        }

        const alerts = await prisma.operationalAlert.findMany({
          where,
          orderBy: [
            { priority: 'desc' },
            { createdAt: 'desc' }
          ],
          skip: (queryData.page - 1) * queryData.pageSize,
          take: queryData.pageSize
        })

        const total = await prisma.operationalAlert.count({ where })

        // Enhanced statistics
        const stats = await prisma.operationalAlert.groupBy({
          by: ['priority', 'isActive'],
          where: {
            ...where,
            OR: [
              { expiresAt: null },
              { expiresAt: { gte: new Date() } }
            ]
          },
          _count: { priority: true }
        })

        // Mask sensitive alert data
        const maskedAlerts = alerts.map(alert => 
          maskSensitiveMonitoringData(alert, 'alerts', auth.payload.role)
        )

        const executionTime = Date.now() - startTime

        return NextResponse.json(
          successResponse({
            alerts: maskedAlerts,
            stats: stats.reduce((acc, stat) => {
              const key = `${stat.priority}_${stat.isActive ? 'active' : 'inactive'}`
              acc[key] = stat._count.priority
              return acc
            }, {} as Record<string, number>),
            total,
            page: queryData.page,
            pageSize: queryData.pageSize,
            hasMore: (queryData.page * queryData.pageSize) < total,
            performance: {
              executionTime,
              requestId,
              threatLevel: threatAnalysis.riskLevel
            }
          }, "Alerts retrieved successfully"),
          {
            status: 200,
            headers: {
              ...SECURITY_HEADERS,
              'X-Request-ID': requestId,
              'X-Response-Time': executionTime.toString(),
              'X-Threat-Level': threatAnalysis.riskLevel,
              'X-Endpoint': endpoint
            }
          }
        )
      }
    }
  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in GET monitoring:`, error)
    
    await logMonitoringSecurityEvent('MONITORING_ERROR', auth.payload, req, {
      requestId,
      endpoint,
      error: error.message,
      executionTime,
      stack: error.stack
    }, 'MEDIUM', requestId, endpoint)

    return NextResponse.json(
      failResponse(null, error.message || "Failed to retrieve monitoring data", "MONITORING_ERROR"), 
      { 
        status: 500,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Endpoint': endpoint
        }
      }
    )
  } finally {
    monitoringThreatDetector.cleanupOldEntries()
  }
}

// ===========================================
// POST - إنشاء تنبيه (Advanced Security)
// ===========================================
export async function POST(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Alert creation POST request initiated`)

  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) {
    console.log(`[${requestId}] Authentication failed`)
    return NextResponse.json(failResponse(null, "Unauthorized", "AUTH_FAILED"), { 
      status: 401,
      headers: SECURITY_HEADERS 
    })
  }

  console.log(`[${requestId}] User authenticated: ${auth.payload.email} (${auth.payload.role})`)

  // Threat analysis
  const threatAnalysis = await monitoringThreatDetector.analyzeMonitoringRequest(req, auth.payload, requestId, 'alerts')
  console.log(`[${requestId}] Threat analysis: ${threatAnalysis.riskLevel} risk`)

  if (threatAnalysis.riskLevel === 'CRITICAL') {
    await logMonitoringSecurityEvent('CRITICAL_ALERT_THREAT_BLOCKED', auth.payload, req, {
      requestId,
      threats: threatAnalysis.threats,
      indicators: threatAnalysis.suspiciousIndicators
    }, 'CRITICAL', requestId, 'alerts')
    
    return NextResponse.json(
      failResponse(null, "Alert creation blocked due to security concerns", "THREAT_BLOCKED"), 
      { 
        status: 403,
        headers: SECURITY_HEADERS 
      }
    )
  }

  // Rate limiting
  const rateLimitKey = `alert_create:${auth.payload.userId}`
  const rateLimitResult = await monitoringRateLimiter.checkLimit(rateLimitKey, 'alerts', 20, 20, 60000) // 20 alerts per minute
  
  if (!rateLimitResult.success) {
    console.log(`[${requestId}] Rate limit exceeded for alert creation`)
    return NextResponse.json(
      failResponse(null, "Rate limit exceeded. Too many alerts created.", "RATE_LIMIT_EXCEEDED"), 
      { 
        status: 429,
        headers: {
          ...SECURITY_HEADERS,
          'X-RateLimit-Limit': '20',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': Math.ceil(rateLimitResult.resetTime / 1000).toString()
        }
      }
    )
  }

  try {
    const body = await req.json()
    const validated = AlertSchema.parse(body)

    console.log(`[${requestId}] Validated alert: ${validated.title}`)

    // Create alert with enhanced metadata
    const alert = await prisma.operationalAlert.create({
      data: {
        hotelId: auth.payload.role === 'HOTEL_MANAGER' ? 
          await prisma.hotel.findFirst({
            where: { managerId: auth.payload.userId },
            select: { id: true }
          }).then(h => h?.id) : null,
        alertType: validated.alertType,
        title: validated.title,
        message: validated.message,
        priority: validated.priority,
        targetRoles: validated.targetRoles as any,
        targetUsers: validated.targetUsers as any || [],
        expiresAt: validated.expiresAt ? new Date(validated.expiresAt) : null,
        metadata: {
          requestId,
          createdBy: auth.payload.email,
          threatLevel: threatAnalysis.riskLevel,
          correlationId: validated.correlationId,
          idempotencyKey: validated.idempotencyKey
        }
      }
    })

    const executionTime = Date.now() - startTime

    console.log(`[${requestId}] Alert created successfully in ${executionTime}ms`)

    // Log security event
    await logMonitoringSecurityEvent('ALERT_CREATED', auth.payload, req, {
      requestId,
      alertId: alert.id,
      alertType: validated.alertType,
      priority: validated.priority,
      title: validated.title,
      threatLevel: threatAnalysis.riskLevel,
      executionTime
    }, threatAnalysis.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW', requestId, 'alerts')

    return NextResponse.json(
      successResponse({
        ...alert,
        performance: {
          executionTime,
          requestId,
          threatLevel: threatAnalysis.riskLevel
        }
      }, "Alert created successfully"),
      {
        status: 201,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Threat-Level': threatAnalysis.riskLevel,
          'X-Alert-ID': alert.id
        }
      }
    )
  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in POST alert creation:`, error)
    
    await logMonitoringSecurityEvent('ALERT_CREATION_ERROR', auth.payload, req, {
      requestId,
      error: error.message,
      executionTime,
      stack: error.stack
    }, 'MEDIUM', requestId, 'alerts')

    return NextResponse.json(
      failResponse(null, error.message || "Failed to create alert", "CREATE_ALERT_ERROR"), 
      { 
        status: 500,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString()
        }
      }
    )
  } finally {
    monitoringThreatDetector.cleanupOldEntries()
  }
}

// ===========================================
// PUT - إلغاء أو قراءة تنبيه (Advanced Security)
// ===========================================
export async function PUT(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Alert update PUT request initiated`)

  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) {
    console.log(`[${requestId}] Authentication failed`)
    return NextResponse.json(failResponse(null, "Unauthorized", "AUTH_FAILED"), { 
      status: 401,
      headers: SECURITY_HEADERS 
    })
  }

  console.log(`[${requestId}] User authenticated: ${auth.payload.email} (${auth.payload.role})`)

  // Threat analysis
  const threatAnalysis = await monitoringThreatDetector.analyzeMonitoringRequest(req, auth.payload, requestId, 'alerts')
  console.log(`[${requestId}] Threat analysis: ${threatAnalysis.riskLevel} risk`)

  // Rate limiting
  const rateLimitKey = `alerts_update:${auth.payload.userId}`
  const rateLimitResult = await monitoringRateLimiter.checkLimit(rateLimitKey, 'alerts', 30, 30, 60000) // 30 updates per minute
  
  if (!rateLimitResult.success) {
    console.log(`[${requestId}] Rate limit exceeded for alert updates`)
    return NextResponse.json(
      failResponse(null, "Rate limit exceeded. Too many alert updates.", "RATE_LIMIT_EXCEEDED"), 
      { 
        status: 429,
        headers: {
          ...SECURITY_HEADERS,
          'X-RateLimit-Limit': '30',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': Math.ceil(rateLimitResult.resetTime / 1000).toString()
        }
      }
    )
  }

  try {
    const body = await req.json()
    const { alertId, action, reason } = body

    if (!alertId || !action) {
      return NextResponse.json(
        failResponse(null, "Alert ID and action are required", "MISSING_PARAMETERS"), 
        { status: 400, headers: SECURITY_HEADERS }
      )
    }

    console.log(`[${requestId}] Alert update: ${action} for alert ${alertId}`)

    const where: any = { id: alertId }

    // Role-based filtering
    if (auth.payload.role !== 'ADMIN' && auth.payload.adminLevel !== 'SUPER_ADMIN') {
      where.OR = [
        { targetRoles: { has: auth.payload.role } },
        { targetUsers: { has: auth.payload.userId } }
      ]
    }

    let updatedAlert

    switch (action) {
      case 'dismiss': {
        updatedAlert = await prisma.operationalAlert.update({
          where,
          data: {
            isActive: false,
            dismissedBy: auth.payload.userId,
            dismissedAt: new Date(),
            metadata: {
              dismissedReason: reason,
              dismissedBy: auth.payload.email,
              dismissalRequestId: requestId
            }
          }
        })
        break
      }

      case 'mark_read': {
        updatedAlert = await prisma.operationalAlert.update({
          where,
          data: {
            isRead: true,
            readAt: new Date(),
            metadata: {
              readBy: auth.payload.email,
              readRequestId: requestId
            }
          }
        })
        break
      }

      default:
        return NextResponse.json(
          failResponse(null, "Unsupported action", "UNSUPPORTED_ACTION"), 
          { status: 400, headers: SECURITY_HEADERS }
        )
    }

    // Log the operation with enhanced audit
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: `ALERT_${action.toUpperCase()}`,
        resource: 'OperationalAlert',
        resourceId: alertId,
        ipAddress: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown',
        userAgent: req.headers.get('user-agent') || undefined,
        method: 'PUT',
        newValues: JSON.stringify({ 
          action, 
          reason, 
          originalAlert: updatedAlert,
          requestId,
          threatLevel: threatAnalysis.riskLevel
        }),
        metadata: {
          requestId,
          threatLevel: threatAnalysis.riskLevel,
          alertAction: action
        }
      }
    })

    const executionTime = Date.now() - startTime

    console.log(`[${requestId}] Alert ${action} completed successfully in ${executionTime}ms`)

    // Log security event
    await logMonitoringSecurityEvent('ALERT_UPDATE', auth.payload, req, {
      requestId,
      alertId,
      action,
      reason,
      threatLevel: threatAnalysis.riskLevel,
      executionTime
    }, threatAnalysis.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW', requestId, 'alerts')

    return NextResponse.json(
      successResponse({
        ...updatedAlert,
        performance: {
          executionTime,
          requestId,
          threatLevel: threatAnalysis.riskLevel
        }
      }, `Alert ${action} completed successfully`),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Threat-Level': threatAnalysis.riskLevel,
          'X-Alert-Action': action
        }
      }
    )
  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in PUT alert update:`, error)
    
    await logMonitoringSecurityEvent('ALERT_UPDATE_ERROR', auth.payload, req, {
      requestId,
      error: error.message,
      executionTime,
      stack: error.stack
    }, 'MEDIUM', requestId, 'alerts')

    return NextResponse.json(
      failResponse(null, error.message || "Failed to update alert", "UPDATE_ALERT_ERROR"), 
      { 
        status: 500,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString()
        }
      }
    )
  } finally {
    monitoringThreatDetector.cleanupOldEntries()
  }
}