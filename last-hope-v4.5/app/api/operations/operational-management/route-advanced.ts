import { NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"
import { createHash, randomBytes, timingSafeEqual } from "crypto"
import jwt from "jsonwebtoken"

// ===========================================
// ADVANCED OPERATIONAL MANAGEMENT APIs
// إدارة العمليات المتقدمة - نظام أمان شامل
// ===========================================

export const dynamic = 'force-dynamic'

// Security Headers Configuration
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
  return `op-${timestamp}-${requestCounter}-${random}`
}

// AI-Powered Threat Detection System
interface ThreatAnalysis {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  threats: string[]
  confidence: number
  recommendedAction: string
  suspiciousIndicators: string[]
}

class AIThreatDetector {
  private threatPatterns = [
    { pattern: /admin|root|system|privilege/i, weight: 30, type: 'PRIVILEGE_ESCALATION' },
    { pattern: /union\s+select|drop\s+table|insert\s+into/i, weight: 50, type: 'SQL_INJECTION' },
    { pattern: /<script|javascript:|vbscript:|onload=|onerror=/i, weight: 40, type: 'XSS_ATTEMPT' },
    { pattern: /\.\.\/|\.\.\\/|%2e%2e%2f/i, weight: 35, type: 'PATH_TRAVERSAL' },
    { pattern: /eval\(|exec\(|system\(|shell_exec/i, weight: 45, type: 'CODE_INJECTION' }
  ]

  private behaviorPatterns = new Map<string, { count: number; lastRequest: Date; pattern: string }>()

  async analyzeRequest(request: NextRequest, user: any, requestId: string): Promise<ThreatAnalysis> {
    const userAgent = request.headers.get('user-agent') || ''
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const referer = request.headers.get('referer') || ''
    
    let riskScore = 0
    const threats: string[] = []
    const suspiciousIndicators: string[] = []
    
    // Analyze user agent
    if (!userAgent || userAgent.length < 10) {
      riskScore += 15
      threats.push('SUSPICIOUS_USER_AGENT')
      suspiciousIndicators.push('Missing or invalid user agent')
    }

    // Detect automated/bot patterns
    const botPatterns = /bot|crawler|spider|scraper|curl|wget|python|java|go-http/i
    if (botPatterns.test(userAgent)) {
      riskScore += 25
      threats.push('AUTOMATED_ACCESS')
      suspiciousIndicators.push('Automated bot detected')
    }

    // Rate limiting analysis
    const behaviorKey = `${user.id}-${ip}`
    const now = new Date()
    const behavior = this.behaviorPatterns.get(behaviorKey)
    
    if (behavior) {
      const timeDiff = now.getTime() - behavior.lastRequest.getTime()
      const requestRate = 1000 / Math.max(timeDiff, 1) // requests per second
      
      if (requestRate > 10) { // More than 10 requests per second
        riskScore += 30
        threats.push('HIGH_FREQUENCY_REQUESTS')
        suspiciousIndicators.push('High request frequency detected')
      }
      
      behavior.count++
      behavior.lastRequest = now
    } else {
      this.behaviorPatterns.set(behaviorKey, { count: 1, lastRequest: now, pattern: '' })
    }

    // Analyze referer
    if (referer && !referer.includes(new URL(request.url).origin)) {
      riskScore += 10
      threats.push('EXTERNAL_REFERRER')
      suspiciousIndicators.push('External referer detected')
    }

    // Check for common attack patterns in URL parameters
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

    // Time-based analysis
    const hour = now.getHours()
    if (hour < 6 || hour > 22) { // Outside normal business hours
      riskScore += 5
      suspiciousIndicators.push('Request outside normal hours')
    }

    // Determine risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    let recommendedAction: string

    if (riskScore >= 70) {
      riskLevel = 'CRITICAL'
      recommendedAction = 'BLOCK_REQUEST'
    } else if (riskScore >= 50) {
      riskLevel = 'HIGH'
      recommendedAction = 'ENHANCED_MONITORING'
    } else if (riskScore >= 25) {
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
    const timeout = 5 * 60 * 1000 // 5 minutes
    
    for (const [key, behavior] of this.behaviorPatterns.entries()) {
      if (now.getTime() - behavior.lastRequest.getTime() > timeout) {
        this.behaviorPatterns.delete(key)
      }
    }
  }
}

const threatDetector = new AIThreatDetector()

// Enhanced Validation Schema
const OperationalControlSchema = z.object({
  moduleName: z.string().min(1).max(100),
  action: z.enum(['LOCK', 'UNLOCK', 'HIDE', 'SHOW', 'SUSPEND', 'ACTIVATE', 'MAINTENANCE_MODE', 'EMERGENCY_MODE']),
  reason: z.string().min(5).max(500).optional(),
  message: z.string().max(1000).optional(),
  controlLevel: z.enum(['SOFT_LOCK', 'HARD_LOCK', 'DEPARTMENTS', 'ROLES', 'GLOBAL']).default('SOFT_LOCK'),
  allowedRoles: z.array(z.string().min(1).max(50)).max(10).optional(),
  restrictedRoles: z.array(z.string().min(1).max(50)).max(10).optional(),
  unlockAt: z.string().datetime().optional(),
  adminOnly: z.boolean().default(false),
  allowOverride: z.boolean().default(false),
  correlationId: z.string().optional(),
  idempotencyKey: z.string().optional()
})

const OperationsQuerySchema = z.object({
  hotelId: z.string().uuid().optional(),
  status: z.string().optional(),
  operationType: z.string().optional(),
  page: z.string().transform(Number).min(1).max(1000).default('1'),
  pageSize: z.string().transform(Number).min(1).max(100).default('20'),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
})

// Data Masking for Sensitive Information
function maskSensitiveData(data: any, context: string): any {
  const maskValue = (value: string, visibleChars: number = 2): string => {
    if (!value || typeof value !== 'string') return value
    if (value.length <= visibleChars * 2) return '*'.repeat(value.length)
    return value.substring(0, visibleChars) + '*'.repeat(value.length - visibleChars * 2) + value.substring(value.length - visibleChars)
  }

  const maskObject = (obj: any): any => {
    if (!obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(maskObject)

    const masked = { ...obj }
    
    // Mask sensitive fields based on context
    const sensitiveFields = context === 'admin' ? ['email', 'phone', 'address', 'ssn', 'taxId'] 
                     : context === 'financial' ? ['salary', 'accountNumber', 'creditCard', 'iban']
                     : ['email', 'phone', 'name']
    
    for (const field of sensitiveFields) {
      if (masked[field]) {
        if (typeof masked[field] === 'string') {
          masked[field] = maskValue(masked[field])
        }
      }
    }

    return masked
  }

  return maskObject(data)
}

// Comprehensive Audit Logging
async function logSecurityEvent(
  eventType: string,
  user: any,
  request: NextRequest,
  details: any,
  riskLevel: string,
  requestId: string
) {
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'
  const referer = request.headers.get('referer') || 'unknown'
  
  try {
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: eventType,
        resource: 'OperationalManagement',
        resourceId: details.resourceId || null,
        ipAddress: ip,
        userAgent,
        method: 'POST',
        newValues: JSON.stringify(details),
        metadata: {
          requestId,
          riskLevel,
          timestamp: new Date().toISOString(),
          referer,
          userRole: user.role,
          adminLevel: user.adminLevel
        }
      }
    })

    // Log to security events table
    await prisma.securityEvent.create({
      data: {
        eventType: `OPERATIONAL_${eventType}`,
        severity: riskLevel === 'CRITICAL' ? 'high' : riskLevel === 'HIGH' ? 'medium' : 'low',
        description: `Operational management event: ${eventType}`,
        ipAddress: ip,
        userId: user.id,
        metadata: {
          requestId,
          userRole: user.role,
          details
        },
        resolved: riskLevel !== 'CRITICAL'
      }
    })
  } catch (error) {
    console.error('Failed to log security event:', error)
  }
}

// Advanced Rate Limiting with Token Bucket
class AdvancedRateLimiter {
  private buckets = new Map<string, { tokens: number; lastRefill: number; maxTokens: number; refillRate: number }>()

  constructor() {
    // Cleanup old entries every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000)
  }

  async checkLimit(key: string, maxTokens: number, refillRate: number, windowMs: number): Promise<{ success: boolean; remaining: number; resetTime: number }> {
    const now = Date.now()
    const bucket = this.buckets.get(key) || { 
      tokens: maxTokens, 
      lastRefill: now, 
      maxTokens, 
      refillRate 
    }

    // Calculate tokens to add based on time passed
    const timePassed = now - bucket.lastRefill
    const tokensToAdd = (timePassed * bucket.refillRate) / windowMs
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd)
    bucket.lastRefill = now

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1
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
      resetTime: bucket.lastRefill + (windowMs / bucket.refillRate) 
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

const advancedRateLimiter = new AdvancedRateLimiter()

// Idempotency Check
const idempotencyStore = new Map<string, { status: number; response: any; timestamp: number }>()

function checkIdempotency(key: string): { shouldProcess: boolean; existingResponse?: any } {
  const now = Date.now()
  const timeout = 24 * 60 * 60 * 1000 // 24 hours
  
  const existing = idempotencyStore.get(key)
  if (existing && (now - existing.timestamp) < timeout) {
    return { shouldProcess: false, existingResponse: existing.response }
  }
  
  if (existing) {
    idempotencyStore.delete(key)
  }
  
  return { shouldProcess: true }
}

function storeIdempotencyResult(key: string, status: number, response: any) {
  idempotencyStore.set(key, {
    status,
    response,
    timestamp: Date.now()
  })
}

// ===========================================
// GET - قائمة جميع العمليات الحالية (Advanced Security)
// ===========================================
export async function GET(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Operational Management GET request initiated`)

  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) {
    console.log(`[${requestId}] Authentication failed`)
    return NextResponse.json(failResponse(null, "Unauthorized", "AUTH_FAILED"), { 
      status: 401,
      headers: SECURITY_HEADERS 
    })
  }

  console.log(`[${requestId}] User authenticated: ${auth.payload.email} (${auth.payload.role})`)

  // AI Threat Analysis
  const threatAnalysis = await threatDetector.analyzeRequest(req, auth.payload, requestId)
  console.log(`[${requestId}] Threat analysis: ${threatAnalysis.riskLevel} risk`)

  // Log security event
  await logSecurityEvent('OPERATIONS_LIST_ACCESS', auth.payload, req, { 
    requestId,
    queryParams: Object.fromEntries(req.nextUrl.searchParams.entries())
  }, threatAnalysis.riskLevel, requestId)

  // Advanced Rate Limiting
  const rateLimitKey = `operations_list:${auth.payload.userId}`
  const rateLimitResult = await advancedRateLimiter.checkLimit(rateLimitKey, 30, 30, 60000) // 30 requests per minute
  
  if (!rateLimitResult.success) {
    console.log(`[${requestId}] Rate limit exceeded`)
    return NextResponse.json(
      failResponse(null, "Rate limit exceeded. Try again later.", "RATE_LIMIT_EXCEEDED"), 
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
    const searchParams = req.nextUrl.searchParams
    const queryData = OperationsQuerySchema.parse({
      hotelId: searchParams.get("hotelId") || undefined,
      status: searchParams.get("status") || undefined,
      operationType: searchParams.get("operationType") || undefined,
      page: searchParams.get("page") || "1",
      pageSize: searchParams.get("pageSize") || "20",
      sortBy: searchParams.get("sortBy") || undefined,
      sortOrder: searchParams.get("sortOrder") || "desc"
    })

    console.log(`[${requestId}] Query parameters: ${JSON.stringify(queryData)}`)

    const where: any = {}

    // Role-based filtering
    if (auth.payload.role !== 'ADMIN' && auth.payload.adminLevel !== 'SUPER_ADMIN') {
      if (auth.payload.role === 'HOTEL_MANAGER') {
        const userHotels = await prisma.hotel.findMany({
          where: { managerId: auth.payload.userId },
          select: { id: true }
        })
        where.hotelId = { in: userHotels.map(h => h.id) }
      } else {
        return NextResponse.json(
          failResponse(null, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS"), 
          { status: 403, headers: SECURITY_HEADERS }
        )
      }
    } else {
      if (queryData.hotelId) {
        where.hotelId = queryData.hotelId
      }
    }

    // Status filtering
    if (queryData.status) {
      where.status = queryData.status
    }

    // Operation type filtering
    if (queryData.operationType) {
      where.operationType = queryData.operationType
    }

    const operations = await prisma.operationalModule.findMany({
      where,
      include: {
        operationLogs: {
          take: 5,
          orderBy: { createdAt: 'desc' },
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
          }
        }
      },
      orderBy: { 
        [queryData.sortBy || 'updatedAt']: queryData.sortOrder 
      },
      skip: (queryData.page - 1) * queryData.pageSize,
      take: queryData.pageSize
    })

    const total = await prisma.operationalModule.count({ where })

    // Performance metrics
    const executionTime = Date.now() - startTime
    const performanceScore = executionTime > 2000 ? 'slow' : executionTime > 500 ? 'medium' : 'fast'
    
    // Statistics with enhanced aggregation
    const stats = await prisma.operationalModule.groupBy({
      by: ['status'],
      where,
      _count: { status: true }
    })

    // Mask sensitive data based on user role
    const context = auth.payload.role === 'ADMIN' ? 'admin' : 'user'
    const maskedOperations = operations.map(op => ({
      ...maskSensitiveData(op, context),
      _masked: true
    }))

    const response = {
      operations: maskedOperations,
      stats: stats.reduce((acc, stat) => {
        acc[stat.status] = stat._count.status
        return acc
      }, {} as Record<string, number>),
      total,
      page: queryData.page,
      pageSize: queryData.pageSize,
      hasMore: (queryData.page * queryData.pageSize) < total,
      performance: {
        executionTime,
        performanceScore,
        requestId
      }
    }

    console.log(`[${requestId}] Successfully retrieved ${operations.length} operations in ${executionTime}ms`)

    return NextResponse.json(
      successResponse(response, "Operations retrieved successfully"),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Performance-Score': performanceScore,
          'X-RateLimit-Remaining': rateLimitResult.remaining.toString()
        }
      }
    )
  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in GET operations:`, error)
    
    await logSecurityEvent('OPERATIONS_LIST_ERROR', auth.payload, req, {
      requestId,
      error: error.message,
      executionTime,
      stack: error.stack
    }, 'MEDIUM', requestId)

    return NextResponse.json(
      failResponse(null, error.message || "Failed to retrieve operations", "GET_OPERATIONS_ERROR"), 
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
    // Cleanup old threat detection entries
    threatDetector.cleanupOldEntries()
  }
}

// ===========================================
// POST - التحكم في العمليات (Advanced Security)
// ===========================================
export async function POST(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Operational Control POST request initiated`)

  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) {
    console.log(`[${requestId}] Authentication failed`)
    return NextResponse.json(failResponse(null, "Unauthorized", "AUTH_FAILED"), { 
      status: 401,
      headers: SECURITY_HEADERS 
    })
  }

  console.log(`[${requestId}] User authenticated: ${auth.payload.email} (${auth.payload.role})`)

  // Idempotency check
  const idempotencyKey = req.headers.get('Idempotency-Key') || req.headers.get('X-Idempotency-Key')
  let shouldProcess = true
  
  if (idempotencyKey) {
    const idempotencyResult = checkIdempotency(idempotencyKey)
    shouldProcess = idempotencyResult.shouldProcess
    
    if (!shouldProcess) {
      console.log(`[${requestId}] Idempotency check: returning cached response`)
      return NextResponse.json(idempotencyResult.existingResponse, {
        status: idempotencyResult.existingResponse.status,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Idempotent': 'true'
        }
      })
    }
  }

  // AI Threat Analysis
  const threatAnalysis = await threatDetector.analyzeRequest(req, auth.payload, requestId)
  console.log(`[${requestId}] Threat analysis: ${threatAnalysis.riskLevel} risk`)

  if (threatAnalysis.riskLevel === 'CRITICAL') {
    await logSecurityEvent('CRITICAL_THREAT_BLOCKED', auth.payload, req, {
      requestId,
      threats: threatAnalysis.threats,
      indicators: threatAnalysis.suspiciousIndicators
    }, 'CRITICAL', requestId)
    
    return NextResponse.json(
      failResponse(null, "Request blocked due to security concerns", "THREAT_BLOCKED"), 
      { 
        status: 403,
        headers: SECURITY_HEADERS 
      }
    )
  }

  // Log security event for high-risk requests
  if (threatAnalysis.riskLevel === 'HIGH') {
    await logSecurityEvent('HIGH_RISK_OPERATION', auth.payload, req, {
      requestId,
      threats: threatAnalysis.threats,
      confidence: threatAnalysis.confidence
    }, 'HIGH', requestId)
  }

  // Strict Rate Limiting for Control Operations
  const rateLimitKey = `operation_control:${auth.payload.userId}`
  const rateLimitResult = await advancedRateLimiter.checkLimit(rateLimitKey, 10, 10, 60000) // 10 operations per minute
  
  if (!rateLimitResult.success) {
    console.log(`[${requestId}] Rate limit exceeded for operation control`)
    return NextResponse.json(
      failResponse(null, "Rate limit exceeded. Too many control operations.", "RATE_LIMIT_EXCEEDED"), 
      { 
        status: 429,
        headers: {
          ...SECURITY_HEADERS,
          'X-RateLimit-Limit': '10',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': Math.ceil(rateLimitResult.resetTime / 1000).toString()
        }
      }
    )
  }

  try {
    const body = await req.json()
    const validated = OperationalControlSchema.parse(body)
    
    // Additional correlation ID check
    if (validated.correlationId && !/^[a-zA-Z0-9\-_]{16,64}$/.test(validated.correlationId)) {
      return NextResponse.json(
        failResponse(null, "Invalid correlation ID format", "INVALID_CORRELATION_ID"), 
        { status: 400, headers: SECURITY_HEADERS }
      )
    }

    console.log(`[${requestId}] Validated operation control request: ${validated.action} on ${validated.moduleName}`)

    // Permission validation
    if (auth.payload.role === 'HOTEL_MANAGER') {
      // Hotel manager can only control their hotel's modules
      const hotelId = validated.moduleName.startsWith('hotel_') ? validated.moduleName.replace('hotel_', '') : null
      
      const hotel = await prisma.hotel.findFirst({
        where: { 
          id: hotelId,
          managerId: auth.payload.userId 
        }
      })
      
      if (!hotel) {
        return NextResponse.json(
          failResponse(null, "You can only control operations in your hotel", "INSUFFICIENT_HOTEL_PERMISSIONS"), 
          { status: 403, headers: SECURITY_HEADERS }
        )
      }
    }

    // Find or create operational module
    let operationalModule = await prisma.operationalModule.findFirst({
      where: { 
        moduleName: validated.moduleName,
        ...(auth.payload.role === 'HOTEL_MANAGER' && {
          hotelId: await prisma.hotel.findFirst({
            where: { managerId: auth.payload.userId },
            select: { id: true }
          }).then(h => h?.id)
        })
      }
    })

    const currentStatus = operationalModule?.status || 'ACTIVE'
    let newStatus = currentStatus

    // Determine new status based on action
    const statusMap = {
      'LOCK': 'LOCKED',
      'UNLOCK': 'ACTIVE',
      'HIDE': 'HIDDEN',
      'SHOW': 'ACTIVE',
      'SUSPEND': 'SUSPENDED',
      'ACTIVATE': 'ACTIVE',
      'MAINTENANCE_MODE': 'MAINTENANCE',
      'EMERGENCY_MODE': 'EMERGENCY'
    } as const

    newStatus = statusMap[validated.action]

    // Create or update the module with enhanced security
    if (!operationalModule) {
      operationalModule = await prisma.operationalModule.create({
        data: {
          moduleName: validated.moduleName,
          operationType: validated.moduleName.includes('BOOKING') ? 'BOOKING_SYSTEM' :
                        validated.moduleName.includes('PAYMENT') ? 'PAYMENT_SYSTEM' :
                        validated.moduleName.includes('ROOM') ? 'ROOM_MANAGEMENT' :
                        validated.moduleName.includes('STAFF') ? 'STAFF_MANAGEMENT' :
                        validated.moduleName.includes('FINANCIAL') ? 'FINANCIAL_SYSTEM' :
                        'BOOKING_SYSTEM',
          status: newStatus,
          controlLevel: validated.controlLevel,
          lockedBy: auth.payload.userId,
          lockedAt: new Date(),
          unlockAt: validated.unlockAt ? new Date(validated.unlockAt) : null,
          lastAction: validated.action as any,
          lockMessage: validated.message,
          adminOnly: validated.adminOnly,
          allowOverride: validated.allowOverride,
          requiredRole: auth.payload.role as any,
          restrictedRoles: validated.restrictedRoles as any || [],
          metadata: {
            requestId,
            threatAnalysis: threatAnalysis.threats,
            userIp: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown',
            correlationId: validated.correlationId
          },
          ...(auth.payload.role === 'HOTEL_MANAGER' && {
            hotelId: await prisma.hotel.findFirst({
              where: { managerId: auth.payload.userId },
              select: { id: true }
            }).then(h => h?.id)
          })
        }
      })
    } else {
      operationalModule = await prisma.operationalModule.update({
        where: { id: operationalModule.id },
        data: {
          status: newStatus,
          controlLevel: validated.controlLevel,
          lockedBy: auth.payload.userId,
          lockedAt: new Date(),
          unlockAt: validated.unlockAt ? new Date(validated.unlockAt) : null,
          lastAction: validated.action as any,
          lockMessage: validated.message,
          adminOnly: validated.adminOnly,
          allowOverride: validated.allowOverride,
          restrictedRoles: validated.restrictedRoles as any || [],
          updatedAt: new Date(),
          metadata: {
            ...operationalModule.metadata,
            requestId,
            threatAnalysis: threatAnalysis.threats,
            userIp: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown'
          }
        }
      })
    }

    // Log the operation
    await prisma.operationLog.create({
      data: {
        moduleId: operationalModule.id,
        action: validated.action as any,
        performedBy: auth.payload.userId,
        reason: validated.reason,
        previousStatus: currentStatus as any,
        newStatus: newStatus as any,
        message: validated.message,
        ipAddress: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown',
        userAgent: req.headers.get('user-agent') || 'unknown',
        metadata: {
          controlLevel: validated.controlLevel,
          adminOnly: validated.adminOnly,
          allowOverride: validated.allowOverride,
          requestId,
          threatLevel: threatAnalysis.riskLevel,
          correlationId: validated.correlationId
        }
      }
    })

    // Create alerts for critical operations
    if (newStatus === 'EMERGENCY' || newStatus === 'MAINTENANCE') {
      await prisma.operationalAlert.create({
        data: {
          hotelId: operationalModule.hotelId,
          alertType: newStatus === 'EMERGENCY' ? 'error' : 'warning',
          title: `${validated.action} - ${validated.moduleName}`,
          message: validated.message || `Operation ${validated.action} executed successfully`,
          priority: newStatus === 'EMERGENCY' ? 'critical' : 'high',
          targetRoles: ['ADMIN', 'HOTEL_MANAGER'],
          metadata: {
            requestId,
            operationId: operationalModule.id,
            threatLevel: threatAnalysis.riskLevel
          }
        }
      })
    }

    // Store idempotency result
    if (idempotencyKey && shouldProcess) {
      storeIdempotencyResult(idempotencyKey, 200, {
        ...successResponse({
          module: operationalModule,
          action: validated.action,
          status: newStatus,
          timestamp: new Date().toISOString(),
          requestId
        }, `Operation ${validated.action} executed successfully`)
      })
    }

    const executionTime = Date.now() - startTime

    console.log(`[${requestId}] Operation control completed successfully in ${executionTime}ms`)

    // Log final security event
    await logSecurityEvent('OPERATION_CONTROL_SUCCESS', auth.payload, req, {
      requestId,
      operation: validated.action,
      module: validated.moduleName,
      previousStatus: currentStatus,
      newStatus: newStatus,
      threatLevel: threatAnalysis.riskLevel,
      executionTime
    }, threatAnalysis.riskLevel === 'CRITICAL' ? 'HIGH' : 'LOW', requestId)

    return NextResponse.json(
      successResponse({
        module: operationalModule,
        action: validated.action,
        status: newStatus,
        timestamp: new Date().toISOString(),
        requestId,
        performance: {
          executionTime,
          threatLevel: threatAnalysis.riskLevel
        }
      }, `Operation ${validated.action} executed successfully`),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Operation-Status': newStatus,
          'X-Threat-Level': threatAnalysis.riskLevel
        }
      }
    )
  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in POST operation control:`, error)
    
    await logSecurityEvent('OPERATION_CONTROL_ERROR', auth.payload, req, {
      requestId,
      error: error.message,
      executionTime,
      stack: error.stack
    }, 'MEDIUM', requestId)

    const errorResponse = NextResponse.json(
      failResponse(null, error.message || "Failed to execute operation", "CONTROL_OPERATION_ERROR"), 
      { 
        status: 500,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString()
        }
      }
    )

    // Store error in idempotency store
    if (idempotencyKey && shouldProcess) {
      storeIdempotencyResult(idempotencyKey, 500, errorResponse)
    }

    return errorResponse
  } finally {
    threatDetector.cleanupOldEntries()
  }
}