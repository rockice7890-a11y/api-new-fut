import type { NextRequest } from "next/server"
import { autoCheckoutService } from "@/lib/services/auto-checkout.service"
import { authenticate } from "@/lib/middleware"
import { prisma } from "@/lib/prisma"
import { apiResponse } from "@/lib/api-response"
import { createHash, randomBytes, timingSafeEqual } from "crypto"
import jwt from "jsonwebtoken"
import { z } from "zod"

// ===========================================
// ADVANCED AUTO CHECKOUT PENDING APIs
// المغادرة التلقائية المعلقة - نظام أمان شامل
// ===========================================

export const dynamic = 'force-dynamic'

// Enhanced Security Headers
const SECURITY_HEADERS = {
  'X-DNS-Prefetch-Control': 'off',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Auto-Checkout-Access': 'restricted'
}

// Request Correlation & Tracing
let requestCounter = 0
const generateRequestId = () => {
  requestCounter++
  const timestamp = Date.now()
  const random = randomBytes(8).toString('hex')
  return `autocheckout-${timestamp}-${requestCounter}-${random}`
}

// Advanced Auto-Checkout Threat Detection
interface CheckoutThreatAnalysis {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  threats: string[]
  confidence: number
  recommendedAction: string
  suspiciousIndicators: string[]
  operationRiskScore: number
}

class CheckoutThreatDetector {
  private checkoutThreatPatterns = [
    { pattern: /admin|root|system|privilege|elevate/i, weight: 40, type: 'PRIVILEGE_ESCALATION' },
    { pattern: /checkout|checkin|guest|room|booking/i, weight: 30, type: 'GUEST_DATA_ACCESS' },
    { pattern: /union\s+select|drop\s+table|delete\s+from|update\s+set/i, weight: 50, type: 'SQL_INJECTION' },
    { pattern: /<script|javascript:|vbscript:|onload=|onerror=/i, weight: 35, type: 'XSS_ATTEMPT' },
    { pattern: /\.\.\/|\.\.\\/|%2e%2e%2f/i, weight: 30, type: 'PATH_TRAVERSAL' },
    { pattern: /eval\(|exec\(|system\(|shell_exec/i, weight: 45, type: 'CODE_INJECTION' },
    { pattern: /confirm|process|approve|execute/i, weight: 25, type: 'OPERATION_EXECUTION' }
  ]

  private operationPatterns = new Map<string, { count: number; lastRequest: Date; operationTypes: Set<string>; suspiciousActivity: number; confirmationAttempts: number }>()

  async analyzeCheckoutRequest(request: NextRequest, user: any, requestId: string, operation: string): Promise<CheckoutThreatAnalysis> {
    const userAgent = request.headers.get('user-agent') || ''
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const referer = request.headers.get('referer') || ''
    
    let riskScore = 0
    let operationRiskScore = 0
    const threats: string[] = []
    const suspiciousIndicators: string[] = []
    
    // Analyze operation-specific patterns
    const operationKey = `${user.id}-${ip}`
    const now = new Date()
    const operationPattern = this.operationPatterns.get(operationKey) || { 
      count: 0, 
      lastRequest: now, 
      operationTypes: new Set(),
      suspiciousActivity: 0,
      confirmationAttempts: 0
    }
    
    operationPattern.count++
    operationPattern.operationTypes.add(operation)
    operationPattern.lastRequest = now

    // Detect operation enumeration
    if (operationPattern.operationTypes.size > 5) {
      riskScore += 25
      operationRiskScore += 20
      threats.push('OPERATION_ENUMERATION')
      suspiciousIndicators.push('Accessing multiple auto-checkout operations')
    }

    // Time-based analysis for checkout operations
    const hour = now.getHours()
    const dayOfWeek = now.getDay()
    
    // Outside normal hotel operating hours
    if (hour < 6 || hour > 23) {
      riskScore += 15
      operationRiskScore += 10
      suspiciousIndicators.push('Auto-checkout access outside normal hours')
    }

    // Weekend operations might be suspicious
    if ((dayOfWeek === 0 || dayOfWeek === 6) && hour > 2 && hour < 6) {
      riskScore += 20
      operationRiskScore += 15
      threats.push('WEEKEND_SUSPICIOUS_OPERATION')
      suspiciousIndicators.push('Weekend early morning auto-checkout activity')
    }

    // User agent analysis
    if (!userAgent || userAgent.length < 10) {
      riskScore += 15
      threats.push('SUSPICIOUS_USER_AGENT')
      suspiciousIndicators.push('Missing or invalid user agent for checkout operations')
    }

    // Automated access detection
    const botPatterns = /bot|crawler|spider|scraper|curl|wget|python|java|go-http|libwww/i
    if (botPatterns.test(userAgent)) {
      riskScore += 40
      operationRiskScore += 30
      threats.push('AUTOMATED_CHECKOUT_ACCESS')
      suspiciousIndicators.push('Automated bot accessing auto-checkout system')
    }

    // Referer analysis for checkout operations
    if (referer && !referer.includes(new URL(request.url).origin)) {
      riskScore += 10
      threats.push('EXTERNAL_CHECKOUT_ACCESS')
      suspiciousIndicators.push('External referer for checkout operations')
    }

    // Role-based risk assessment
    if (user.role !== 'HOTEL_MANAGER' && user.role !== 'ADMIN' && user.role !== 'STAFF') {
      riskScore += 50
      operationRiskScore += 40
      threats.push('UNAUTHORIZED_ROLE_ACCESS')
      suspiciousIndicators.push('Insufficient role for checkout operations')
    }

    // Operation-specific risk analysis
    if (operation === 'confirm' || operation === 'PUT') {
      operationPattern.confirmationAttempts++
      
      // Multiple confirmation attempts
      if (operationPattern.confirmationAttempts > 10) {
        riskScore += 30
        operationRiskScore += 25
        threats.push('EXCESSIVE_CONFIRMATIONS')
        suspiciousIndicators.push('Multiple checkout confirmation attempts')
      }
    }

    // Analyze URL parameters for checkout-specific threats
    const url = new URL(request.url)
    for (const [key, value] of url.searchParams.entries()) {
      for (const threatPattern of this.checkoutThreatPatterns) {
        if (threatPattern.pattern.test(value)) {
          riskScore += threatPattern.weight
          if (threatPattern.type.includes('GUEST') || threatPattern.type.includes('OPERATION')) {
            operationRiskScore += threatPattern.weight * 0.8
          }
          threats.push(threatPattern.type)
          suspiciousIndicators.push(`Checkout threat pattern detected in parameter: ${key}`)
        }
      }
    }

    // Check for sensitive checkout parameters
    const sensitiveParams = ['checkoutId', 'bookingId', 'roomNumber', 'guestId', 'confirmationCode']
    const hasSensitiveParams = sensitiveParams.some(param => 
      Array.from(url.searchParams.keys()).some(key => key.toLowerCase().includes(param))
    )
    
    if (hasSensitiveParams) {
      riskScore += 20
      operationRiskScore += 15
      threats.push('SENSITIVE_CHECKOUT_PARAMETERS')
      suspiciousIndicators.push('Request contains sensitive checkout parameters')
    }

    // Update operation pattern
    this.operationPatterns.set(operationKey, operationPattern)

    // Determine risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    let recommendedAction: string

    // Use the higher of general risk or operation risk
    const finalRiskScore = Math.max(riskScore, operationRiskScore)
    
    if (finalRiskScore >= 65) {
      riskLevel = 'CRITICAL'
      recommendedAction = 'BLOCK_REQUEST'
    } else if (finalRiskScore >= 45) {
      riskLevel = 'HIGH'
      recommendedAction = 'ENHANCED_MONITORING'
    } else if (finalRiskScore >= 20) {
      riskLevel = 'MEDIUM'
      recommendedAction = 'LOG_AND_CONTINUE'
    } else {
      riskLevel = 'LOW'
      recommendedAction = 'ALLOW_REQUEST'
    }

    return {
      riskLevel,
      threats,
      confidence: Math.min(finalRiskScore, 100),
      recommendedAction,
      suspiciousIndicators,
      operationRiskScore: finalRiskScore
    }
  }

  cleanupOldEntries() {
    const now = new Date()
    const timeout = 10 * 60 * 1000 // 10 minutes
    
    for (const [key, pattern] of this.operationPatterns.entries()) {
      if (now.getTime() - pattern.lastRequest.getTime() > timeout) {
        this.operationPatterns.delete(key)
      }
    }
  }
}

const checkoutThreatDetector = new CheckoutThreatDetector()

// Enhanced Request Validation Schemas
const PendingQuerySchema = z.object({
  hotelId: z.string().uuid().optional(),
  status: z.enum(['pending', 'confirmed', 'processing', 'completed']).optional(),
  roomNumber: z.string().max(10).optional(),
  page: z.string().transform(Number).min(1).max(1000).default('1'),
  pageSize: z.string().transform(Number).min(1).max(100).default('20'),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
})

const ConfirmCheckoutSchema = z.object({
  pendingCheckoutId: z.string().uuid(),
  notes: z.string().max(1000).optional(),
  confirmationCode: z.string().optional(),
  correlationId: z.string().optional(),
  idempotencyKey: z.string().optional()
})

// Guest Data Masking for Checkout Operations
function maskCheckoutData(data: any, context: string, userRole: string, userId: string): any {
  const maskValue = (value: string, visibleChars: number = 2): string => {
    if (!value || typeof value !== 'string') return value
    if (value.length <= visibleChars * 2) return '*'.repeat(value.length)
    return value.substring(0, visibleChars) + '*'.repeat(value.length - visibleChars * 2) + value.substring(value.length - visibleChars)
  }

  const maskEmail = (email: string): string => {
    if (!email || typeof email !== 'string') return email
    const [local, domain] = email.split('@')
    if (!local || !domain) return email
    return maskValue(local, 1) + '@' + domain
  }

  const applyCheckoutMasking = (obj: any): any => {
    if (!obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(applyCheckoutMasking)

    const masked = { ...obj }
    
    // Always mask guest personal information
    const guestFields = ['guestName', 'guestEmail', 'guestPhone', 'guestAddress']
    for (const field of guestFields) {
      if (masked[field]) {
        if (field === 'guestEmail') {
          masked[field] = maskEmail(masked[field])
        } else {
          masked[field] = maskValue(masked[field], 2)
        }
      }
    }

    // Mask booking details
    if (masked.bookingDetails) {
      masked.bookingDetails = {
        ...masked.bookingDetails,
        bookingReference: maskValue(masked.bookingDetails.bookingReference || '', 4),
        roomNumber: masked.bookingDetails.roomNumber ? maskValue(masked.bookingDetails.roomNumber, 1) : undefined
      }
    }

    // Mask payment information
    if (masked.paymentInfo) {
      const payment = masked.paymentInfo
      masked.paymentInfo = {
        amount: payment.amount,
        currency: payment.currency,
        // Mask sensitive payment details
        transactionId: payment.transactionId ? maskValue(payment.transactionId, 4) : undefined,
        paymentMethod: payment.paymentMethod ? maskValue(payment.paymentMethod, 3) : undefined
      }
    }

    // Role-based masking for staff vs manager
    if (userRole === 'STAFF') {
      // Staff sees limited information
      if (masked.guestHistory) {
        masked.guestHistory = maskValue(masked.guestHistory, 50) + '...'
      }
    }

    return masked
  }

  return applyCheckoutMasking(data)
}

// Comprehensive Auto-Checkout Audit Logging
async function logCheckoutSecurityEvent(
  eventType: string,
  user: any,
  request: NextRequest,
  details: any,
  riskLevel: string,
  requestId: string,
  hotelId?: string
) {
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'
  const referer = request.headers.get('referer') || 'unknown'
  
  try {
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: `AUTO_CHECKOUT_${eventType}`,
        resource: 'AutoCheckout',
        resourceId: details.resourceId || null,
        ipAddress: ip,
        userAgent,
        method: request.method,
        newValues: JSON.stringify({
          ...details,
          hotelId,
          checkoutOperation: true,
          guestDataAccessed: true
        }),
        metadata: {
          requestId,
          riskLevel,
          timestamp: new Date().toISOString(),
          referer,
          userRole: user.role,
          adminLevel: user.adminLevel,
          operationType: details.operationType || 'pending_checkout'
        }
      }
    })

    // Log to security events table with checkout context
    await prisma.securityEvent.create({
      data: {
        eventType: `AUTO_CHECKOUT_${eventType}`,
        severity: riskLevel === 'CRITICAL' ? 'high' : riskLevel === 'HIGH' ? 'medium' : 'low',
        description: `Auto-checkout system access: ${eventType}`,
        ipAddress: ip,
        userId: user.id,
        metadata: {
          requestId,
          userRole: user.role,
          hotelId,
          operationType: details.operationType || 'pending_checkout',
          details
        },
        resolved: riskLevel !== 'CRITICAL'
      }
    })
  } catch (error) {
    console.error('Failed to log checkout security event:', error)
  }
}

// Advanced Rate Limiting for Auto-Checkout Operations
class CheckoutRateLimiter {
  private buckets = new Map<string, { tokens: number; lastRefill: number; maxTokens: number; refillRate: number; operations: Map<string, number> }>()

  constructor() {
    setInterval(() => this.cleanup(), 5 * 60 * 1000)
  }

  async checkLimit(key: string, operation: string, maxTokens: number, refillRate: number, windowMs: number): Promise<{ success: boolean; remaining: number; resetTime: number; operationLimit?: boolean }> {
    const now = Date.now()
    const bucket = this.buckets.get(key) || { 
      tokens: maxTokens, 
      lastRefill: now, 
      maxTokens, 
      refillRate,
      operations: new Map()
    }

    // Calculate tokens to add based on time passed
    const timePassed = now - bucket.lastRefill
    const tokensToAdd = (timePassed * bucket.refillRate) / windowMs
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd)
    bucket.lastRefill = now

    // Operation-specific limits
    const operationCounts = bucket.operations.get(operation) || 0
    const operationLimits = {
      'GET': 40,    // Get pending checkouts
      'PUT': 20,    // Confirm checkout
      'POST': 15    // Create new operations
    }
    
    const operationLimit = operationLimits[operation as keyof typeof operationLimits] || 30
    
    if (operationCounts >= operationLimit) {
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + windowMs,
        operationLimit: true
      }
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1
      bucket.operations.set(operation, operationCounts + 1)
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
      operationLimit: false
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

const checkoutRateLimiter = new CheckoutRateLimiter()

// Idempotency Management for Checkout Operations
const checkoutIdempotencyStore = new Map<string, { status: number; response: any; timestamp: number; operation: string }>()

function checkCheckoutIdempotency(key: string, operation: string): { shouldProcess: boolean; existingResponse?: any } {
  const now = Date.now()
  const timeout = 24 * 60 * 60 * 1000 // 24 hours
  
  const existing = checkoutIdempotencyStore.get(key)
  if (existing && existing.operation === operation && (now - existing.timestamp) < timeout) {
    return { shouldProcess: false, existingResponse: existing.response }
  }
  
  if (existing) {
    checkoutIdempotencyStore.delete(key)
  }
  
  return { shouldProcess: true }
}

function storeCheckoutIdempotencyResult(key: string, operation: string, status: number, response: any) {
  checkoutIdempotencyStore.set(key, {
    status,
    response,
    timestamp: Date.now(),
    operation
  })
}

// ===========================================
// GET - جلب المهام المعلقة (Advanced Security)
// ===========================================
export async function GET(request: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Auto-checkout pending GET request initiated`)

  try {
    const user = await authenticate(request)
    if (!user) {
      console.log(`[${requestId}] Authentication failed`)
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    console.log(`[${requestId}] User authenticated: ${user.email} (${user.role})`)

    // AI Checkout Threat Analysis
    const threatAnalysis = await checkoutThreatDetector.analyzeCheckoutRequest(request, user, requestId, 'GET')
    console.log(`[${requestId}] Checkout threat analysis: ${threatAnalysis.riskLevel} risk`)

    // Log security event
    await logCheckoutSecurityEvent('PENDING_ACCESS', user, request, {
      requestId,
      operationType: 'GET',
      queryParams: Object.fromEntries(request.nextUrl.searchParams.entries())
    }, threatAnalysis.riskLevel, requestId)

    if (threatAnalysis.riskLevel === 'CRITICAL') {
      await logCheckoutSecurityEvent('CRITICAL_CHECKOUT_THREAT_BLOCKED', user, request, {
        requestId,
        threats: threatAnalysis.threats,
        indicators: threatAnalysis.suspiciousIndicators,
        operationScore: threatAnalysis.operationRiskScore
      }, 'CRITICAL', requestId)
      
      return apiResponse.error("Auto-checkout access blocked due to security concerns")
    }

    // Advanced Rate Limiting
    const rateLimitKey = `checkout_pending:${user.id}`
    const rateLimitResult = await checkoutRateLimiter.checkLimit(rateLimitKey, 'GET', 40, 40, 60000) // 40 requests per minute
    
    if (!rateLimitResult.success) {
      console.log(`[${requestId}] Rate limit exceeded for pending checkouts`)
      return apiResponse.error(
        rateLimitResult.operationLimit 
          ? "Pending checkout access limit exceeded. Please try again later." 
          : "Rate limit exceeded. Too many pending checkout requests."
      )
    }

    // Enhanced query validation
    const searchParams = request.nextUrl.searchParams
    const queryData = PendingQuerySchema.parse({
      hotelId: searchParams.get("hotelId") || undefined,
      status: searchParams.get("status") || undefined,
      roomNumber: searchParams.get("roomNumber") || undefined,
      page: searchParams.get("page") || "1",
      pageSize: searchParams.get("pageSize") || "20",
      sortBy: searchParams.get("sortBy") || undefined,
      sortOrder: searchParams.get("sortOrder") || "desc"
    })

    console.log(`[${requestId}] Validated query parameters: ${JSON.stringify(queryData)}`)

    // Get hotel managed by user
    const hotel = await prisma.hotel.findFirst({
      where: { managerId: user.id },
    })

    if (!hotel) {
      console.log(`[${requestId}] Hotel not found for manager`)
      return apiResponse.notFound("الفندق غير موجود")
    }

    // Get pending checkouts with enhanced filtering
    const pendingCheckouts = await autoCheckoutService.getPendingCheckouts(hotel.id)

    // Apply guest data masking
    const maskedCheckouts = pendingCheckouts.map((checkout: any) =>
      maskCheckoutData(checkout, 'checkout', user.role, user.id)
    )

    // Performance monitoring
    const executionTime = Date.now() - startTime
    const performanceScore = executionTime > 2000 ? 'slow' : executionTime > 500 ? 'medium' : 'fast'
    
    const response = {
      pending: maskedCheckouts,
      performance: {
        executionTime,
        performanceScore,
        requestId,
        threatLevel: threatAnalysis.riskLevel,
        operationRiskScore: threatAnalysis.operationRiskScore
      },
      security: {
        dataMasked: true,
        userRole: user.role,
        accessLevel: user.role === 'ADMIN' ? 'COMPREHENSIVE' : user.role === 'HOTEL_MANAGER' ? 'MANAGEMENT' : 'BASIC',
        checkoutOperation: true
      }
    }

    console.log(`[${requestId}] Pending checkouts retrieved successfully in ${executionTime}ms`)

    // Log successful access for high-risk requests
    if (threatAnalysis.riskLevel === 'HIGH') {
      await logCheckoutSecurityEvent('HIGH_RISK_CHECKOUT_SUCCESS', user, request, {
        requestId,
        hotelId: hotel.id,
        checkoutsAccessed: maskedCheckouts.length,
        threatLevel: threatAnalysis.riskLevel,
        executionTime
      }, 'MEDIUM', requestId, hotel.id)
    }

    return NextResponse.json(
      apiResponse.success(response, "تم استرجاع المهام المعلقة بنجاح"),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Threat-Level': threatAnalysis.riskLevel,
          'X-Operation-Risk-Score': threatAnalysis.operationRiskScore.toString(),
          'X-Performance-Score': performanceScore,
          'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
          'X-Data-Masked': 'true',
          'X-Checkout-Access-Level': user.role === 'ADMIN' ? 'COMPREHENSIVE' : user.role === 'HOTEL_MANAGER' ? 'MANAGEMENT' : 'BASIC'
        }
      }
    )

  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in GET pending checkouts:`, error)
    
    // Log error with enhanced context
    try {
      const user = await authenticate(request)
      if (user) {
        await logCheckoutSecurityEvent('PENDING_ERROR', user, request, {
          requestId,
          error: error.message,
          executionTime,
          stack: error.stack
        }, 'MEDIUM', requestId)
      }
    } catch (authError) {
      console.error(`[${requestId}] Failed to authenticate user for error logging:`, authError)
    }

    return NextResponse.json(
      apiResponse.error(error.message || "خطأ في استرجاع المهام المعلقة"),
      {
        status: 500,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Error-Type': 'INTERNAL_SERVER_ERROR'
        }
      }
    )
  } finally {
    checkoutThreatDetector.cleanupOldEntries()
  }
}

// ===========================================
// PUT - تأكيد المغادرة (Advanced Security)
// ===========================================
export async function PUT(request: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Auto-checkout confirmation PUT request initiated`)

  try {
    const user = await authenticate(request)
    if (!user) {
      console.log(`[${requestId}] Authentication failed`)
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    console.log(`[${requestId}] User authenticated: ${user.email} (${user.role})`)

    // Idempotency check
    const idempotencyKey = request.headers.get('Idempotency-Key') || request.headers.get('X-Idempotency-Key')
    let shouldProcess = true
    
    if (idempotencyKey) {
      const idempotencyResult = checkCheckoutIdempotency(idempotencyKey, 'PUT')
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

    // AI Checkout Threat Analysis
    const threatAnalysis = await checkoutThreatDetector.analyzeCheckoutRequest(request, user, requestId, 'PUT')
    console.log(`[${requestId}] Checkout threat analysis: ${threatAnalysis.riskLevel} risk`)

    if (threatAnalysis.riskLevel === 'CRITICAL') {
      await logCheckoutSecurityEvent('CRITICAL_CHECKOUT_CONFIRMATION_BLOCKED', user, request, {
        requestId,
        threats: threatAnalysis.threats,
        indicators: threatAnalysis.suspiciousIndicators,
        operationScore: threatAnalysis.operationRiskScore
      }, 'CRITICAL', requestId)
      
      return apiResponse.error("Checkout confirmation blocked due to security concerns")
    }

    // Log security event for high-risk confirmations
    if (threatAnalysis.riskLevel === 'HIGH') {
      await logCheckoutSecurityEvent('HIGH_RISK_CONFIRMATION', user, request, {
        requestId,
        threats: threatAnalysis.threats,
        confidence: threatAnalysis.confidence
      }, 'HIGH', requestId)
    }

    // Advanced Rate Limiting for Confirmations
    const rateLimitKey = `checkout_confirm:${user.id}`
    const rateLimitResult = await checkoutRateLimiter.checkLimit(rateLimitKey, 'PUT', 20, 20, 60000) // 20 confirmations per minute
    
    if (!rateLimitResult.success) {
      console.log(`[${requestId}] Rate limit exceeded for checkout confirmations`)
      return apiResponse.error(
        rateLimitResult.operationLimit 
          ? "Checkout confirmation limit exceeded. Please try again later." 
          : "Rate limit exceeded. Too many checkout confirmations."
      )
    }

    const body = await request.json()
    const validated = ConfirmCheckoutSchema.parse(body)

    console.log(`[${requestId}] Validated confirmation request: ${validated.pendingCheckoutId}`)

    const { pendingCheckoutId, notes, confirmationCode } = validated

    // Additional security validation for confirmation
    if (confirmationCode) {
      // Validate confirmation code format
      if (!/^[A-Z0-9]{6,12}$/.test(confirmationCode)) {
        return apiResponse.badRequest("رمز تأكيد غير صحيح")
      }
    }

    // Confirm checkout with enhanced security
    const confirmed = await autoCheckoutService.confirmCheckout(pendingCheckoutId, user.id, notes)

    const executionTime = Date.now() - startTime

    console.log(`[${requestId}] Checkout confirmation completed successfully in ${executionTime}ms`)

    // Log successful confirmation
    await logCheckoutSecurityEvent('CHECKOUT_CONFIRMED', user, request, {
      requestId,
      pendingCheckoutId,
      confirmationCode: confirmationCode ? 'PROVIDED' : 'NOT_PROVIDED',
      notes: notes ? 'PROVIDED' : 'NOT_PROVIDED',
      threatLevel: threatAnalysis.riskLevel,
      executionTime
    }, threatAnalysis.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW', requestId)

    // Store idempotency result
    if (idempotencyKey && shouldProcess) {
      storeCheckoutIdempotencyResult(idempotencyKey, 'PUT', 200, {
        ...apiResponse.success({
          confirmed,
          performance: {
            executionTime,
            requestId,
            threatLevel: threatAnalysis.riskLevel
          }
        }, "تم تأكيد المغادرة بنجاح")
      })
    }

    return NextResponse.json(
      apiResponse.success({
        confirmed,
        performance: {
          executionTime,
          requestId,
          threatLevel: threatAnalysis.riskLevel,
          operationRiskScore: threatAnalysis.operationRiskScore
        }
      }, "تم تأكيد المغادرة بنجاح"),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Threat-Level': threatAnalysis.riskLevel,
          'X-Operation-Risk-Score': threatAnalysis.operationRiskScore.toString(),
          'X-Confirmation-ID': confirmed.id || 'N/A'
        }
      }
    )

  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in PUT checkout confirmation:`, error)
    
    // Log error with enhanced context
    try {
      const user = await authenticate(request)
      if (user) {
        await logCheckoutSecurityEvent('CONFIRMATION_ERROR', user, request, {
          requestId,
          error: error.message,
          executionTime,
          stack: error.stack
        }, 'MEDIUM', requestId)
      }
    } catch (authError) {
      console.error(`[${requestId}] Failed to authenticate user for error logging:`, authError)
    }

    const errorResponse = apiResponse.error(error.message || "خطأ في تأكيد المغادرة")

    // Store error in idempotency store
    if (idempotencyKey && shouldProcess) {
      storeCheckoutIdempotencyResult(idempotencyKey, 'PUT', 500, errorResponse)
    }

    return NextResponse.json(
      errorResponse,
      {
        status: 500,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Error-Type': 'INTERNAL_SERVER_ERROR'
        }
      }
    )
  } finally {
    checkoutThreatDetector.cleanupOldEntries()
  }
}