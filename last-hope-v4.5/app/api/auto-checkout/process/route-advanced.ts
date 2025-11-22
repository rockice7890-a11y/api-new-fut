import type { NextRequest } from "next/server"
import { autoCheckoutService } from "@/lib/services/auto-checkout.service"
import { authenticate } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { createHash, randomBytes, timingSafeEqual } from "crypto"
import jwt from "jsonwebtoken"
import { z } from "zod"

// ===========================================
// ADVANCED AUTO CHECKOUT PROCESS APIs
// معالجة المغادرة التلقائية - نظام أمان شامل
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
  'X-Auto-Checkout-Process': 'restricted'
}

// Request Correlation & Tracing
let requestCounter = 0
const generateRequestId = () => {
  requestCounter++
  const timestamp = Date.now()
  const random = randomBytes(8).toString('hex')
  return `process-${timestamp}-${requestCounter}-${random}`
}

// Advanced Processing Threat Detection
interface ProcessThreatAnalysis {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  threats: string[]
  confidence: number
  recommendedAction: string
  suspiciousIndicators: string[]
  processingRiskScore: number
}

class ProcessThreatDetector {
  private processThreatPatterns = [
    { pattern: /admin|root|system|privilege|elevate/i, weight: 50, type: 'PRIVILEGE_ESCALATION' },
    { pattern: /process|execute|run|start|trigger/i, weight: 40, type: 'PROCESS_EXECUTION' },
    { pattern: /union\s+select|drop\s+table|delete\s+from|update\s+set/i, weight: 60, type: 'SQL_INJECTION' },
    { pattern: /<script|javascript:|vbscript:|onload=|onerror=/i, weight: 45, type: 'XSS_ATTEMPT' },
    { pattern: /\.\.\/|\.\.\\/|%2e%2e%2f/i, weight: 40, type: 'PATH_TRAVERSAL' },
    { pattern: /eval\(|exec\(|system\(|shell_exec|process\.|exec\(/i, weight: 70, type: 'CODE_INJECTION' },
    { pattern: /batch|bulk|multiple|concurrent/i, weight: 30, type: 'BATCH_PROCESSING' },
    { pattern: /automation|script|robot|bot/i, weight: 35, type: 'AUTOMATED_PROCESSING' }
  ]

  private processingPatterns = new Map<string, { count: number; lastRequest: Date; processTypes: Set<string>; suspiciousActivity: number; batchOperations: number; concurrentRequests: number }>()

  async analyzeProcessRequest(request: NextRequest, user: any, requestId: string): Promise<ProcessThreatAnalysis> {
    const userAgent = request.headers.get('user-agent') || ''
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const referer = request.headers.get('referer') || ''
    
    let riskScore = 0
    let processingRiskScore = 0
    const threats: string[] = []
    const suspiciousIndicators: string[] = []
    
    // Analyze processing-specific patterns
    const processKey = `${user.id}-${ip}`
    const now = new Date()
    const processingPattern = this.processingPatterns.get(processKey) || { 
      count: 0, 
      lastRequest: now, 
      processTypes: new Set(),
      suspiciousActivity: 0,
      batchOperations: 0,
      concurrentRequests: 0
    }
    
    processingPattern.count++
    processingPattern.processTypes.add('auto_checkout_process')
    processingPattern.lastRequest = now

    // Detect concurrent processing requests
    const recentRequests = Array.from(this.processingPatterns.values())
      .filter(p => now.getTime() - p.lastRequest.getTime() < 5000) // Last 5 seconds
    
    if (recentRequests.length > 3) {
      processingPattern.concurrentRequests++
      riskScore += 25
      processingRiskScore += 20
      threats.push('CONCURRENT_PROCESSING_REQUESTS')
      suspiciousIndicators.push('Multiple concurrent processing requests detected')
    }

    // Detect batch processing attempts
    if (processingPattern.batchOperations > 5) {
      riskScore += 30
      processingRiskScore += 25
      threats.push('EXCESSIVE_BATCH_OPERATIONS')
      suspiciousIndicators.push('Multiple batch checkout processing operations')
    }

    // Time-based analysis for processing operations
    const hour = now.getHours()
    const dayOfWeek = now.getDay()
    
    // Outside normal hotel operating hours - higher risk for processing
    if (hour < 5 || hour > 22) {
      riskScore += 20
      processingRiskScore += 15
      suspiciousIndicators.push('Auto-checkout processing outside normal hours')
    }

    // Night processing is more suspicious
    if (hour >= 1 && hour <= 5) {
      riskScore += 25
      processingRiskScore += 20
      threats.push('NIGHT_PROCESSING_ACTIVITY')
      suspiciousIndicators.push('Night time auto-checkout processing activity')
    }

    // Weekend processing might indicate automated activity
    if ((dayOfWeek === 0 || dayOfWeek === 6) && hour > 2 && hour < 7) {
      riskScore += 25
      processingRiskScore += 20
      threats.push('WEEKEND_NIGHT_PROCESSING')
      suspiciousIndicators.push('Weekend night time processing activity')
    }

    // User agent analysis
    if (!userAgent || userAgent.length < 10) {
      riskScore += 20
      threats.push('SUSPICIOUS_USER_AGENT')
      suspiciousIndicators.push('Missing or invalid user agent for processing operations')
    }

    // Automated processing detection
    const botPatterns = /bot|crawler|spider|scraper|curl|wget|python|java|go-http|libwww|nikto|nmap|process/i
    if (botPatterns.test(userAgent)) {
      riskScore += 60
      processingRiskScore += 50
      threats.push('AUTOMATED_PROCESSING_ACCESS')
      suspiciousIndicators.push('Automated bot accessing auto-checkout processing system')
    }

    // Common automation indicators
    const automationIndicators = [
      'headless', 'phantom', 'selenium', 'webdriver', 'puppeteer', 'playwright'
    ]
    
    if (automationIndicators.some(indicator => userAgent.toLowerCase().includes(indicator))) {
      riskScore += 45
      processingRiskScore += 40
      threats.push('AUTOMATION_TOOL_DETECTED')
      suspiciousIndicators.push('Browser automation tool detected')
    }

    // Referer analysis for processing operations
    if (referer) {
      const refererUrl = new URL(referer)
      const isInternalReferer = refererUrl.hostname.includes('localhost') || 
                               refererUrl.hostname.includes('127.0.0.1') ||
                               refererUrl.hostname.includes(new URL(request.url).hostname)
      
      if (!isInternalReferer) {
        riskScore += 15
        threats.push('EXTERNAL_PROCESSING_ACCESS')
        suspiciousIndicators.push('External referer for processing operations')
      }
    }

    // Role-based risk assessment - processing is more sensitive
    if (user.role !== 'HOTEL_MANAGER' && user.role !== 'ADMIN') {
      riskScore += 70
      processingRiskScore += 60
      threats.push('UNAUTHORIZED_PROCESSING_ACCESS')
      suspiciousIndicators.push('Insufficient role for processing operations')
    }

    // Analyze JSON body for processing-specific threats
    try {
      const body = await request.clone().json()
      
      // Check for suspicious processing parameters
      const suspiciousParams = ['batch', 'bulk', 'multiple', 'concurrent', 'force', 'override']
      const hasSuspiciousParams = suspiciousParams.some(param => 
        JSON.stringify(body).toLowerCase().includes(param)
      )
      
      if (hasSuspiciousParams) {
        riskScore += 30
        processingRiskScore += 25
        threats.push('SUSPICIOUS_PROCESSING_PARAMETERS')
        suspiciousIndicators.push('Request contains suspicious processing parameters')
      }

      // Check for bulk processing indicators
      if (body.taskId && Array.isArray(body.taskId)) {
        riskScore += 35
        processingRiskScore += 30
        threats.push('BULK_PROCESSING_DETECTED')
        suspiciousIndicators.push('Bulk processing attempt detected')
      }
    } catch (e) {
      // If we can't parse the body, that's suspicious for a POST request
      riskScore += 15
      threats.push('INVALID_REQUEST_BODY')
      suspiciousIndicators.push('Unable to parse request body')
    }

    // Analyze URL parameters for processing threats
    const url = new URL(request.url)
    for (const [key, value] of url.searchParams.entries()) {
      for (const threatPattern of this.processThreatPatterns) {
        if (threatPattern.pattern.test(value)) {
          riskScore += threatPattern.weight
          if (threatPattern.type.includes('PROCESS') || threatPattern.type.includes('EXECUTION')) {
            processingRiskScore += threatPattern.weight * 0.9
          }
          threats.push(threatPattern.type)
          suspiciousIndicators.push(`Processing threat pattern detected in parameter: ${key}`)
        }
      }
    }

    // Check for sensitive processing parameters
    const sensitiveParams = ['taskId', 'hotelId', 'batchId', 'processId', 'force', 'override']
    const hasSensitiveParams = sensitiveParams.some(param => 
      Array.from(url.searchParams.keys()).some(key => key.toLowerCase().includes(param))
    )
    
    if (hasSensitiveParams) {
      riskScore += 25
      processingRiskScore += 20
      threats.push('SENSITIVE_PROCESSING_PARAMETERS')
      suspiciousIndicators.push('Request contains sensitive processing parameters')
    }

    // Update processing pattern
    this.processingPatterns.set(processKey, processingPattern)

    // Determine risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    let recommendedAction: string

    // Use the higher of general risk or processing risk
    const finalRiskScore = Math.max(riskScore, processingRiskScore)
    
    if (finalRiskScore >= 75) {
      riskLevel = 'CRITICAL'
      recommendedAction = 'BLOCK_REQUEST'
    } else if (finalRiskScore >= 55) {
      riskLevel = 'HIGH'
      recommendedAction = 'ENHANCED_MONITORING'
    } else if (finalRiskScore >= 30) {
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
      processingRiskScore: finalRiskScore
    }
  }

  cleanupOldEntries() {
    const now = new Date()
    const timeout = 15 * 60 * 1000 // 15 minutes
    
    for (const [key, pattern] of this.processingPatterns.entries()) {
      if (now.getTime() - pattern.lastRequest.getTime() > timeout) {
        this.processingPatterns.delete(key)
      }
    }
  }
}

const processThreatDetector = new ProcessThreatDetector()

// Enhanced Request Validation Schema
const ProcessCheckoutSchema = z.object({
  taskId: z.union([z.string().uuid(), z.array(z.string().uuid()).min(1).max(10)]),
  hotelId: z.string().uuid().optional(),
  forceProcess: z.boolean().default(false),
  batchMode: z.boolean().default(false),
  notes: z.string().max(1000).optional(),
  correlationId: z.string().optional(),
  idempotencyKey: z.string().optional(),
  priority: z.enum(['low', 'normal', 'high', 'urgent']).default('normal')
})

// Processing Data Masking
function maskProcessingData(data: any, context: string, userRole: string, userId: string): any {
  const maskValue = (value: string, visibleChars: number = 2): string => {
    if (!value || typeof value !== 'string') return value
    if (value.length <= visibleChars * 2) return '*'.repeat(value.length)
    return value.substring(0, visibleChars) + '*'.repeat(value.length - visibleChars * 2) + value.substring(value.length - visibleChars)
  }

  const applyProcessingMasking = (obj: any): any => {
    if (!obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(applyProcessingMasking)

    const masked = { ...obj }
    
    // Mask task and process IDs
    if (masked.taskId) {
      masked.taskId = maskValue(masked.taskId, 8)
    }
    
    // Mask hotel information
    if (masked.hotelId) {
      masked.hotelId = maskValue(masked.hotelId, 8)
    }
    
    // Mask guest information in processing context
    if (masked.guestInfo) {
      masked.guestInfo = {
        ...masked.guestInfo,
        name: maskValue(masked.guestInfo.name || '', 1),
        email: maskValue(masked.guestInfo.email || '', 3)
      }
    }
    
    // Mask financial information
    if (masked.amount) {
      // Round amounts for non-admin users
      if (userRole !== 'ADMIN') {
        masked.amount = Math.round(masked.amount / 10) * 10
      }
    }
    
    // Mask payment information
    if (masked.paymentInfo) {
      masked.paymentInfo = {
        method: masked.paymentInfo.method,
        amount: masked.paymentInfo.amount,
        transactionId: masked.paymentInfo.transactionId ? maskValue(masked.paymentInfo.transactionId, 4) : undefined
      }
    }

    return masked
  }

  return applyProcessingMasking(data)
}

// Comprehensive Processing Audit Logging
async function logProcessingSecurityEvent(
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
        action: `PROCESS_${eventType}`,
        resource: 'AutoCheckoutProcess',
        resourceId: details.resourceId || null,
        ipAddress: ip,
        userAgent,
        method: 'POST',
        newValues: JSON.stringify({
          ...details,
          hotelId,
          processingOperation: true,
          batchMode: details.batchMode || false,
          forceProcess: details.forceProcess || false
        }),
        metadata: {
          requestId,
          riskLevel,
          timestamp: new Date().toISOString(),
          referer,
          userRole: user.role,
          adminLevel: user.adminLevel,
          processingType: 'auto_checkout_processing'
        }
      }
    })

    // Log to security events table with processing context
    await prisma.securityEvent.create({
      data: {
        eventType: `PROCESS_${eventType}`,
        severity: riskLevel === 'CRITICAL' ? 'high' : riskLevel === 'HIGH' ? 'medium' : 'low',
        description: `Auto-checkout processing operation: ${eventType}`,
        ipAddress: ip,
        userId: user.id,
        metadata: {
          requestId,
          userRole: user.role,
          hotelId,
          processingType: 'auto_checkout_processing',
          batchMode: details.batchMode || false,
          details
        },
        resolved: riskLevel !== 'CRITICAL'
      }
    })
  } catch (error) {
    console.error('Failed to log processing security event:', error)
  }
}

// Advanced Rate Limiting for Processing Operations
class ProcessingRateLimiter {
  private buckets = new Map<string, { tokens: number; lastRefill: number; maxTokens: number; refillRate: number; processingOperations: number; batchOperations: number }>()

  constructor() {
    setInterval(() => this.cleanup(), 5 * 60 * 1000)
  }

  async checkLimit(key: string, isBatch: boolean, maxTokens: number, refillRate: number, windowMs: number): Promise<{ success: boolean; remaining: number; resetTime: number; processingLimit?: boolean; batchLimit?: boolean }> {
    const now = Date.now()
    const bucket = this.buckets.get(key) || { 
      tokens: maxTokens, 
      lastRefill: now, 
      maxTokens, 
      refillRate,
      processingOperations: 0,
      batchOperations: 0
    }

    // Calculate tokens to add based on time passed
    const timePassed = now - bucket.lastRefill
    const tokensToAdd = (timePassed * bucket.refillRate) / windowMs
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd)
    bucket.lastRefill = now

    // Check batch operation limits
    if (isBatch && bucket.batchOperations >= 5) {
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + windowMs,
        batchLimit: true
      }
    }

    // Check general processing limits
    if (bucket.processingOperations >= 15) {
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + windowMs,
        processingLimit: true
      }
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1
      bucket.processingOperations++
      if (isBatch) {
        bucket.batchOperations++
      }
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
      processingLimit: true
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

const processingRateLimiter = new ProcessingRateLimiter()

// Idempotency Management for Processing Operations
const processingIdempotencyStore = new Map<string, { status: number; response: any; timestamp: number; operation: string; isBatch: boolean }>()

function checkProcessingIdempotency(key: string, operation: string, isBatch: boolean): { shouldProcess: boolean; existingResponse?: any } {
  const now = Date.now()
  const timeout = 24 * 60 * 60 * 1000 // 24 hours
  
  const existing = processingIdempotencyStore.get(key)
  if (existing && existing.operation === operation && existing.isBatch === isBatch && (now - existing.timestamp) < timeout) {
    return { shouldProcess: false, existingResponse: existing.response }
  }
  
  if (existing) {
    processingIdempotencyStore.delete(key)
  }
  
  return { shouldProcess: true }
}

function storeProcessingIdempotencyResult(key: string, operation: string, isBatch: boolean, status: number, response: any) {
  processingIdempotencyStore.set(key, {
    status,
    response,
    timestamp: Date.now(),
    operation,
    isBatch
  })
}

// ===========================================
// POST - معالجة المغادرة التلقائية (Advanced Security)
// ===========================================
export async function POST(request: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Auto-checkout processing POST request initiated`)

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
      const body = await request.clone().json()
      const isBatch = Array.isArray(body.taskId) && body.taskId.length > 1
      
      const idempotencyResult = checkProcessingIdempotency(idempotencyKey, 'POST', isBatch)
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

    // AI Processing Threat Analysis
    const threatAnalysis = await processThreatDetector.analyzeProcessRequest(request, user, requestId)
    console.log(`[${requestId}] Processing threat analysis: ${threatAnalysis.riskLevel} risk`)

    if (threatAnalysis.riskLevel === 'CRITICAL') {
      await logProcessingSecurityEvent('CRITICAL_PROCESSING_THREAT_BLOCKED', user, request, {
        requestId,
        threats: threatAnalysis.threats,
        indicators: threatAnalysis.suspiciousIndicators,
        processingScore: threatAnalysis.processingRiskScore
      }, 'CRITICAL', requestId)
      
      return apiResponse.error("Auto-checkout processing blocked due to security concerns")
    }

    // Log security event for high-risk processing
    if (threatAnalysis.riskLevel === 'HIGH') {
      await logProcessingSecurityEvent('HIGH_RISK_PROCESSING_ATTEMPT', user, request, {
        requestId,
        threats: threatAnalysis.threats,
        confidence: threatAnalysis.confidence
      }, 'HIGH', requestId)
    }

    // Advanced Rate Limiting for Processing Operations
    const body = await request.json()
    const isBatch = Array.isArray(body.taskId) && body.taskId.length > 1
    
    const rateLimitKey = `checkout_process:${user.id}`
    const rateLimitResult = await processingRateLimiter.checkLimit(rateLimitKey, isBatch, 15, 15, 60000) // 15 operations per minute
    
    if (!rateLimitResult.success) {
      console.log(`[${requestId}] Rate limit exceeded for checkout processing`)
      return apiResponse.error(
        rateLimitResult.batchLimit 
          ? "Batch processing limit exceeded. Please process fewer items at once." 
          : rateLimitResult.processingLimit
          ? "Processing limit exceeded. Please try again later."
          : "Rate limit exceeded. Too many checkout processing requests."
      )
    }

    const validated = ProcessCheckoutSchema.parse(body)

    console.log(`[${requestId}] Validated processing request: ${isBatch ? 'BATCH' : 'SINGLE'} mode`)

    const { taskId, hotelId: requestHotelId, forceProcess, batchMode, notes, priority } = validated

    // Validate hotel access
    let hotelId = requestHotelId
    if (!hotelId) {
      // For single task processing, try to get hotel from task
      if (!Array.isArray(taskId)) {
        // This would require a database lookup to get the hotel ID from task
        // For now, we'll require hotelId to be provided
        return apiResponse.badRequest("Hotel ID is required for processing")
      }
    }

    // Enhanced validation for batch processing
    if (Array.isArray(taskId) && taskId.length > 5) {
      return apiResponse.badRequest("Maximum 5 tasks can be processed in batch mode")
    }

    // Process auto-checkout with enhanced security
    const result = await autoCheckoutService.processAutoCheckout(
      Array.isArray(taskId) ? taskId[0] : taskId, // For now, process single task
      user.id,
      {
        force: forceProcess,
        notes,
        priority,
        requestId,
        threatLevel: threatAnalysis.riskLevel
      }
    )

    const executionTime = Date.now() - startTime

    console.log(`[${requestId}] Auto-checkout processing completed successfully in ${executionTime}ms`)

    // Log successful processing
    await logProcessingSecurityEvent('PROCESSING_COMPLETED', user, request, {
      requestId,
      taskId: Array.isArray(taskId) ? taskId.length : 1,
      batchMode: isBatch,
      forceProcess,
      notes: notes ? 'PROVIDED' : 'NOT_PROVIDED',
      threatLevel: threatAnalysis.riskLevel,
      executionTime
    }, threatAnalysis.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW', requestId)

    // Mask processing result data
    const maskedResult = maskProcessingData(result, 'processing', user.role, user.id)

    // Store idempotency result
    if (idempotencyKey && shouldProcess) {
      storeProcessingIdempotencyResult(idempotencyKey, 'POST', isBatch, 200, {
        ...apiResponse.success({
          result: maskedResult,
          processing: {
            executionTime,
            requestId,
            threatLevel: threatAnalysis.riskLevel,
            processingRiskScore: threatAnalysis.processingRiskScore,
            batchMode: isBatch,
            forceProcess
          }
        }, "تمت معالجة المغادرة التلقائية بنجاح")
      })
    }

    return NextResponse.json(
      apiResponse.success({
        result: maskedResult,
        processing: {
          executionTime,
          requestId,
          threatLevel: threatAnalysis.riskLevel,
          processingRiskScore: threatAnalysis.processingRiskScore,
          batchMode: isBatch,
          forceProcess
        }
      }, "تمت معالجة المغادرة التلقائية بنجاح"),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Threat-Level': threatAnalysis.riskLevel,
          'X-Processing-Risk-Score': threatAnalysis.processingRiskScore.toString(),
          'X-Batch-Mode': isBatch.toString(),
          'X-Processing-Status': 'COMPLETED'
        }
      }
    )

  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in POST auto-checkout processing:`, error)
    
    // Log error with enhanced context
    try {
      const user = await authenticate(request)
      if (user) {
        await logProcessingSecurityEvent('PROCESSING_ERROR', user, request, {
          requestId,
          error: error.message,
          executionTime,
          stack: error.stack
        }, 'MEDIUM', requestId)
      }
    } catch (authError) {
      console.error(`[${requestId}] Failed to authenticate user for error logging:`, authError)
    }

    const errorResponse = apiResponse.error(error.message || "خطأ في معالجة المغادرة")

    // Store error in idempotency store
    try {
      const body = await request.clone().json()
      const isBatch = Array.isArray(body.taskId) && body.taskId.length > 1
      if (idempotencyKey && shouldProcess) {
        storeProcessingIdempotencyResult(idempotencyKey, 'POST', isBatch, 500, errorResponse)
      }
    } catch (parseError) {
      console.error(`[${requestId}] Failed to parse body for idempotency storage:`, parseError)
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
    processThreatDetector.cleanupOldEntries()
  }
}