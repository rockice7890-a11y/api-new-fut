import type { NextRequest } from "next/server"
import { autoCheckoutService } from "@/lib/services/auto-checkout.service"
import { authenticate } from "@/lib/middleware"
import { authorize } from "@/lib/middleware/permissions.middleware"
import { apiResponse } from "@/lib/api-response"
import { createHash, randomBytes, timingSafeEqual } from "crypto"
import jwt from "jsonwebtoken"
import { z } from "zod"

// ===========================================
// ADVANCED AUTO CHECKOUT SCHEDULE APIs
// جدولة المغادرة التلقائية - نظام أمان شامل
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
  'X-Auto-Checkout-Schedule': 'admin-only'
}

// Request Correlation & Tracing
let requestCounter = 0
const generateRequestId = () => {
  requestCounter++
  const timestamp = Date.now()
  const random = randomBytes(8).toString('hex')
  return `schedule-${timestamp}-${requestCounter}-${random}`
}

// Advanced Scheduling Threat Detection
interface ScheduleThreatAnalysis {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  threats: string[]
  confidence: number
  recommendedAction: string
  suspiciousIndicators: string[]
  schedulingRiskScore: number
}

class ScheduleThreatDetector {
  private scheduleThreatPatterns = [
    { pattern: /admin|root|system|privilege|elevate/i, weight: 60, type: 'PRIVILEGE_ESCALATION' },
    { pattern: /schedule|cron|job|task|automation/i, weight: 50, type: 'SCHEDULING_OPERATION' },
    { pattern: /union\s+select|drop\s+table|delete\s+from|update\s+set/i, weight: 70, type: 'SQL_INJECTION' },
    { pattern: /<script|javascript:|vbscript:|onload=|onerror=/i, weight: 55, type: 'XSS_ATTEMPT' },
    { pattern: /\.\.\/|\.\.\\/|%2e%2e%2f/i, weight: 50, type: 'PATH_TRAVERSAL' },
    { pattern: /eval\(|exec\(|system\(|shell_exec|cron|at|batch/i, weight: 80, type: 'CODE_INJECTION' },
    { pattern: /bulk|batch|multiple|concurrent|mass/i, weight: 40, type: 'BULK_SCHEDULING' },
    { pattern: /robot|automation|script|cronjob/i, weight: 45, type: 'AUTOMATED_SCHEDULING' }
  ]

  private schedulingPatterns = new Map<string, { count: number; lastRequest: Date; scheduleTypes: Set<string>; suspiciousActivity: number; bulkOperations: number; automationAttempts: number }>()

  async analyzeScheduleRequest(request: NextRequest, user: any, requestId: string): Promise<ScheduleThreatAnalysis> {
    const userAgent = request.headers.get('user-agent') || ''
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const referer = request.headers.get('referer') || ''
    
    let riskScore = 0
    let schedulingRiskScore = 0
    const threats: string[] = []
    const suspiciousIndicators: string[] = []
    
    // Analyze scheduling-specific patterns
    const scheduleKey = `${user.id}-${ip}`
    const now = new Date()
    const schedulingPattern = this.schedulingPatterns.get(scheduleKey) || { 
      count: 0, 
      lastRequest: now, 
      scheduleTypes: new Set(),
      suspiciousActivity: 0,
      bulkOperations: 0,
      automationAttempts: 0
    }
    
    schedulingPattern.count++
    schedulingPattern.scheduleTypes.add('auto_checkout_schedule')
    schedulingPattern.lastRequest = now

    // Detect scheduling enumeration
    if (schedulingPattern.scheduleTypes.size > 3) {
      riskScore += 35
      schedulingRiskScore += 30
      threats.push('SCHEDULING_ENUMERATION')
      suspiciousIndicators.push('Accessing multiple scheduling operations')
    }

    // Detect bulk scheduling attempts
    if (schedulingPattern.bulkOperations > 3) {
      riskScore += 40
      schedulingRiskScore += 35
      threats.push('EXCESSIVE_BULK_SCHEDULING')
      suspiciousIndicators.push('Multiple bulk scheduling operations')
    }

    // Time-based analysis for scheduling operations
    const hour = now.getHours()
    const dayOfWeek = now.getDay()
    
    // Outside normal hotel operating hours - critical for scheduling
    if (hour < 4 || hour > 20) {
      riskScore += 30
      schedulingRiskScore += 25
      suspiciousIndicators.push('Auto-checkout scheduling outside normal hours')
    }

    // Very early morning scheduling is suspicious
    if (hour >= 2 && hour <= 5) {
      riskScore += 35
      schedulingRiskScore += 30
      threats.push('EARLY_MORNING_SCHEDULING')
      suspiciousIndicators.push('Very early morning scheduling activity')
    }

    // Weekend scheduling might indicate background automation
    if ((dayOfWeek === 0 || dayOfWeek === 6) && hour > 1 && hour < 6) {
      riskScore += 30
      schedulingRiskScore += 25
      threats.push('WEEKEND_SCHEDULING_ACTIVITY')
      suspiciousIndicators.push('Weekend early morning scheduling activity')
    }

    // User agent analysis
    if (!userAgent || userAgent.length < 10) {
      riskScore += 25
      threats.push('SUSPICIOUS_USER_AGENT')
      suspiciousIndicators.push('Missing or invalid user agent for scheduling operations')
    }

    // Advanced automation detection for scheduling
    const automationPatterns = [
      'headless', 'phantom', 'selenium', 'webdriver', 'puppeteer', 'playwright',
      'cron', 'scheduler', 'job', 'task', 'automation'
    ]
    
    if (automationPatterns.some(pattern => userAgent.toLowerCase().includes(pattern))) {
      riskScore += 70
      schedulingRiskScore += 60
      threats.push('AUTOMATED_SCHEDULING_ACCESS')
      suspiciousIndicators.push('Automation tool accessing scheduling system')
      schedulingPattern.automationAttempts++
    }

    // Bot detection with higher sensitivity for scheduling
    const botPatterns = /bot|crawler|spider|scraper|curl|wget|python|java|go-http|libwww|nikto|nmap|cron|schedule/i
    if (botPatterns.test(userAgent)) {
      riskScore += 75
      schedulingRiskScore += 65
      threats.push('BOT_SCHEDULING_ACCESS')
      suspiciousIndicators.push('Bot detected accessing scheduling operations')
    }

    // Common scheduling automation tools
    const automationTools = [
      'curl', 'wget', 'python', 'node', 'php', 'ruby', 'perl', 'bash', 'sh'
    ]
    
    if (automationTools.some(tool => userAgent.toLowerCase().includes(tool))) {
      riskScore += 60
      schedulingRiskScore += 50
      threats.push 'AUTOMATION_TOOL_DETECTED'
      suspiciousIndicators.push('Programming tool detected for scheduling operations')
    }

    // Referer analysis for scheduling operations
    if (referer) {
      const refererUrl = new URL(referer)
      const isInternalReferer = refererUrl.hostname.includes('localhost') || 
                               refererUrl.hostname.includes('127.0.0.1') ||
                               refererUrl.hostname.includes(new URL(request.url).hostname)
      
      if (!isInternalReferer) {
        riskScore += 20
        threats.push('EXTERNAL_SCHEDULING_ACCESS')
        suspiciousIndicators.push('External referer for scheduling operations')
      }
    }

    // Role-based risk assessment - scheduling requires ADMIN
    if (user.role !== 'ADMIN') {
      riskScore += 80
      schedulingRiskScore += 70
      threats.push('UNAUTHORIZED_SCHEDULING_ACCESS')
      suspiciousIndicators.push('Scheduling operations require ADMIN role')
    }

    // Authorization check for scheduling
    if (user.role === 'ADMIN') {
      try {
        await authorize(user.id, 'ADMIN')
      } catch (authzError) {
        riskScore += 90
        schedulingRiskScore += 80
        threats.push('AUTHORIZATION_FAILURE')
        suspiciousIndicators.push('Failed authorization check for scheduling operations')
      }
    }

    // Analyze request body for scheduling-specific threats
    try {
      const body = await request.clone().json()
      
      // Check for suspicious scheduling parameters
      const suspiciousParams = ['cron', 'schedule', 'bulk', 'batch', 'force', 'override', 'script']
      const bodyStr = JSON.stringify(body).toLowerCase()
      
      if (suspiciousParams.some(param => bodyStr.includes(param))) {
        riskScore += 35
        schedulingRiskScore += 30
        threats.push('SUSPICIOUS_SCHEDULING_PARAMETERS')
        suspiciousIndicators.push('Request contains suspicious scheduling parameters')
      }

      // Check for automation indicators
      const automationIndicators = ['automatic', 'background', 'cron', 'job', 'task', 'script']
      const hasAutomationIndicators = automationIndicators.some(indicator => bodyStr.includes(indicator))
      
      if (hasAutomationIndicators) {
        riskScore += 40
        schedulingRiskScore += 35
        threats.push('AUTOMATION_INDICATORS_DETECTED')
        suspiciousIndicators.push('Request contains automation indicators')
      }

      // Check for bulk scheduling attempts
      if (body.bulk || body.batch || body.multiple) {
        riskScore += 45
        schedulingRiskScore += 40
        threats.push('BULK_SCHEDULING_ATTEMPT')
        suspiciousIndicators.push('Bulk scheduling attempt detected')
        schedulingPattern.bulkOperations++
      }
    } catch (e) {
      // If we can't parse the body, that's very suspicious for a POST scheduling request
      riskScore += 25
      threats.push('INVALID_SCHEDULING_REQUEST_BODY')
      suspiciousIndicators.push('Unable to parse scheduling request body')
    }

    // Analyze URL parameters for scheduling threats
    const url = new URL(request.url)
    for (const [key, value] of url.searchParams.entries()) {
      for (const threatPattern of this.scheduleThreatPatterns) {
        if (threatPattern.pattern.test(value)) {
          riskScore += threatPattern.weight
          if (threatPattern.type.includes('SCHEDULING') || threatPattern.type.includes('AUTOMATION')) {
            schedulingRiskScore += threatPattern.weight * 0.9
          }
          threats.push(threatPattern.type)
          suspiciousIndicators.push(`Scheduling threat pattern detected in parameter: ${key}`)
        }
      }
    }

    // Check for sensitive scheduling parameters
    const sensitiveParams = ['scheduleId', 'cron', 'jobId', 'taskId', 'force', 'override', 'bulk']
    const hasSensitiveParams = sensitiveParams.some(param => 
      Array.from(url.searchParams.keys()).some(key => key.toLowerCase().includes(param))
    )
    
    if (hasSensitiveParams) {
      riskScore += 30
      schedulingRiskScore += 25
      threats.push('SENSITIVE_SCHEDULING_PARAMETERS')
      suspiciousIndicators.push('Request contains sensitive scheduling parameters')
    }

    // Detect potential cron job injection attempts
    const cronPatterns = /[\;\|\&\$\(\)\[\]\{\}\`\\]/i
    const urlString = url.toString()
    if (cronPatterns.test(urlString)) {
      riskScore += 50
      schedulingRiskScore += 45
      threats.push('POTENTIAL_CRON_INJECTION')
      suspiciousIndicators.push('Potential cron job injection attempt detected')
    }

    // Update scheduling pattern
    this.schedulingPatterns.set(scheduleKey, schedulingPattern)

    // Determine risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    let recommendedAction: string

    // Use the higher of general risk or scheduling risk
    const finalRiskScore = Math.max(riskScore, schedulingRiskScore)
    
    if (finalRiskScore >= 80) {
      riskLevel = 'CRITICAL'
      recommendedAction = 'BLOCK_REQUEST'
    } else if (finalRiskScore >= 60) {
      riskLevel = 'HIGH'
      recommendedAction = 'ENHANCED_MONITORING'
    } else if (finalRiskScore >= 35) {
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
      schedulingRiskScore: finalRiskScore
    }
  }

  cleanupOldEntries() {
    const now = new Date()
    const timeout = 20 * 60 * 1000 // 20 minutes for scheduling operations
    
    for (const [key, pattern] of this.schedulingPatterns.entries()) {
      if (now.getTime() - pattern.lastRequest.getTime() > timeout) {
        this.schedulingPatterns.delete(key)
      }
    }
  }
}

const scheduleThreatDetector = new ScheduleThreatDetector()

// Enhanced Request Validation Schema
const ScheduleCheckoutSchema = z.object({
  hotelId: z.string().uuid().optional(),
  scheduleTime: z.string().datetime().optional(),
  bulkMode: z.boolean().default(false),
  forceSchedule: z.boolean().default(false),
  priority: z.enum(['low', 'normal', 'high', 'critical']).default('normal'),
  notes: z.string().max(1000).optional(),
  correlationId: z.string().optional(),
  idempotencyKey: z.string().optional(),
  validateOnly: z.boolean().default(false)
})

// Scheduling Data Masking
function maskSchedulingData(data: any, context: string, userRole: string, userId: string): any {
  const maskValue = (value: string, visibleChars: number = 2): string => {
    if (!value || typeof value !== 'string') return value
    if (value.length <= visibleChars * 2) return '*'.repeat(value.length)
    return value.substring(0, visibleChars) + '*'.repeat(value.length - visibleChars * 2) + value.substring(value.length - visibleChars)
  }

  const applySchedulingMasking = (obj: any): any => {
    if (!obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(applySchedulingMasking)

    const masked = { ...obj }
    
    // Mask sensitive scheduling identifiers
    if (masked.scheduleId) {
      masked.scheduleId = maskValue(masked.scheduleId, 8)
    }
    
    if (masked.jobId) {
      masked.jobId = maskValue(masked.jobId, 8)
    }
    
    if (masked.taskId) {
      masked.taskId = maskValue(masked.taskId, 8)
    }
    
    // Mask hotel information
    if (masked.hotelId) {
      masked.hotelId = maskValue(masked.hotelId, 8)
    }
    
    // Mask cron expressions if present
    if (masked.cronExpression) {
      masked.cronExpression = maskValue(masked.cronExpression, 5)
    }
    
    // Mask configuration details
    if (masked.config) {
      masked.config = {
        ...masked.config,
        // Mask sensitive config values
        apiKey: masked.config.apiKey ? maskValue(masked.config.apiKey, 4) : undefined,
        secret: masked.config.secret ? maskValue(masked.config.secret, 4) : undefined
      }
    }

    return masked
  }

  return applySchedulingMasking(data)
}

// Comprehensive Scheduling Audit Logging
async function logSchedulingSecurityEvent(
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
        action: `SCHEDULE_${eventType}`,
        resource: 'AutoCheckoutSchedule',
        resourceId: details.resourceId || null,
        ipAddress: ip,
        userAgent,
        method: 'POST',
        newValues: JSON.stringify({
          ...details,
          hotelId,
          schedulingOperation: true,
          adminOnly: true,
          bulkMode: details.bulkMode || false
        }),
        metadata: {
          requestId,
          riskLevel,
          timestamp: new Date().toISOString(),
          referer,
          userRole: user.role,
          adminLevel: user.adminLevel,
          schedulingType: 'auto_checkout_scheduling',
          requiresAuthorization: true
        }
      }
    })

    // Log to security events table with scheduling context
    await prisma.securityEvent.create({
      data: {
        eventType: `SCHEDULE_${eventType}`,
        severity: riskLevel === 'CRITICAL' ? 'high' : riskLevel === 'HIGH' ? 'medium' : 'low',
        description: `Auto-checkout scheduling operation: ${eventType}`,
        ipAddress: ip,
        userId: user.id,
        metadata: {
          requestId,
          userRole: user.role,
          hotelId,
          schedulingType: 'auto_checkout_scheduling',
          adminOnly: true,
          bulkMode: details.bulkMode || false,
          details
        },
        resolved: riskLevel !== 'CRITICAL'
      }
    })
  } catch (error) {
    console.error('Failed to log scheduling security event:', error)
  }
}

// Advanced Rate Limiting for Scheduling Operations
class SchedulingRateLimiter {
  private buckets = new Map<string, { tokens: number; lastRefill: number; maxTokens: number; refillRate: number; schedulingOperations: number; bulkOperations: number; adminOperations: number }>()

  constructor() {
    setInterval(() => this.cleanup(), 5 * 60 * 1000)
  }

  async checkLimit(key: string, isBulk: boolean, maxTokens: number, refillRate: number, windowMs: number): Promise<{ success: boolean; remaining: number; resetTime: number; schedulingLimit?: boolean; bulkLimit?: boolean; adminLimit?: boolean }> {
    const now = Date.now()
    const bucket = this.buckets.get(key) || { 
      tokens: maxTokens, 
      lastRefill: now, 
      maxTokens, 
      refillRate,
      schedulingOperations: 0,
      bulkOperations: 0,
      adminOperations: 0
    }

    // Calculate tokens to add based on time passed
    const timePassed = now - bucket.lastRefill
    const tokensToAdd = (timePassed * bucket.refillRate) / windowMs
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd)
    bucket.lastRefill = now

    // Check admin operation limits (very strict)
    bucket.adminOperations++
    if (bucket.adminOperations > 10) {
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + windowMs,
        adminLimit: true
      }
    }

    // Check bulk operation limits
    if (isBulk && bucket.bulkOperations > 3) {
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + windowMs,
        bulkLimit: true
      }
    }

    // Check general scheduling limits
    if (bucket.schedulingOperations > 8) {
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + windowMs,
        schedulingLimit: true
      }
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1
      bucket.schedulingOperations++
      if (isBulk) {
        bucket.bulkOperations++
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
      schedulingLimit: true
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

const schedulingRateLimiter = new SchedulingRateLimiter()

// Idempotency Management for Scheduling Operations
const schedulingIdempotencyStore = new Map<string, { status: number; response: any; timestamp: number; operation: string; isBulk: boolean }>()

function checkSchedulingIdempotency(key: string, operation: string, isBulk: boolean): { shouldProcess: boolean; existingResponse?: any } {
  const now = Date.now()
  const timeout = 24 * 60 * 60 * 1000 // 24 hours
  
  const existing = schedulingIdempotencyStore.get(key)
  if (existing && existing.operation === operation && existing.isBulk === isBulk && (now - existing.timestamp) < timeout) {
    return { shouldProcess: false, existingResponse: existing.response }
  }
  
  if (existing) {
    schedulingIdempotencyStore.delete(key)
  }
  
  return { shouldProcess: true }
}

function storeSchedulingIdempotencyResult(key: string, operation: string, isBulk: boolean, status: number, response: any) {
  schedulingIdempotencyStore.set(key, {
    status,
    response,
    timestamp: Date.now(),
    operation,
    isBulk
  })
}

// ===========================================
// POST - جدولة المغادرة التلقائية (Advanced Security)
// ===========================================
export async function POST(request: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Auto-checkout scheduling POST request initiated`)

  try {
    // Enhanced authentication with multiple checks
    const user = await authenticate(request)
    if (!user) {
      console.log(`[${requestId}] Authentication failed`)
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    console.log(`[${requestId}] User authenticated: ${user.email} (${user.role})`)

    // Strict authorization check for scheduling
    try {
      await authorize(user.id, "ADMIN")
      console.log(`[${requestId}] Authorization check passed`)
    } catch (authzError) {
      console.log(`[${requestId}] Authorization failed:`, authzError)
      await logSchedulingSecurityEvent('AUTHORIZATION_DENIED', user, request, {
        requestId,
        error: 'Authorization denied for scheduling operations',
        userRole: user.role
      }, 'HIGH', requestId)
      
      return apiResponse.forbidden("صلاحية إدارية مطلوبة لعمليات الجدولة")
    }

    // Idempotency check
    const idempotencyKey = request.headers.get('Idempotency-Key') || request.headers.get('X-Idempotency-Key')
    let shouldProcess = true
    
    if (idempotencyKey) {
      const body = await request.clone().json()
      const isBulk = body.bulkMode || false
      
      const idempotencyResult = checkSchedulingIdempotency(idempotencyKey, 'POST', isBulk)
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

    // AI Scheduling Threat Analysis
    const threatAnalysis = await scheduleThreatDetector.analyzeScheduleRequest(request, user, requestId)
    console.log(`[${requestId}] Scheduling threat analysis: ${threatAnalysis.riskLevel} risk`)

    if (threatAnalysis.riskLevel === 'CRITICAL') {
      await logSchedulingSecurityEvent('CRITICAL_SCHEDULING_THREAT_BLOCKED', user, request, {
        requestId,
        threats: threatAnalysis.threats,
        indicators: threatAnalysis.suspiciousIndicators,
        schedulingScore: threatAnalysis.schedulingRiskScore
      }, 'CRITICAL', requestId)
      
      return apiResponse.error("Auto-checkout scheduling blocked due to security concerns")
    }

    // Log security event for high-risk scheduling
    if (threatAnalysis.riskLevel === 'HIGH') {
      await logSchedulingSecurityEvent('HIGH_RISK_SCHEDULING_ATTEMPT', user, request, {
        requestId,
        threats: threatAnalysis.threats,
        confidence: threatAnalysis.confidence
      }, 'HIGH', requestId)
    }

    // Very strict rate limiting for scheduling operations
    const body = await request.json()
    const isBulk = body.bulkMode || false
    
    const rateLimitKey = `checkout_schedule:${user.id}`
    const rateLimitResult = await schedulingRateLimiter.checkLimit(rateLimitKey, isBulk, 8, 8, 60000) // 8 operations per minute
    
    if (!rateLimitResult.success) {
      console.log(`[${requestId}] Rate limit exceeded for checkout scheduling`)
      return apiResponse.error(
        rateLimitResult.adminLimit 
          ? "Admin operation limit exceeded. Contact system administrator." 
          : rateLimitResult.bulkLimit 
          ? "Bulk scheduling limit exceeded. Please schedule fewer operations."
          : rateLimitResult.schedulingLimit
          ? "Scheduling limit exceeded. Please try again later."
          : "Rate limit exceeded. Too many checkout scheduling requests."
      )
    }

    const validated = ScheduleCheckoutSchema.parse(body)

    console.log(`[${requestId}] Validated scheduling request: ${isBulk ? 'BULK' : 'SINGLE'} mode`)

    const { hotelId: requestHotelId, scheduleTime, bulkMode, forceSchedule, priority, notes, validateOnly } = validated

    // Log the scheduling attempt with full context
    await logSchedulingSecurityEvent('SCHEDULING_ATTEMPT', user, request, {
      requestId,
      hotelId: requestHotelId,
      scheduleTime,
      bulkMode,
      forceSchedule,
      priority,
      notes: notes ? 'PROVIDED' : 'NOT_PROVIDED',
      validateOnly,
      threatLevel: threatAnalysis.riskLevel
    }, threatAnalysis.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW', requestId, requestHotelId)

    // Schedule auto-checkouts with enhanced security
    if (!validateOnly) {
      await autoCheckoutService.scheduleAutoCheckouts({
        hotelId: requestHotelId,
        scheduleTime,
        bulkMode,
        forceSchedule,
        priority,
        notes,
        requestId,
        threatLevel: threatAnalysis.riskLevel,
        userId: user.id
      })
    }

    const executionTime = Date.now() - startTime

    console.log(`[${requestId}] Auto-checkout scheduling completed successfully in ${executionTime}ms`)

    // Log successful scheduling
    await logSchedulingSecurityEvent('SCHEDULING_COMPLETED', user, request, {
      requestId,
      scheduleTime,
      bulkMode,
      forceSchedule,
      priority,
      validateOnly,
      threatLevel: threatAnalysis.riskLevel,
      executionTime
    }, 'LOW', requestId, requestHotelId)

    // Mask response data
    const response = {
      message: "تم جدولة المغادرة التلقائية بنجاح",
      scheduledAt: new Date().toISOString(),
      requestId,
      performance: {
        executionTime,
        threatLevel: threatAnalysis.riskLevel,
        schedulingRiskScore: threatAnalysis.schedulingRiskScore,
        bulkMode,
        validateOnly
      },
      security: {
        userRole: user.role,
        authorizationLevel: 'ADMIN',
        schedulingOperation: true,
        auditLogged: true
      }
    }

    // Store idempotency result
    if (idempotencyKey && shouldProcess) {
      storeSchedulingIdempotencyResult(idempotencyKey, 'POST', isBulk, 200, {
        ...apiResponse.success(response, "تم جدولة المغادرة التلقائية بنجاح")
      })
    }

    return NextResponse.json(
      apiResponse.success(response, "تم جدولة المغادرة التلقائية بنجاح"),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Threat-Level': threatAnalysis.riskLevel,
          'X-Scheduling-Risk-Score': threatAnalysis.schedulingRiskScore.toString(),
          'X-Authorization-Level': 'ADMIN',
          'X-Bulk-Mode': isBulk.toString(),
          'X-Admin-Operation': 'true'
        }
      }
    )

  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in POST auto-checkout scheduling:`, error)
    
    // Log error with enhanced context
    try {
      const user = await authenticate(request)
      if (user) {
        await logSchedulingSecurityEvent('SCHEDULING_ERROR', user, request, {
          requestId,
          error: error.message,
          executionTime,
          stack: error.stack
        }, 'MEDIUM', requestId)
      }
    } catch (authError) {
      console.error(`[${requestId}] Failed to authenticate user for error logging:`, authError)
    }

    const errorResponse = apiResponse.error(error.message || "خطأ في جدولة المغادرة")

    // Store error in idempotency store
    try {
      const body = await request.clone().json()
      const isBulk = body.bulkMode || false
      if (idempotencyKey && shouldProcess) {
        storeSchedulingIdempotencyResult(idempotencyKey, 'POST', isBulk, 500, errorResponse)
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
          'X-Error-Type': 'INTERNAL_SERVER_ERROR',
          'X-Admin-Operation-Failed': 'true'
        }
      }
    )
  } finally {
    scheduleThreatDetector.cleanupOldEntries()
  }
}