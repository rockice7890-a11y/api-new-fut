import { type NextRequest, NextResponse } from "next/server"
import { requireAuth, requireRole } from "@/lib/middleware"
import { PermissionsService } from "@/lib/services/permissions.service"
import { auditLogger } from "@/lib/audit-logger"
import { securityMonitor } from "@/lib/security-monitor"
import { securitySafe } from "@/lib/security-safe"
import { rateLimit } from "@/lib/rate-limit"
import { jwtVerify, SignJWT } from "jose"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Security constants
const SECURITY_CONFIG = {
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 50,
  CACHE_TTL: 30 * 1000, // 30 seconds
  SESSION_VALIDATION_TIMEOUT: 5 * 60 * 1000, // 5 minutes
  AUDIT_LOG_RETENTION_DAYS: 90,
  SENSITIVE_DATA_MASKING: true,
  ENCRYPTION_ENABLED: true
}

// Security state management
interface SecurityState {
  requestId: string
  deviceFingerprint: string
  userAgent: string
  ipAddress: string
  riskScore: number
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  sessionToken: string
  correlationId: string
}

class AdvancedAuditLogSecurity {
  private static instance: AdvancedAuditLogSecurity
  private securityContext: Map<string, SecurityState> = new Map()
  private requestPatterns: Map<string, number[]> = new Map()
  private sensitiveFields = ['password', 'token', 'secret', 'key', 'credentials', 'ssn', 'credit_card']

  private constructor() {}

  static getInstance(): AdvancedAuditLogSecurity {
    if (!AdvancedAuditLogSecurity.instance) {
      AdvancedAuditLogSecurity.instance = new AdvancedAuditLogSecurity()
    }
    return AdvancedAuditLogSecurity.instance
  }

  // Generate unique request identifiers
  private generateRequestId(): string {
    return crypto.randomUUID()
  }

  private generateCorrelationId(): string {
    return crypto.randomUUID()
  }

  // Extract and validate device information
  private extractDeviceInfo(req: NextRequest): { fingerprint: string; userAgent: string } {
    const userAgent = req.headers.get('user-agent') || 'Unknown'
    
    // Create device fingerprint based on multiple factors
    const fingerprintComponents = [
      userAgent,
      req.headers.get('accept-language') || '',
      req.headers.get('accept-encoding') || '',
      req.headers.get('sec-ch-ua') || '',
      req.headers.get('sec-ch-ua-platform') || '',
    ].join('|')

    const fingerprint = crypto
      .createHash('sha256')
      .update(fingerprintComponents)
      .digest('hex')
      .substring(0, 32)

    return { fingerprint, userAgent }
  }

  // AI-powered threat detection for audit log access
  private analyzeAuditLogThreat(context: SecurityState, queryParams: URLSearchParams): {
    threatScore: number
    detectedThreats: string[]
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  } {
    const threats: string[] = []
    let threatScore = 0

    // Analyze query patterns for suspicious behavior
    const action = queryParams.get('action')
    const resource = queryParams.get('resource')
    const limit = queryParams.get('limit')

    // Suspicious action patterns
    if (action && this.isSuspiciousAction(action)) {
      threats.push('SUSPICIOUS_AUDIT_ACTION')
      threatScore += 20
    }

    // Resource enumeration attempts
    if (resource && this.isSuspiciousResource(resource)) {
      threats.push('RESOURCE_ENUMERATION')
      threatScore += 25
    }

    // Excessive data requests
    if (limit && Number(limit) > 1000) {
      threats.push('EXCESSIVE_DATA_REQUEST')
      threatScore += 30
    }

    // Frequency-based detection
    const recentRequests = this.requestPatterns.get(context.ipAddress) || []
    const now = Date.now()
    const recentRequestCount = recentRequests.filter(timestamp => 
      now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW
    ).length

    if (recentRequestCount > 20) {
      threats.push('HIGH_FREQUENCY_ACCESS')
      threatScore += 15
    }

    // Role-based anomaly detection
    if (this.isUnusualTimeForAuditAccess()) {
      threats.push('UNUSUAL_TIME_ACCESS')
      threatScore += 10
    }

    // Risk level determination
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    if (threatScore >= 50) riskLevel = 'CRITICAL'
    else if (threatScore >= 30) riskLevel = 'HIGH'
    else if (threatScore >= 15) riskLevel = 'MEDIUM'

    return { threatScore, detectedThreats: threats, riskLevel }
  }

  private isSuspiciousAction(action: string): boolean {
    const suspiciousPatterns = [
      /delete|remove/i,
      /admin|super/i,
      /config|settings/i,
      /user|password/i
    ]
    return suspiciousPatterns.some(pattern => pattern.test(action))
  }

  private isSuspiciousResource(resource: string): boolean {
    const suspiciousPatterns = [
      /users|accounts/i,
      /admin|root/i,
      /config|database/i,
      /financial|payment/i
    ]
    return suspiciousPatterns.some(pattern => pattern.test(resource))
  }

  private isUnusualTimeForAuditAccess(): boolean {
    const hour = new Date().getHours()
    // Flag access during typical off-hours (2 AM - 6 AM)
    return hour >= 2 && hour <= 6
  }

  // Advanced session validation
  private async validateSessionSecurity(req: NextRequest, userId: string): Promise<{
    isValid: boolean
    sessionState: any
    violations: string[]
  }> {
    const violations: string[] = []
    
    try {
      const sessionToken = req.headers.get('x-session-token')
      const refreshToken = req.headers.get('x-refresh-token')
      
      if (!sessionToken) {
        violations.push('MISSING_SESSION_TOKEN')
        return { isValid: false, sessionState: null, violations }
      }

      // JWT session validation
      const secret = new TextEncoder().encode(process.env.REFRESH_TOKEN_SECRET || 'fallback-secret')
      const { payload } = await jwtVerify(sessionToken, secret)
      
      // Session expiration check
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        violations.push('SESSION_EXPIRED')
        return { isValid: false, sessionState: null, violations }
      }

      // Session fingerprint validation
      const deviceInfo = this.extractDeviceInfo(req)
      const sessionFingerprint = payload.deviceFingerprint as string
      if (sessionFingerprint && sessionFingerprint !== deviceInfo.fingerprint) {
        violations.push('DEVICE_FINGERPRINT_MISMATCH')
      }

      return { 
        isValid: violations.length === 0, 
        sessionState: payload, 
        violations 
      }
    } catch (error) {
      violations.push('SESSION_VALIDATION_ERROR')
      return { isValid: false, sessionState: null, violations }
    }
  }

  // Encrypt sensitive log data
  private encryptSensitiveData(data: any): any {
    if (!SECURITY_CONFIG.ENCRYPTION_ENABLED) return data

    const encrypted = { ...data }
    const cipher = crypto.createCipher('aes-256-gcm', process.env.JWT_SECRET || 'fallback-secret')
    
    // Encrypt sensitive fields
    for (const field of this.sensitiveFields) {
      if (encrypted[field]) {
        encrypted[field] = this.performEncryption(encrypted[field])
      }
    }

    return encrypted
  }

  private performEncryption(data: string): string {
    const cipher = crypto.createCipher('aes-256-gcm', process.env.JWT_SECRET || 'fallback-secret')
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return encrypted
  }

  // Record security event for monitoring
  private recordSecurityEvent(event: any): void {
    try {
      auditLogger.log({
        event: 'AUDIT_LOG_ACCESS',
        level: 'INFO',
        userId: event.userId,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: {
          requestId: event.requestId,
          correlationId: event.correlationId,
          threatLevel: event.threatLevel,
          riskScore: event.riskScore,
          queryParams: event.queryParams,
          securityViolations: event.violations
        }
      })
    } catch (error) {
      console.error('Failed to record security event:', error)
    }
  }

  // Mask sensitive data in logs
  private maskSensitiveData(data: any): any {
    if (!SECURITY_CONFIG.SENSITIVE_DATA_MASKING) return data

    const masked = { ...data }
    
    function maskObject(obj: any): any {
      if (typeof obj !== 'object' || obj === null) return obj
      
      const result = Array.isArray(obj) ? [] : {}
      
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'object') {
          result[key] = maskObject(value)
        } else if (typeof value === 'string') {
          // Mask sensitive fields
          if (key.toLowerCase().includes('password') || 
              key.toLowerCase().includes('token') ||
              key.toLowerCase().includes('secret')) {
            result[key] = '***MASKED***'
          } else {
            result[key] = value
          }
        } else {
          result[key] = value
        }
      }
      
      return result
    }

    return maskObject(masked)
  }

  // Main security processing
  public async processRequest(req: NextRequest): Promise<{
    isAllowed: boolean
    context: SecurityState
    violations: string[]
    recommendations: string[]
  }> {
    const requestId = this.generateRequestId()
    const correlationId = this.generateCorrelationId()
    
    // Extract request information
    const { fingerprint, userAgent } = this.extractDeviceInfo(req)
    const ipAddress = req.headers.get('x-forwarded-for') || req.ip || 'unknown'

    // Initialize security context
    const context: SecurityState = {
      requestId,
      deviceFingerprint: fingerprint,
      userAgent,
      ipAddress,
      riskScore: 0,
      threatLevel: 'LOW',
      sessionToken: req.headers.get('x-session-token') || '',
      correlationId
    }

    const violations: string[] = []
    const recommendations: string[] = []

    try {
      // Rate limiting check
      const rateLimitKey = `${ipAddress}:audit-logs`
      const rateLimitResult = await rateLimit.check(rateLimitKey, SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS, SECURITY_CONFIG.RATE_LIMIT_WINDOW)
      
      if (!rateLimitResult.allowed) {
        violations.push('RATE_LIMIT_EXCEEDED')
        recommendations.push('Implement exponential backoff')
      }

      // Record request pattern
      const now = Date.now()
      const requests = this.requestPatterns.get(ipAddress) || []
      requests.push(now)
      // Keep only recent requests
      this.requestPatterns.set(ipAddress, requests.filter(timestamp => now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW))

      // Query parameter validation
      const { searchParams } = new URL(req.url)
      
      // Parameter sanitization
      const sanitizedParams = new URLSearchParams()
      for (const [key, value] of searchParams.entries()) {
        if (this.isValidParameter(key, value)) {
          sanitizedParams.append(key, value)
        } else {
          violations.push(`INVALID_PARAMETER: ${key}`)
        }
      }

      // Threat analysis
      const threatAnalysis = this.analyzeAuditLogThreat(context, sanitizedParams)
      context.riskScore = threatAnalysis.threatScore
      context.threatLevel = threatAnalysis.riskLevel

      if (threatAnalysis.detectedThreats.length > 0) {
        violations.push(...threatAnalysis.detectedThreats)
        recommendations.push('Review and block suspicious IP addresses')
      }

      // Session validation will be performed after user authentication

      // Final security decision
      const isAllowed = violations.length === 0 || context.threatLevel !== 'CRITICAL'

      // Record security event
      this.recordSecurityEvent({
        event: 'AUDIT_LOG_SECURITY_CHECK',
        userId: 'unknown',
        ipAddress,
        userAgent,
        requestId,
        correlationId,
        threatLevel: context.threatLevel,
        riskScore: context.riskScore,
        queryParams: sanitizedParams.toString(),
        violations
      })

      return { isAllowed, context, violations, recommendations }

    } catch (error) {
      violations.push('SECURITY_PROCESSING_ERROR')
      return { 
        isAllowed: false, 
        context, 
        violations,
        recommendations: ['Contact system administrator']
      }
    }
  }

  private isValidParameter(key: string, value: string): boolean {
    // Parameter validation rules
    const validKeys = ['action', 'resource', 'limit', 'offset', 'date_from', 'date_to', 'user_id']
    
    if (!validKeys.includes(key)) return false
    
    // Value validation
    if (typeof value !== 'string') return false
    
    // SQL injection prevention
    const sqlPatterns = /('|(\\x27)|(\\x23)|(;)|(\\*)|(%)|(\\*)|(\\x2b)|(\\x2b)|(UNION)|(SELECT)|(INSERT)|(UPDATE)|(DELETE)|(DROP)|(CREATE)|(ALTER)|(EXEC)|(EXECUTE))/i
    if (sqlPatterns.test(value)) return false
    
    // XSS prevention
    const xssPatterns = /(<script|javascript:|onload=|onerror=|eval\(|expression\()/i
    if (xssPatterns.test(value)) return false
    
    return true
  }
}

// Initialize security processor
const securityProcessor = AdvancedAuditLogSecurity.getInstance()

export async function GET(req: NextRequest) {
  const startTime = Date.now()
  let securityContext: SecurityState | null = null

  try {
    // Perform advanced security analysis
    const securityResult = await securityProcessor.processRequest(req)
    
    if (!securityResult.isAllowed) {
      // Log security violation
      await auditLogger.log({
        event: 'AUDIT_LOG_ACCESS_DENIED',
        level: 'HIGH',
        userId: 'unknown',
        ipAddress: securityResult.context.ipAddress,
        userAgent: securityResult.context.userAgent,
        metadata: {
          requestId: securityResult.context.requestId,
          correlationId: securityResult.context.correlationId,
          violations: securityResult.violations,
          threatLevel: securityResult.context.threatLevel,
          riskScore: securityResult.context.riskScore
        }
      })

      return NextResponse.json(
        {
          status: "error",
          message: "Access denied due to security policy violations",
          security: {
            violations: securityResult.violations,
            recommendations: securityResult.recommendations,
            threatLevel: securityResult.context.threatLevel
          }
        },
        { status: 403 }
      )
    }

    securityContext = securityResult.context

    // Authenticate user with enhanced validation
    const user = await requireAuth(req)
    
    // Verify admin role with additional checks
    await requireRole(req, ["ADMIN"])

    // Enhanced session validation
    const sessionValidation = await securityProcessor.validateSessionSecurity(req, user.id)
    if (!sessionValidation.isValid) {
      await auditLogger.log({
        event: 'INVALID_SESSION_AUDIT_ACCESS',
        level: 'HIGH',
        userId: user.id,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        metadata: {
          requestId: securityContext.requestId,
          violations: sessionValidation.violations
        }
      })

      return NextResponse.json(
        {
          status: "error",
          message: "Session validation failed",
          security: {
            violations: sessionValidation.violations
          }
        },
        { status: 401 }
      )
    }

    // Extract and validate query parameters
    const { searchParams } = new URL(req.url)
    const action = searchParams.get("action") || undefined
    const resource = searchParams.get("resource") || undefined
    const limit = Math.min(Number.parseInt(searchParams.get("limit") || "100"), 1000) // Max 1000
    const offset = Math.max(Number.parseInt(searchParams.get("offset") || "0"), 0)
    const dateFrom = searchParams.get("date_from") || undefined
    const dateTo = searchParams.get("date_to") || undefined
    const userId = searchParams.get("user_id") || undefined

    // Validate date ranges
    if (dateFrom && dateTo) {
      const fromDate = new Date(dateFrom)
      const toDate = new Date(dateTo)
      if (fromDate >= toDate) {
        return NextResponse.json(
          { status: "error", message: "Invalid date range" },
          { status: 400 }
        )
      }
    }

    // Get audit logs with security context
    const logs = await PermissionsService.getAuditLogs(
      action || undefined,
      resource || undefined,
      limit,
      offset,
      dateFrom,
      dateTo,
      userId
    )

    // Apply security post-processing
    const processedLogs = logs.map(log => securityProcessor.maskSensitiveData(log))
    
    // Performance monitoring
    const processingTime = Date.now() - startTime

    // Log successful audit access
    await auditLogger.log({
      event: 'AUDIT_LOG_ACCESS_SUCCESS',
      level: 'INFO',
      userId: user.id,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      metadata: {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        action: action || 'all',
        resource: resource || 'all',
        limit,
        offset,
        recordsRetrieved: processedLogs.length,
        processingTime,
        threatLevel: securityContext.threatLevel,
        riskScore: securityContext.riskScore
      }
    })

    // Update security monitoring
    securityMonitor.recordMetric('audit_log_access_duration', processingTime)
    securityMonitor.recordMetric('audit_log_records_retrieved', processedLogs.length)
    securityMonitor.recordSecurityEvent({
      type: 'AUDIT_LOG_ACCESS',
      severity: 'LOW',
      details: {
        userId: user.id,
        action,
        resource,
        processingTime
      }
    })

    return NextResponse.json({ 
      status: "success", 
      data: processedLogs,
      security: {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        processingTime,
        threatLevel: securityContext.threatLevel,
        riskScore: securityContext.riskScore
      }
    })

  } catch (error) {
    const processingTime = Date.now() - startTime

    // Log security error
    await auditLogger.log({
      event: 'AUDIT_LOG_ACCESS_ERROR',
      level: 'HIGH',
      userId: securityContext?.sessionToken || 'unknown',
      ipAddress: securityContext?.ipAddress || 'unknown',
      userAgent: securityContext?.userAgent || 'unknown',
      metadata: {
        requestId: securityContext?.requestId,
        correlationId: securityContext?.correlationId,
        error: error instanceof Error ? error.message : 'Unknown error',
        processingTime
      }
    })

    // Enhanced error response with security context
    const errorResponse = {
      status: "error", 
      message: error instanceof Error ? error.message : "Failed to fetch audit logs",
      security: securityContext ? {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        threatLevel: securityContext.threatLevel
      } : null
    }

    return NextResponse.json(errorResponse, { status: 400 })
  }
}