import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { addSecurityHeaders } from "@/lib/security"
import { verifyToken } from "@/lib/auth"
import { AIThreatDetection } from "@/lib/security/ai-threat-detection"
import { AdvancedRateLimiter } from "@/lib/security/advanced-rate-limiter"
import { RequestCorrelation } from "@/lib/security/request-correlation"
import { AuditLogger } from "@/lib/security/audit-logger"
import { DataEncryption } from "@/lib/security/data-encryption"
import { BehavioralAnalysis } from "@/lib/security/behavioral-analysis"
import { PermissionValidator } from "@/lib/security/permission-validator"
import { ContentSecurity } from "@/lib/security/content-security"
import { SessionManager } from "@/lib/security/session-manager"
import { IPGeolocation } from "@/lib/security/ip-geolocation"
import { SecurityEventEmitter } from "@/lib/security/event-emitter"
import { AdvancedInputValidator } from "@/lib/security/advanced-input-validator"
import { EncryptedCache } from "@/lib/security/encrypted-cache"
import { SecurityMetrics } from "@/lib/security/security-metrics"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const requestId = RequestCorrelation.generateCorrelationId()
  const startTime = Date.now()
  
  // Initialize security context
  const clientIP = req.headers.get("x-forwarded-for") || req.ip || "unknown"
  const userAgent = req.headers.get("user-agent") || "unknown"
  const clientId = req.headers.get("x-client-id") || "unknown"
  
  try {
    // Advanced Security Layer 1: Request Correlation & Tracking
    RequestCorrelation.trackRequest(requestId, clientIP, userAgent, clientId)
    
    // Advanced Security Layer 2: IP Geolocation Analysis
    const geoLocation = await IPGeolocation.analyzeLocation(clientIP)
    
    // Advanced Security Layer 3: AI Threat Detection
    const threatAnalysis = await AIThreatDetection.analyzeRequest({
      method: 'GET',
      endpoint: '/api/profile/me',
      ip: clientIP,
      userAgent,
      headers: Object.fromEntries(req.headers.entries()),
      timestamp: new Date().toISOString()
    })
    
    if (threatAnalysis.shouldBlock) {
      await AuditLogger.log({
        event: 'THREAT_BLOCKED',
        level: 'HIGH',
        userId: 'unknown',
        details: { threatAnalysis, clientIP, requestId },
        requestId
      })
      
      SecurityEventEmitter.emit('security.threat_detected', {
        type: 'AI_DETECTED_THREAT',
        source: clientIP,
        requestId,
        severity: threatAnalysis.severity
      })
      
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Request blocked due to security concerns",
            code: "SECURITY_BLOCK",
            requestId
          },
          { status: 403 },
        ),
      )
    }
    
    // Advanced Security Layer 4: Rate Limiting with AI
    const rateLimiter = new AdvancedRateLimiter('profile_access')
    const rateLimitResult = await rateLimiter.checkLimit(clientIP, clientId)
    
    if (!rateLimitResult.allowed) {
      await AuditLogger.log({
        event: 'RATE_LIMIT_EXCEEDED',
        level: 'MEDIUM',
        userId: 'unknown',
        details: { rateLimitResult, clientIP, requestId },
        requestId
      })
      
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Too many requests",
            code: "RATE_LIMIT_EXCEEDED",
            retryAfter: rateLimitResult.retryAfter,
            requestId
          },
          { status: 429 },
        ),
      )
    }
    
    // Advanced Security Layer 5: Behavioral Analysis
    const behavioralAnalysis = await BehavioralAnalysis.analyzeUserBehavior(clientIP, {
      endpoint: '/api/profile/me',
      method: 'GET',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/profile/me'
      })
    }
    
    // Advanced Security Layer 6: Authorization Check
    const authHeader = req.headers.get("authorization")
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      await AuditLogger.log({
        event: 'AUTHENTICATION_FAILED',
        level: 'MEDIUM',
        userId: 'unknown',
        details: { reason: 'NO_TOKEN', clientIP, requestId },
        requestId
      })
      
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error", 
            message: "Authorization required",
            code: "NO_TOKEN",
            requestId
          },
          { status: 401 },
        ),
      )
    }
    
    // Advanced Security Layer 7: Token Validation & Verification
    const token = authHeader.substring(7)
    const decoded = verifyToken(token)
    
    if (!decoded) {
      await AuditLogger.log({
        event: 'TOKEN_VALIDATION_FAILED',
        level: 'HIGH',
        userId: 'unknown',
        details: { reason: 'INVALID_TOKEN', clientIP, requestId },
        requestId
      })
      
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid authentication token",
            code: "INVALID_TOKEN",
            requestId
          },
          { status: 401 },
        ),
      )
    }
    
    // Advanced Security Layer 8: Session Validation
    const sessionValid = await SessionManager.validateSession(decoded.userId as string, token)
    if (!sessionValid) {
      await AuditLogger.log({
        event: 'SESSION_INVALID',
        level: 'HIGH',
        userId: decoded.userId as string,
        details: { reason: 'SESSION_EXPIRED', clientIP, requestId },
        requestId
      })
      
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Session expired or invalid",
            code: "SESSION_INVALID",
            requestId
          },
          { status: 401 },
        ),
      )
    }
    
    // Advanced Security Layer 9: Permission Validation
    const permissionCheck = await PermissionValidator.checkPermission(
      decoded.userId as string,
      'profile:read',
      decoded.role as string
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: decoded.userId as string,
        details: { 
          permission: 'profile:read',
          role: decoded.role,
          clientIP, 
          requestId 
        },
        requestId
      })
      
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Insufficient permissions",
            code: "PERMISSION_DENIED",
            requestId
          },
          { status: 403 },
        ),
      )
    }
    
    // Advanced Security Layer 10: User Existence Verification
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId as string },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        avatar: true,
        phone: true,
        bio: true,
        createdAt: true,
        updatedAt: true,
        preferences: true,
        userProfile: true,
      },
    })
    
    if (!user) {
      await AuditLogger.log({
        event: 'USER_NOT_FOUND',
        level: 'MEDIUM',
        userId: decoded.userId as string,
        details: { clientIP, requestId },
        requestId
      })
      
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "User profile not found",
            code: "USER_NOT_FOUND",
            requestId
          },
          { status: 404 },
        ),
      )
    }
    
    // Advanced Security Layer 11: Data Encryption & Privacy Protection
    const encryptedUser = await DataEncryption.encryptSensitiveUserData(user, {
      fields: ['phone', 'email'],
      level: 'HIGH'
    })
    
    // Advanced Security Layer 12: Content Security Validation
    const sanitizedResponse = await ContentSecurity.sanitizeResponse({
      user: encryptedUser
    })
    
    // Advanced Security Layer 13: Cached Response with Encryption
    const cacheKey = `profile:${decoded.userId}:${user.updatedAt.getTime()}`
    const cachedResponse = await EncryptedCache.get(cacheKey)
    
    let responseData
    if (cachedResponse) {
      responseData = cachedResponse
    } else {
      responseData = {
        status: "success",
        data: { user: sanitizedResponse.user },
        message: "تم استرجاع الملف الشخصي بنجاح",
        metadata: {
          retrievedAt: new Date().toISOString(),
          requestId,
          encryptionLevel: 'HIGH'
        }
      }
      
      await EncryptedCache.set(cacheKey, responseData, 300) // 5 minutes
    }
    
    // Advanced Security Layer 14: Performance & Security Metrics
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/profile/me',
      method: 'GET',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: decoded.userId as string,
      requestId
    })
    
    // Advanced Security Layer 15: Audit Logging
    await AuditLogger.log({
      event: 'PROFILE_ACCESSED',
      level: 'LOW',
      userId: decoded.userId as string,
      details: {
        clientIP,
        userAgent,
        geoLocation,
        processingTime,
        threatAnalysis: threatAnalysis.summary,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Add security headers and return response
    const response = addSecurityHeaders(
      NextResponse.json(responseData, { status: 200 }),
    )
    
    // Additional security headers
    response.headers.set('X-Request-ID', requestId)
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'DENY')
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
    
    return response
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'PROFILE_ACCESS_ERROR',
      level: 'HIGH',
      userId: decoded?.userId as string || 'unknown',
      details: {
        error: error.message,
        stack: error.stack,
        clientIP,
        processingTime,
        requestId
      },
      requestId
    })
    
    SecurityEventEmitter.emit('security.system_error', {
      type: 'PROFILE_ACCESS_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    // Log security metrics
    await SecurityMetrics.recordRequest({
      endpoint: '/api/profile/me',
      method: 'GET',
      statusCode: 500,
      processingTime,
      userId: decoded?.userId as string || 'unknown',
      requestId
    })
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "error",
          message: "فشل في استرجاع الملف الشخصي",
          code: "PROFILE_ACCESS_ERROR",
          requestId
        },
        { status: 500 },
      ),
    )
  }
}