import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { GuestDetailsService } from "@/lib/services/guest-details.service"
import { apiResponse } from "@/lib/api-response"
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
import { GuestDataProtector } from "@/lib/security/guest-data-protector"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  const requestId = RequestCorrelation.generateCorrelationId()
  const startTime = Date.now()
  
  // Initialize security context
  const clientIP = request.headers.get("x-forwarded-for") || request.ip || "unknown"
  const userAgent = request.headers.get("user-agent") || "unknown"
  const clientId = request.headers.get("x-client-id") || "unknown"
  
  try {
    // Advanced Security Layer 1: Request Correlation & Tracking
    RequestCorrelation.trackRequest(requestId, clientIP, userAgent, clientId)
    
    // Advanced Security Layer 2: IP Geolocation Analysis
    const geoLocation = await IPGeolocation.analyzeLocation(clientIP)
    
    // Advanced Security Layer 3: AI Threat Detection
    const threatAnalysis = await AIThreatDetection.analyzeRequest({
      method: 'POST',
      endpoint: '/api/guest-details',
      ip: clientIP,
      userAgent,
      headers: Object.fromEntries(request.headers.entries()),
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
      
      return apiResponse.forbidden("طلب محظور بسبب مخاوف أمنية")
    }
    
    // Advanced Security Layer 4: Rate Limiting with AI
    const rateLimiter = new AdvancedRateLimiter('guest_details_create')
    const rateLimitResult = await rateLimiter.checkLimit(clientIP, clientId)
    
    if (!rateLimitResult.allowed) {
      await AuditLogger.log({
        event: 'RATE_LIMIT_EXCEEDED',
        level: 'MEDIUM',
        userId: 'unknown',
        details: { rateLimitResult, clientIP, requestId },
        requestId
      })
      
      return apiResponse.tooManyRequests("تم تجاوز الحد المسموح من الطلبات")
    }
    
    // Advanced Security Layer 5: Behavioral Analysis
    const behavioralAnalysis = await BehavioralAnalysis.analyzeUserBehavior(clientIP, {
      endpoint: '/api/guest-details',
      method: 'POST',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/guest-details'
      })
    }
    
    // Advanced Security Layer 6: Input Validation & Sanitization
    const rawBody = await request.text()
    const inputValidation = await AdvancedInputValidator.validateAndSanitizeJSON(rawBody, {
      strictMode: true,
      maxSize: 10000, // 10KB
      allowedFields: [
        'bookingId', 'firstName', 'lastName', 'email', 'phone', 
        'passportNumber', 'nationality', 'dateOfBirth', 'address',
        'emergencyContact', 'dietaryRequirements', 'specialRequests'
      ],
      requiredFields: ['bookingId']
    })
    
    if (!inputValidation.isValid) {
      await AuditLogger.log({
        event: 'INPUT_VALIDATION_FAILED',
        level: 'MEDIUM',
        userId: 'unknown',
        details: { 
          validationErrors: inputValidation.errors,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.badRequest(`بيانات غير صحيحة: ${inputValidation.errors.join(', ')}`)
    }
    
    const { bookingId, ...data } = inputValidation.sanitizedData
    
    // Advanced Security Layer 7: Authorization Check
    const token = request.headers.get("Authorization")?.split(" ")[1]
    const decoded = token ? verifyToken(token) : null
    
    if (!decoded) {
      await AuditLogger.log({
        event: 'AUTHENTICATION_FAILED',
        level: 'HIGH',
        userId: 'unknown',
        details: { reason: 'INVALID_TOKEN', clientIP, requestId },
        requestId
      })
      
      return apiResponse.unauthorized("مطلوب تسجيل الدخول")
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
      
      return apiResponse.unauthorized("انتهت صلاحية الجلسة")
    }
    
    // Advanced Security Layer 9: Permission Validation
    const permissionCheck = await PermissionValidator.checkPermission(
      decoded.userId as string,
      'guest-details:write',
      decoded.role as string
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: decoded.userId as string,
        details: { 
          permission: 'guest-details:write',
          role: decoded.role,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.forbidden("صلاحيات غير كافية")
    }
    
    // Advanced Security Layer 10: Booking Ownership Verification
    const booking = await prisma.booking.findUnique({
      where: { id: bookingId },
      select: { id: true, userId: true, status: true }
    })
    
    if (!booking) {
      await AuditLogger.log({
        event: 'BOOKING_NOT_FOUND',
        level: 'MEDIUM',
        userId: decoded.userId as string,
        details: { bookingId, clientIP, requestId },
        requestId
      })
      
      return apiResponse.notFound("الحجز غير موجود")
    }
    
    if (booking.userId !== decoded.userId) {
      await AuditLogger.log({
        event: 'UNAUTHORIZED_BOOKING_ACCESS',
        level: 'HIGH',
        userId: decoded.userId as string,
        details: { 
          bookingId,
          actualOwner: booking.userId,
          requester: decoded.userId,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.forbidden("غير مسموح لك بتعديل هذا الحجز")
    }
    
    // Advanced Security Layer 11: Guest Data Protection & Encryption
    const protectedGuestData = await GuestDataProtector.protectGuestData(data, {
      encryptFields: ['passportNumber', 'email', 'phone', 'emergencyContact'],
      maskFields: ['firstName', 'lastName', 'address'],
      level: 'MAXIMUM'
    })
    
    // Advanced Security Layer 12: Content Security Validation
    const sanitizedData = await ContentSecurity.sanitizeGuestDetails(protectedGuestData)
    
    // Advanced Security Layer 13: Guest Details Service with Security
    const guestDetails = await GuestDetailsService.saveGuestDetails(
      bookingId, 
      decoded.userId as string, 
      sanitizedData,
      {
        auditRequestId: requestId,
        encryptSensitiveData: true,
        validateDataIntegrity: true
      }
    )
    
    // Advanced Security Layer 14: Audit Logging
    await AuditLogger.log({
      event: 'GUEST_DETAILS_SAVED',
      level: 'LOW',
      userId: decoded.userId as string,
      details: {
        bookingId,
        guestDetailsId: guestDetails.id,
        dataFields: Object.keys(data),
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 15: Security Event Emission
    SecurityEventEmitter.emit('security.guest_data_access', {
      userId: decoded.userId as string,
      bookingId,
      action: 'CREATE',
      dataClassification: 'SENSITIVE',
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/guest-details',
      method: 'POST',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: decoded.userId as string,
      requestId
    })
    
    // Return success response
    return apiResponse.success(
      { 
        guestDetails,
        metadata: {
          savedAt: new Date().toISOString(),
          requestId,
          dataClassification: 'SENSITIVE',
          encryptionLevel: 'MAXIMUM'
        }
      },
      "تم حفظ بيانات النزيل بنجاح"
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'GUEST_DETAILS_ERROR',
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
      type: 'GUEST_DETAILS_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    // Log security metrics
    await SecurityMetrics.recordRequest({
      endpoint: '/api/guest-details',
      method: 'POST',
      statusCode: 500,
      processingTime,
      userId: decoded?.userId as string || 'unknown',
      requestId
    })
    
    return apiResponse.error(error.message || "فشل في حفظ بيانات النزيل")
  }
}