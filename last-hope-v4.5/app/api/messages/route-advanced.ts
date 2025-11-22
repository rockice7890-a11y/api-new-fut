import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { prisma } from "@/lib/prisma"
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
import { MessageSecurityManager } from "@/lib/security/message-security-manager"
import { SecurityMetrics } from "@/lib/security/security-metrics"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
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
      method: 'GET',
      endpoint: '/api/messages',
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
    const rateLimiter = new AdvancedRateLimiter('messages_read')
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
      endpoint: '/api/messages',
      method: 'GET',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/messages'
      })
    }
    
    // Advanced Security Layer 6: Authorization & Authentication
    const user = await authenticateRequest(request)
    if (!user) {
      await AuditLogger.log({
        event: 'AUTHENTICATION_FAILED',
        level: 'HIGH',
        userId: 'unknown',
        details: { reason: 'INVALID_TOKEN', clientIP, requestId },
        requestId
      })
      
      return apiResponse.unauthorized("مطلوب تسجيل الدخول")
    }
    
    // Advanced Security Layer 7: Session Validation
    const sessionValid = await SessionManager.validateSession(user.userId, user.token)
    if (!sessionValid) {
      await AuditLogger.log({
        event: 'SESSION_INVALID',
        level: 'HIGH',
        userId: user.userId,
        details: { reason: 'SESSION_EXPIRED', clientIP, requestId },
        requestId
      })
      
      return apiResponse.unauthorized("انتهت صلاحية الجلسة")
    }
    
    // Advanced Security Layer 8: Permission Validation
    const permissionCheck = await PermissionValidator.checkPermission(
      user.userId,
      'messages:read',
      user.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: user.userId,
        details: { 
          permission: 'messages:read',
          role: user.role,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.forbidden("صلاحيات غير كافية")
    }
    
    // Advanced Security Layer 9: Input Validation & Sanitization
    const bookingId = request.nextUrl.searchParams.get("bookingId")
    
    if (bookingId) {
      const inputValidation = await AdvancedInputValidator.validateBookingId(bookingId)
      if (!inputValidation.isValid) {
        await AuditLogger.log({
          event: 'INPUT_VALIDATION_FAILED',
          level: 'MEDIUM',
          userId: user.userId,
          details: { 
            validationErrors: inputValidation.errors,
            bookingId,
            clientIP,
            requestId 
          },
          requestId
        })
        
        return apiResponse.badRequest("معرف حجز غير صحيح")
      }
    }
    
    // Advanced Security Layer 10: Data Access Control
    let whereClause: any = {}
    
    if (bookingId) {
      // Verify booking ownership
      const booking = await prisma.booking.findUnique({
        where: { id: bookingId },
        select: { id: true, userId: true }
      })
      
      if (!booking) {
        await AuditLogger.log({
          event: 'BOOKING_NOT_FOUND',
          level: 'MEDIUM',
          userId: user.userId,
          details: { bookingId, clientIP, requestId },
          requestId
        })
        
        return apiResponse.notFound("الحجز غير موجود")
      }
      
      if (booking.userId !== user.userId) {
        await AuditLogger.log({
          event: 'UNAUTHORIZED_BOOKING_ACCESS',
          level: 'HIGH',
          userId: user.userId,
          details: { 
            bookingId,
            actualOwner: booking.userId,
            requester: user.userId,
            clientIP,
            requestId 
          },
          requestId
        })
        
        return apiResponse.forbidden("غير مسموح لك بالوصول إلى رسائل هذا الحجز")
      }
      
      whereClause.bookingId = bookingId
    }
    
    // Add user-based filtering
    whereClause.OR = [{ userId: user.userId }]
    
    // Advanced Security Layer 11: Message Security Filtering
    const secureWhereClause = await MessageSecurityManager.applyMessageFilters(whereClause, user.userId)
    
    // Advanced Security Layer 12: Encrypted Data Retrieval
    const encryptedMessages = await prisma.message.findMany({
      where: secureWhereClause,
      include: { 
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            role: true
          }
        },
        hotel: {
          select: {
            id: true,
            name: true
          }
        }
      },
      orderBy: { createdAt: "asc" },
      take: 100, // Security limit
    })
    
    // Advanced Security Layer 13: Message Content Decryption & Sanitization
    const sanitizedMessages = await Promise.all(
      encryptedMessages.map(async (message) => {
        const decryptedMessage = await MessageSecurityManager.decryptMessageContent(message)
        return MessageSecurityManager.sanitizeMessageForDisplay(decryptedMessage)
      })
    )
    
    // Advanced Security Layer 14: Audit Logging
    await AuditLogger.log({
      event: 'MESSAGES_RETRIEVED',
      level: 'LOW',
      userId: user.userId,
      details: {
        messageCount: sanitizedMessages.length,
        bookingId: bookingId || null,
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 15: Security Event Emission
    SecurityEventEmitter.emit('security.messages_accessed', {
      userId: user.userId,
      bookingId: bookingId || null,
      action: 'READ',
      messageCount: sanitizedMessages.length,
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/messages',
      method: 'GET',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: user.userId,
      requestId
    })
    
    return apiResponse.success(
      { 
        messages: sanitizedMessages,
        metadata: {
          retrievedAt: new Date().toISOString(),
          requestId,
          totalMessages: sanitizedMessages.length,
          encryptionLevel: 'HIGH'
        }
      },
      "تم استرجاع الرسائل بنجاح"
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'MESSAGES_READ_ERROR',
      level: 'HIGH',
      userId: user?.userId || 'unknown',
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
      type: 'MESSAGES_READ_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return apiResponse.error(error.message || "فشل في استرجاع الرسائل")
  }
}

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
      endpoint: '/api/messages',
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
    const rateLimiter = new AdvancedRateLimiter('messages_create')
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
      endpoint: '/api/messages',
      method: 'POST',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/messages'
      })
    }
    
    // Advanced Security Layer 6: Authorization & Authentication
    const user = await authenticateRequest(request)
    if (!user) {
      await AuditLogger.log({
        event: 'AUTHENTICATION_FAILED',
        level: 'HIGH',
        userId: 'unknown',
        details: { reason: 'INVALID_TOKEN', clientIP, requestId },
        requestId
      })
      
      return apiResponse.unauthorized("مطلوب تسجيل الدخول")
    }
    
    // Advanced Security Layer 7: Session Validation
    const sessionValid = await SessionManager.validateSession(user.userId, user.token)
    if (!sessionValid) {
      await AuditLogger.log({
        event: 'SESSION_INVALID',
        level: 'HIGH',
        userId: user.userId,
        details: { reason: 'SESSION_EXPIRED', clientIP, requestId },
        requestId
      })
      
      return apiResponse.unauthorized("انتهت صلاحية الجلسة")
    }
    
    // Advanced Security Layer 8: Permission Validation
    const permissionCheck = await PermissionValidator.checkPermission(
      user.userId,
      'messages:write',
      user.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: user.userId,
        details: { 
          permission: 'messages:write',
          role: user.role,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.forbidden("صلاحيات غير كافية")
    }
    
    // Advanced Security Layer 9: Input Validation & Sanitization
    const rawBody = await request.text()
    const inputValidation = await AdvancedInputValidator.validateAndSanitizeJSON(rawBody, {
      strictMode: true,
      maxSize: 5000, // 5KB
      allowedFields: ['hotelId', 'bookingId', 'message', 'senderType'],
      requiredFields: ['hotelId', 'message']
    })
    
    if (!inputValidation.isValid) {
      await AuditLogger.log({
        event: 'INPUT_VALIDATION_FAILED',
        level: 'MEDIUM',
        userId: user.userId,
        details: { 
          validationErrors: inputValidation.errors,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.badRequest(`بيانات غير صحيحة: ${inputValidation.errors.join(', ')}`)
    }
    
    const { hotelId, bookingId, message, senderType } = inputValidation.sanitizedData
    
    // Advanced Security Layer 10: Content Security Validation
    const contentValidation = await ContentSecurity.validateMessageContent(message)
    if (!contentValidation.isValid) {
      await AuditLogger.log({
        event: 'CONTENT_BLOCKED',
        level: 'HIGH',
        userId: user.userId,
        details: { 
          reason: 'INAPPROPRIATE_CONTENT',
          violations: contentValidation.violations,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.badRequest("المحتوى المرسل غير مناسب")
    }
    
    // Advanced Security Layer 11: Authorization Checks
    if (bookingId) {
      // Verify booking ownership
      const booking = await prisma.booking.findUnique({
        where: { id: bookingId },
        select: { id: true, userId: true }
      })
      
      if (!booking) {
        await AuditLogger.log({
          event: 'BOOKING_NOT_FOUND',
          level: 'MEDIUM',
          userId: user.userId,
          details: { bookingId, clientIP, requestId },
          requestId
        })
        
        return apiResponse.notFound("الحجز غير موجود")
      }
      
      if (booking.userId !== user.userId) {
        await AuditLogger.log({
          event: 'UNAUTHORIZED_BOOKING_ACCESS',
          level: 'HIGH',
          userId: user.userId,
          details: { 
            bookingId,
            actualOwner: booking.userId,
            requester: user.userId,
            clientIP,
            requestId 
          },
          requestId
        })
        
        return apiResponse.forbidden("غير مسموح لك بإرسال رسائل لهذا الحجز")
      }
    }
    
    // Advanced Security Layer 12: Hotel Access Verification
    const hotel = await prisma.hotel.findUnique({
      where: { id: hotelId },
      select: { id: true, name: true, status: true }
    })
    
    if (!hotel) {
      await AuditLogger.log({
        event: 'HOTEL_NOT_FOUND',
        level: 'MEDIUM',
        userId: user.userId,
        details: { hotelId, clientIP, requestId },
        requestId
      })
      
      return apiResponse.notFound("الفندق غير موجود")
    }
    
    if (hotel.status !== 'ACTIVE') {
      await AuditLogger.log({
        event: 'HOTEL_INACTIVE_ACCESS_ATTEMPT',
        level: 'MEDIUM',
        userId: user.userId,
        details: { hotelId, hotelStatus: hotel.status, clientIP, requestId },
        requestId
      })
      
      return apiResponse.forbidden("الفندق غير نشط")
    }
    
    // Advanced Security Layer 13: Message Content Encryption & Security
    const secureMessage = await MessageSecurityManager.encryptAndSecureMessage({
      content: message,
      userId: user.userId,
      hotelId,
      bookingId,
      senderType: senderType || "USER",
      requestId
    })
    
    // Advanced Security Layer 14: Secure Message Creation
    const newMessage = await prisma.message.create({
      data: {
        userId: user.userId,
        hotelId,
        bookingId,
        message: secureMessage.encryptedContent,
        senderType: secureMessage.senderType,
        metadata: {
          requestId,
          encrypted: true,
          securityLevel: 'HIGH',
          contentHash: secureMessage.contentHash
        }
      },
      include: { 
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            role: true
          }
        },
        hotel: {
          select: {
            id: true,
            name: true
          }
        }
      },
    })
    
    // Advanced Security Layer 15: Decrypt Message for Response
    const decryptedResponse = await MessageSecurityManager.decryptMessageContent(newMessage)
    
    // Advanced Security Layer 16: Audit Logging
    await AuditLogger.log({
      event: 'MESSAGE_SENT',
      level: 'LOW',
      userId: user.userId,
      details: {
        messageId: newMessage.id,
        hotelId,
        bookingId,
        messageLength: message.length,
        contentHash: secureMessage.contentHash,
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 17: Security Event Emission
    SecurityEventEmitter.emit('security.message_sent', {
      userId: user.userId,
      hotelId,
      bookingId: bookingId || null,
      action: 'CREATE',
      messageClassification: 'COMMUNICATION',
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/messages',
      method: 'POST',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: user.userId,
      requestId
    })
    
    return apiResponse.success(
      { 
        message: decryptedResponse,
        metadata: {
          sentAt: new Date().toISOString(),
          requestId,
          encryptionLevel: 'HIGH',
          contentClassification: 'COMMUNICATION'
        }
      },
      "تم إرسال الرسالة بنجاح"
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'MESSAGE_SEND_ERROR',
      level: 'HIGH',
      userId: user?.userId || 'unknown',
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
      type: 'MESSAGE_SEND_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return apiResponse.error(error.message || "فشل في إرسال الرسالة")
  }
}