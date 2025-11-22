import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createNotificationSchema } from "@/lib/validation"
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
import { NotificationSecurityManager } from "@/lib/security/notification-security-manager"
import { SecurityMetrics } from "@/lib/security/security-metrics"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
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
      method: 'POST',
      endpoint: '/api/notifications',
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
      
      return NextResponse.json(
        failResponse(null, "طلب محظور بسبب مخاوف أمنية", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }
    
    // Advanced Security Layer 4: Rate Limiting with AI
    const rateLimiter = new AdvancedRateLimiter('notifications_admin_create')
    const rateLimitResult = await rateLimiter.checkLimit(clientIP, clientId)
    
    if (!rateLimitResult.allowed) {
      await AuditLogger.log({
        event: 'RATE_LIMIT_EXCEEDED',
        level: 'MEDIUM',
        userId: 'unknown',
        details: { rateLimitResult, clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "تم تجاوز الحد المسموح من الطلبات", "RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }
    
    // Advanced Security Layer 5: Behavioral Analysis
    const behavioralAnalysis = await BehavioralAnalysis.analyzeUserBehavior(clientIP, {
      endpoint: '/api/notifications',
      method: 'POST',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/notifications'
      })
    }
    
    // Advanced Security Layer 6: Authorization & Authentication
    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!
    
    // Advanced Security Layer 7: Enhanced Permission Validation
    const permissionCheck = await PermissionValidator.checkPermission(
      auth.payload.userId,
      'notifications:admin:create',
      auth.payload.role
    )
    
    // Only admins and hotel managers can create notifications
    if (!permissionCheck.granted || !['ADMIN', 'HOTEL_MANAGER'].includes(auth.payload.role)) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          permission: 'notifications:admin:create',
          role: auth.payload.role,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "صلاحيات غير كافية لإنشاء الإشعارات", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }
    
    // Advanced Security Layer 8: Input Validation & Sanitization
    const rawBody = await req.text()
    const inputValidation = await AdvancedInputValidator.validateAndSanitizeJSON(rawBody, {
      strictMode: true,
      maxSize: 2000, // 2KB
      allowedFields: ['userId', 'type', 'title', 'message', 'data'],
      requiredFields: ['userId', 'type', 'title', 'message']
    })
    
    if (!inputValidation.isValid) {
      await AuditLogger.log({
        event: 'INPUT_VALIDATION_FAILED',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { 
          validationErrors: inputValidation.errors,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, `بيانات غير صحيحة: ${inputValidation.errors.join(', ')}`, "INVALID_INPUT"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 9: Schema Validation
    const body = inputValidation.sanitizedData
    let validated: any
    try {
      validated = createNotificationSchema.parse(body)
    } catch (error: any) {
      await AuditLogger.log({
        event: 'SCHEMA_VALIDATION_FAILED',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { 
          schemaErrors: error.errors,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "بيانات غير متطابقة مع المخطط المطلوب", "SCHEMA_VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 10: Content Security Validation
    const titleValidation = await ContentSecurity.validateTextContent(validated.title, {
      maxLength: 100,
      allowedPatterns: ['text'],
      blockPatterns: ['spam', 'malicious']
    })
    
    const messageValidation = await ContentSecurity.validateTextContent(validated.message, {
      maxLength: 500,
      allowedPatterns: ['text'],
      blockPatterns: ['spam', 'malicious', 'inappropriate']
    })
    
    if (!titleValidation.isValid || !messageValidation.isValid) {
      await AuditLogger.log({
        event: 'CONTENT_BLOCKED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          reason: 'INAPPROPRIATE_CONTENT',
          titleViolations: titleValidation.violations,
          messageViolations: messageValidation.violations,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "المحتوى المرسل غير مناسب", "CONTENT_BLOCKED"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 11: User Existence & Status Check
    const targetUser = await prisma.user.findUnique({
      where: { id: validated.userId },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        role: true,
        isActive: true
      }
    })
    
    if (!targetUser) {
      await AuditLogger.log({
        event: 'USER_NOT_FOUND',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { 
          targetUserId: validated.userId,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "المستخدم المحدد غير موجود", "TARGET_USER_NOT_FOUND"),
        { status: 404 }
      )
    }
    
    if (!targetUser.isActive) {
      await AuditLogger.log({
        event: 'INACTIVE_USER_TARGET',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { 
          targetUserId: validated.userId,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "لا يمكن إرسال إشعارات للمستخدمين غير النشطين", "INACTIVE_USER"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 12: Notification Security & Encryption
    const secureNotification = await NotificationSecurityManager.createSecureNotification({
      ...validated,
      createdBy: auth.payload.userId,
      requestId
    })
    
    // Advanced Security Layer 13: Create Notification with Security
    const notification = await prisma.notification.create({
      data: {
        userId: validated.userId,
        type: secureNotification.type,
        title: secureNotification.encryptedTitle,
        message: secureNotification.encryptedMessage,
        data: secureNotification.encryptedData,
        metadata: {
          requestId,
          createdBy: auth.payload.userId,
          encrypted: true,
          securityLevel: 'HIGH',
          contentHash: secureNotification.contentHash
        }
      },
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
            email: true,
          },
        },
      },
    })
    
    // Advanced Security Layer 14: Decrypt for Response
    const decryptedNotification = await NotificationSecurityManager.decryptNotification(notification)
    
    // Advanced Security Layer 15: Audit Logging
    await AuditLogger.log({
      event: 'NOTIFICATION_CREATED',
      level: 'LOW',
      userId: auth.payload.userId,
      details: {
        notificationId: notification.id,
        targetUserId: validated.userId,
        notificationType: validated.type,
        titleLength: validated.title.length,
        messageLength: validated.message.length,
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 16: Security Event Emission
    SecurityEventEmitter.emit('security.notification_created', {
      createdBy: auth.payload.userId,
      targetUserId: validated.userId,
      type: validated.type,
      action: 'CREATE',
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/notifications',
      method: 'POST',
      statusCode: 201,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: auth.payload.userId,
      requestId
    })
    
    return NextResponse.json(
      successResponse(
        { 
          notification: decryptedNotification,
          metadata: {
            createdAt: new Date().toISOString(),
            requestId,
            encryptionLevel: 'HIGH',
            contentClassification: 'SYSTEM_NOTIFICATION'
          }
        },
        "تم إنشاء الإشعار بنجاح"
      ),
      { status: 201 }
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'CREATE_NOTIFICATION_ERROR',
      level: 'HIGH',
      userId: auth?.payload?.userId || 'unknown',
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
      type: 'NOTIFICATION_CREATE_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return NextResponse.json(
      failResponse(null, error.message || "فشل في إنشاء الإشعار", "CREATE_NOTIFICATION_ERROR"),
      { status: 500 }
    )
  }
}

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
      endpoint: '/api/notifications',
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
      
      return NextResponse.json(
        failResponse(null, "طلب محظور بسبب مخاوف أمنية", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }
    
    // Advanced Security Layer 4: Rate Limiting with AI
    const rateLimiter = new AdvancedRateLimiter('notifications_read')
    const rateLimitResult = await rateLimiter.checkLimit(clientIP, clientId)
    
    if (!rateLimitResult.allowed) {
      await AuditLogger.log({
        event: 'RATE_LIMIT_EXCEEDED',
        level: 'MEDIUM',
        userId: 'unknown',
        details: { rateLimitResult, clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "تم تجاوز الحد المسموح من الطلبات", "RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }
    
    // Advanced Security Layer 5: Behavioral Analysis
    const behavioralAnalysis = await BehavioralAnalysis.analyzeUserBehavior(clientIP, {
      endpoint: '/api/notifications',
      method: 'GET',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/notifications'
      })
    }
    
    // Advanced Security Layer 6: Authorization & Authentication
    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!
    
    // Advanced Security Layer 7: Session Validation
    const sessionValid = await SessionManager.validateSession(auth.payload.userId, auth.token)
    if (!sessionValid) {
      await AuditLogger.log({
        event: 'SESSION_INVALID',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { reason: 'SESSION_EXPIRED', clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "انتهت صلاحية الجلسة", "SESSION_INVALID"),
        { status: 401 }
      )
    }
    
    // Advanced Security Layer 8: Permission Validation
    const permissionCheck = await PermissionValidator.checkPermission(
      auth.payload.userId,
      'notifications:read',
      auth.payload.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          permission: 'notifications:read',
          role: auth.payload.role,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "صلاحيات غير كافية", "PERMISSION_DENIED"),
        { status: 403 }
      )
    }
    
    // Advanced Security Layer 9: Input Validation & Sanitization
    const searchParams = req.nextUrl.searchParams
    const type = searchParams.get("type")
    const isRead = searchParams.get("read")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Number.parseInt(searchParams.get("pageSize") || "20")
    
    // Validate pagination parameters
    if (page < 1 || page > 1000) {
      return NextResponse.json(
        failResponse(null, "رقم الصفحة غير صحيح", "INVALID_PAGE"),
        { status: 400 }
      )
    }
    
    if (pageSize < 1 || pageSize > 100) {
      return NextResponse.json(
        failResponse(null, "حجم الصفحة غير صحيح", "INVALID_PAGE_SIZE"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 10: Data Access Control
    const where: any = { userId: auth.payload.userId }
    if (type) {
      const typeValidation = await AdvancedInputValidator.validateNotificationType(type)
      if (!typeValidation.isValid) {
        return NextResponse.json(
          failResponse(null, "نوع الإشعار غير صحيح", "INVALID_NOTIFICATION_TYPE"),
          { status: 400 }
        )
      }
      where.type = type
    }
    if (isRead !== null) {
      const isReadBool = isRead === 'true'
      if (isRead !== 'true' && isRead !== 'false') {
        return NextResponse.json(
          failResponse(null, "قيمة القراءة غير صحيحة", "INVALID_READ_VALUE"),
          { status: 400 }
        )
      }
      where.read = isReadBool
    }
    
    // Advanced Security Layer 11: Secure Data Retrieval
    const notifications = await prisma.notification.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })
    
    // Advanced Security Layer 12: Decrypt and Sanitize Notifications
    const decryptedNotifications = await Promise.all(
      notifications.map(async (notification) => {
        const decrypted = await NotificationSecurityManager.decryptNotification(notification)
        return NotificationSecurityManager.sanitizeNotificationForDisplay(decrypted)
      })
    )
    
    // Advanced Security Layer 13: Count Statistics
    const total = await prisma.notification.count({ where })
    const unreadCount = await prisma.notification.count({
      where: {
        userId: auth.payload.userId,
        read: false,
      },
    })
    
    // Advanced Security Layer 14: Audit Logging
    await AuditLogger.log({
      event: 'NOTIFICATIONS_RETRIEVED',
      level: 'LOW',
      userId: auth.payload.userId,
      details: {
        notificationCount: decryptedNotifications.length,
        totalCount: total,
        unreadCount,
        type: type || 'all',
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 15: Security Event Emission
    SecurityEventEmitter.emit('security.notifications_accessed', {
      userId: auth.payload.userId,
      action: 'READ',
      notificationCount: decryptedNotifications.length,
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/notifications',
      method: 'GET',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: auth.payload.userId,
      requestId
    })
    
    return NextResponse.json(
      successResponse(
        {
          notifications: decryptedNotifications,
          total,
          unreadCount,
          page,
          pageSize,
          hasMore: (page * pageSize) < total,
          metadata: {
            retrievedAt: new Date().toISOString(),
            requestId,
            encryptionLevel: 'HIGH',
            totalRecords: total,
            currentPage: page
          }
        },
        "تم استرجاع الإشعارات بنجاح"
      ),
      { status: 200 }
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'GET_NOTIFICATIONS_ERROR',
      level: 'HIGH',
      userId: auth?.payload?.userId || 'unknown',
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
      type: 'NOTIFICATIONS_FETCH_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return NextResponse.json(
      failResponse(null, error.message || "فشل في استرجاع الإشعارات", "FETCH_NOTIFICATIONS_ERROR"),
      { status: 500 }
    )
  }
}

export async function PUT(req: NextRequest) {
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
      method: 'PUT',
      endpoint: '/api/notifications',
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
      
      return NextResponse.json(
        failResponse(null, "طلب محظور بسبب مخاوف أمنية", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }
    
    // Advanced Security Layer 4: Rate Limiting with AI
    const rateLimiter = new AdvancedRateLimiter('notifications_update')
    const rateLimitResult = await rateLimiter.checkLimit(clientIP, clientId)
    
    if (!rateLimitResult.allowed) {
      await AuditLogger.log({
        event: 'RATE_LIMIT_EXCEEDED',
        level: 'MEDIUM',
        userId: 'unknown',
        details: { rateLimitResult, clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "تم تجاوز الحد المسموح من الطلبات", "RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }
    
    // Advanced Security Layer 5: Behavioral Analysis
    const behavioralAnalysis = await BehavioralAnalysis.analyzeUserBehavior(clientIP, {
      endpoint: '/api/notifications',
      method: 'PUT',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/notifications'
      })
    }
    
    // Advanced Security Layer 6: Authorization & Authentication
    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!
    
    // Advanced Security Layer 7: Session Validation
    const sessionValid = await SessionManager.validateSession(auth.payload.userId, auth.token)
    if (!sessionValid) {
      await AuditLogger.log({
        event: 'SESSION_INVALID',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { reason: 'SESSION_EXPIRED', clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "انتهت صلاحية الجلسة", "SESSION_INVALID"),
        { status: 401 }
      )
    }
    
    // Advanced Security Layer 8: Permission Validation
    const permissionCheck = await PermissionValidator.checkPermission(
      auth.payload.userId,
      'notifications:update',
      auth.payload.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          permission: 'notifications:update',
          role: auth.payload.role,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "صلاحيات غير كافية", "PERMISSION_DENIED"),
        { status: 403 }
      )
    }
    
    // Advanced Security Layer 9: Input Validation & Sanitization
    const rawBody = await req.text()
    const inputValidation = await AdvancedInputValidator.validateAndSanitizeJSON(rawBody, {
      strictMode: true,
      maxSize: 1000, // 1KB
      allowedFields: ['action', 'notificationIds'],
      requiredFields: ['action']
    })
    
    if (!inputValidation.isValid) {
      await AuditLogger.log({
        event: 'INPUT_VALIDATION_FAILED',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { 
          validationErrors: inputValidation.errors,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, `بيانات غير صحيحة: ${inputValidation.errors.join(', ')}`, "INVALID_INPUT"),
        { status: 400 }
      )
    }
    
    const { action, notificationIds } = inputValidation.sanitizedData
    
    // Advanced Security Layer 10: Action Validation
    const allowedActions = ['mark_all_read', 'mark_selected_read', 'delete_selected', 'delete_all']
    if (!allowedActions.includes(action)) {
      await AuditLogger.log({
        event: 'INVALID_ACTION',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { 
          action,
          allowedActions,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "عملية غير صحيحة", "INVALID_ACTION"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 11: Notification ID Validation
    if ((action === 'mark_selected_read' || action === 'delete_selected') && 
        (!notificationIds || !Array.isArray(notificationIds) || notificationIds.length === 0)) {
      return NextResponse.json(
        failResponse(null, "معرفات الإشعارات مطلوبة", "NOTIFICATION_IDS_REQUIRED"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 12: Notification Ownership Verification
    if (notificationIds && Array.isArray(notificationIds)) {
      // Verify all notification IDs belong to the authenticated user
      const userNotifications = await prisma.notification.findMany({
        where: {
          id: { in: notificationIds },
          userId: auth.payload.userId
        },
        select: { id: true }
      })
      
      if (userNotifications.length !== notificationIds.length) {
        await AuditLogger.log({
          event: 'UNAUTHORIZED_NOTIFICATION_ACCESS',
          level: 'HIGH',
          userId: auth.payload.userId,
          details: { 
            requestedIds: notificationIds,
            authorizedIds: userNotifications.map(n => n.id),
            clientIP,
            requestId 
          },
          requestId
        })
        
        return NextResponse.json(
          failResponse(null, "بعض الإشعارات غير مملوكة لك", "UNAUTHORIZED_NOTIFICATIONS"),
          { status: 403 }
        )
      }
    }
    
    // Advanced Security Layer 13: Action Execution with Security
    let result: any
    
    switch (action) {
      case 'mark_all_read':
        await prisma.notification.updateMany({
          where: {
            userId: auth.payload.userId,
            read: false,
          },
          data: {
            read: true,
            metadata: {
              updatedAt: new Date().toISOString(),
              updatedBy: auth.payload.userId,
              requestId
            }
          },
        })
        
        result = "تم تحديد جميع الإشعارات كمقروءة"
        break
        
      case 'mark_selected_read':
        await prisma.notification.updateMany({
          where: {
            id: { in: notificationIds },
            userId: auth.payload.userId,
          },
          data: {
            read: true,
            metadata: {
              updatedAt: new Date().toISOString(),
              updatedBy: auth.payload.userId,
              requestId
            }
          },
        })
        
        result = "تم تحديد الإشعارات المحددة كمقروءة"
        break
        
      case 'delete_selected':
        await prisma.notification.deleteMany({
          where: {
            id: { in: notificationIds },
            userId: auth.payload.userId,
          },
        })
        
        result = "تم حذف الإشعارات المحددة"
        break
        
      case 'delete_all':
        await prisma.notification.deleteMany({
          where: {
            userId: auth.payload.userId,
          },
        })
        
        result = "تم حذف جميع الإشعارات"
        break
    }
    
    // Advanced Security Layer 14: Audit Logging
    await AuditLogger.log({
      event: 'NOTIFICATIONS_UPDATED',
      level: 'LOW',
      userId: auth.payload.userId,
      details: {
        action,
        notificationIds: notificationIds || null,
        notificationCount: notificationIds?.length || 'ALL',
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 15: Security Event Emission
    SecurityEventEmitter.emit('security.notifications_updated', {
      userId: auth.payload.userId,
      action,
      notificationIds: notificationIds || null,
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/notifications',
      method: 'PUT',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: auth.payload.userId,
      requestId
    })
    
    return NextResponse.json(
      successResponse(null, result),
      { status: 200 }
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'UPDATE_NOTIFICATIONS_ERROR',
      level: 'HIGH',
      userId: auth?.payload?.userId || 'unknown',
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
      type: 'NOTIFICATIONS_UPDATE_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return NextResponse.json(
      failResponse(null, error.message || "فشل في تحديث الإشعارات", "UPDATE_NOTIFICATIONS_ERROR"),
      { status: 500 }
    )
  }
}