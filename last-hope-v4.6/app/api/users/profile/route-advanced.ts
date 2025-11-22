import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updateProfileSchema, changePasswordSchema } from "@/lib/validation"
import bcrypt from "bcryptjs"
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
import { ProfileSecurityManager } from "@/lib/security/profile-security-manager"
import { UserProfileProtector } from "@/lib/security/user-profile-protector"
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
      endpoint: '/api/users/profile',
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
    const rateLimiter = new AdvancedRateLimiter('profile_read')
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
      endpoint: '/api/users/profile',
      method: 'GET',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/users/profile'
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
      'profile:read',
      auth.payload.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          permission: 'profile:read',
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
    
    // Advanced Security Layer 9: User Status Verification
    const userStatus = await prisma.user.findUnique({
      where: { id: auth.payload.userId },
      select: { 
        id: true, 
        isActive: true,
        role: true
      }
    })
    
    if (!userStatus) {
      await AuditLogger.log({
        event: 'USER_NOT_FOUND',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "المستخدم غير موجود", "USER_NOT_FOUND"),
        { status: 404 }
      )
    }
    
    if (!userStatus.isActive) {
      await AuditLogger.log({
        event: 'INACTIVE_USER_ACCESS_ATTEMPT',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "الحساب غير نشط", "INACTIVE_ACCOUNT"),
        { status: 403 }
      )
    }
    
    // Advanced Security Layer 10: Secure User Data Retrieval
    const user = await prisma.user.findUnique({
      where: { id: auth.payload.userId },
      include: {
        preferences: true,
        loyaltyPoints: true,
        userProfile: true,
        blockInfo: true,
        _count: {
          select: {
            bookings: true,
            reviews: true,
            wishlist: true,
          },
        },
      },
    })
    
    if (!user) {
      await AuditLogger.log({
        event: 'PROFILE_DATA_NOT_FOUND',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { clientIP, requestId },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "بيانات الملف الشخصي غير موجودة", "PROFILE_NOT_FOUND"),
        { status: 404 }
      )
    }
    
    // Advanced Security Layer 11: Data Sanitization & Privacy Protection
    const sanitizedUser = await ProfileSecurityManager.sanitizeUserProfile(user, {
      removeSensitiveFields: true,
      maskPII: true,
      encryptSensitiveData: true
    })
    
    // Advanced Security Layer 12: Profile Data Encryption
    const protectedProfile = await UserProfileProtector.protectUserProfile(sanitizedUser, {
      level: 'HIGH',
      encryptFields: ['email', 'phone'],
      maskFields: ['firstName', 'lastName'],
      preserveForOwner: true // Allow user to see their own data
    })
    
    // Advanced Security Layer 13: Audit Logging
    await AuditLogger.log({
      event: 'USER_PROFILE_ACCESSED',
      level: 'LOW',
      userId: auth.payload.userId,
      details: {
        profileFieldsAccessed: Object.keys(protectedProfile),
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 14: Security Event Emission
    SecurityEventEmitter.emit('security.profile_accessed', {
      userId: auth.payload.userId,
      action: 'READ',
      dataClassification: 'PERSONAL',
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/users/profile',
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
          user: protectedProfile,
          metadata: {
            retrievedAt: new Date().toISOString(),
            requestId,
            encryptionLevel: 'HIGH',
            dataClassification: 'PERSONAL'
          }
        },
        "تم استرجاع ملف المستخدم بنجاح"
      ),
      { status: 200 }
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'GET_USER_PROFILE_ERROR',
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
      type: 'PROFILE_ACCESS_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return NextResponse.json(
      failResponse(null, error.message || "فشل في استرجاع ملف المستخدم", "FETCH_USER_ERROR"),
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
      endpoint: '/api/users/profile',
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
    const rateLimiter = new AdvancedRateLimiter('profile_update')
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
      endpoint: '/api/users/profile',
      method: 'PUT',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/users/profile'
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
      'profile:update',
      auth.payload.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          permission: 'profile:update',
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
      maxSize: 5000, // 5KB
      allowedFields: ['firstName', 'lastName', 'phone', 'bio', 'avatar'],
      requiredFields: []
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
    
    // Advanced Security Layer 10: Schema Validation
    let validated: any
    try {
      validated = updateProfileSchema.parse(inputValidation.sanitizedData)
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
    
    // Advanced Security Layer 11: Content Security Validation
    if (validated.firstName) {
      const nameValidation = await ContentSecurity.validateTextContent(validated.firstName, {
        maxLength: 50,
        allowedPatterns: ['name'],
        blockPatterns: ['malicious', 'inappropriate']
      })
      
      if (!nameValidation.isValid) {
        return NextResponse.json(
          failResponse(null, "الاسم الأول غير مناسب", "INVALID_FIRST_NAME"),
          { status: 400 }
        )
      }
    }
    
    if (validated.lastName) {
      const nameValidation = await ContentSecurity.validateTextContent(validated.lastName, {
        maxLength: 50,
        allowedPatterns: ['name'],
        blockPatterns: ['malicious', 'inappropriate']
      })
      
      if (!nameValidation.isValid) {
        return NextResponse.json(
          failResponse(null, "الاسم الأخير غير مناسب", "INVALID_LAST_NAME"),
          { status: 400 }
        )
      }
    }
    
    if (validated.bio) {
      const bioValidation = await ContentSecurity.validateTextContent(validated.bio, {
        maxLength: 500,
        allowedPatterns: ['text'],
        blockPatterns: ['malicious', 'inappropriate', 'spam']
      })
      
      if (!bioValidation.isValid) {
        return NextResponse.json(
          failResponse(null, "النبذة التعريفية غير مناسبة", "INVALID_BIO"),
          { status: 400 }
        )
      }
    }
    
    // Advanced Security Layer 12: Profile Update with Security
    const updateData: any = {}
    if (validated.firstName !== undefined) updateData.firstName = validated.firstName
    if (validated.lastName !== undefined) updateData.lastName = validated.lastName
    if (validated.phone !== undefined) updateData.phone = validated.phone
    if (validated.bio !== undefined) updateData.bio = validated.bio
    if (validated.avatar !== undefined) updateData.avatar = validated.avatar
    
    const updatedUser = await prisma.user.update({
      where: { id: auth.payload.userId },
      data: {
        ...updateData,
        updatedAt: new Date(),
        metadata: {
          lastModifiedBy: auth.payload.userId,
          requestId
        }
      },
      include: {
        preferences: true,
        loyaltyPoints: true,
        userProfile: true,
        _count: {
          select: {
            bookings: true,
            reviews: true,
            wishlist: true,
          },
        },
      },
    })
    
    // Advanced Security Layer 13: Data Sanitization for Response
    const sanitizedUser = await ProfileSecurityManager.sanitizeUserProfile(updatedUser, {
      removeSensitiveFields: true,
      maskPII: true,
      encryptSensitiveData: true
    })
    
    // Advanced Security Layer 14: Audit Logging
    await AuditLogger.log({
      event: 'USER_PROFILE_UPDATED',
      level: 'LOW',
      userId: auth.payload.userId,
      details: {
        updatedFields: Object.keys(updateData),
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 15: Security Event Emission
    SecurityEventEmitter.emit('security.profile_updated', {
      userId: auth.payload.userId,
      action: 'UPDATE',
      updatedFields: Object.keys(updateData),
      dataClassification: 'PERSONAL',
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/users/profile',
      method: 'PUT',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: auth.payload.userId,
      requestId
    })
    
    return NextResponse.json(
      successResponse(
        { 
          user: sanitizedUser,
          metadata: {
            updatedAt: new Date().toISOString(),
            requestId,
            encryptionLevel: 'HIGH',
            dataClassification: 'PERSONAL'
          }
        },
        "تم تحديث الملف الشخصي بنجاح"
      ),
      { status: 200 }
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'UPDATE_USER_PROFILE_ERROR',
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
      type: 'PROFILE_UPDATE_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return NextResponse.json(
      failResponse(null, error.message || "فشل في تحديث الملف الشخصي", "UPDATE_PROFILE_ERROR"),
      { status: 500 }
    )
  }
}

export async function PATCH(req: NextRequest) {
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
      method: 'PATCH',
      endpoint: '/api/users/profile',
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
    const rateLimiter = new AdvancedRateLimiter('profile_patch')
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
      endpoint: '/api/users/profile',
      method: 'PATCH',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/users/profile'
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
      'profile:patch',
      auth.payload.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          permission: 'profile:patch',
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
      maxSize: 10000, // 10KB
      allowedFields: ['action', 'currentPassword', 'newPassword', 'emailNotifications', 'smsNotifications', 'marketingEmails', 'preferredCurrency', 'language', 'profileImage', 'coverImage', 'bio', 'company', 'jobTitle', 'location', 'website', 'socialLinks'],
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
    
    const body = inputValidation.sanitizedData
    const { action, ...data } = body
    
    // Advanced Security Layer 10: Action Validation
    const allowedActions = ['change_password', 'update_preferences', 'update_profile']
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
    
    let result: any
    
    // Advanced Security Layer 11: Password Change with Enhanced Security
    if (action === 'change_password') {
      const passwordData = changePasswordSchema.parse(data)
      
      // Verify current password
      const user = await prisma.user.findUnique({
        where: { id: auth.payload.userId },
        select: { password: true },
      })
      
      if (!user) {
        await AuditLogger.log({
          event: 'USER_NOT_FOUND',
          level: 'MEDIUM',
          userId: auth.payload.userId,
          details: { clientIP, requestId },
          requestId
        })
        
        return NextResponse.json(
          failResponse(null, "المستخدم غير موجود", "USER_NOT_FOUND"),
          { status: 404 }
        )
      }
      
      const isCurrentPasswordValid = await bcrypt.compare(passwordData.currentPassword, user.password)
      if (!isCurrentPasswordValid) {
        await AuditLogger.log({
          event: 'INVALID_CURRENT_PASSWORD',
          level: 'MEDIUM',
          userId: auth.payload.userId,
          details: { clientIP, requestId },
          requestId
        })
        
        return NextResponse.json(
          failResponse(null, "كلمة المرور الحالية غير صحيحة", "INVALID_CURRENT_PASSWORD"),
          { status: 400 }
        )
      }
      
      // Hash new password with enhanced security
      const hashedNewPassword = await bcrypt.hash(passwordData.newPassword, 12)
      
      // Update password
      await prisma.user.update({
        where: { id: auth.payload.userId },
        data: {
          password: hashedNewPassword,
          updatedAt: new Date(),
          metadata: {
            passwordChangedAt: new Date().toISOString(),
            requestId
          }
        },
      })
      
      // Invalidate all other sessions
      await SessionManager.invalidateUserSessions(auth.payload.userId, auth.payload.userId)
      
      result = "تم تغيير كلمة المرور بنجاح"
      
    // Advanced Security Layer 12: Preferences Update with Security
    } else if (action === 'update_preferences') {
      const { 
        emailNotifications, 
        smsNotifications, 
        marketingEmails, 
        preferredCurrency, 
        language 
      } = data
      
      // Validate preferences
      if (preferredCurrency && !['USD', 'EUR', 'GBP', 'AED', 'SAR'].includes(preferredCurrency)) {
        return NextResponse.json(
          failResponse(null, "عملة غير صحيحة", "INVALID_CURRENCY"),
          { status: 400 }
        )
      }
      
      if (language && !['en', 'ar', 'es', 'fr', 'de'].includes(language)) {
        return NextResponse.json(
          failResponse(null, "لغة غير صحيحة", "INVALID_LANGUAGE"),
          { status: 400 }
        )
      }
      
      // Update or create user preferences
      const preferences = await prisma.userPreference.upsert({
        where: { userId: auth.payload.userId },
        update: {
          emailNotifications: emailNotifications ?? undefined,
          smsNotifications: smsNotifications ?? undefined,
          marketingEmails: marketingEmails ?? undefined,
          preferredCurrency: preferredCurrency ?? undefined,
          language: language ?? undefined,
          updatedAt: new Date(),
          metadata: {
            lastModifiedBy: auth.payload.userId,
            requestId
          }
        },
        create: {
          userId: auth.payload.userId,
          emailNotifications: emailNotifications ?? true,
          smsNotifications: smsNotifications ?? false,
          marketingEmails: marketingEmails ?? true,
          preferredCurrency: preferredCurrency ?? 'USD',
          language: language ?? 'en',
        },
      })
      
      result = { preferences }
      
    // Advanced Security Layer 13: Profile Update with Enhanced Security
    } else if (action === 'update_profile') {
      const { 
        profileImage, 
        coverImage, 
        bio, 
        company, 
        jobTitle, 
        location, 
        website, 
        socialLinks 
      } = data
      
      // Validate social links if provided
      if (socialLinks && typeof socialLinks === 'object') {
        const socialValidation = await ContentSecurity.validateSocialLinks(socialLinks)
        if (!socialValidation.isValid) {
          return NextResponse.json(
            failResponse(null, "روابط وسائل التواصل الاجتماعي غير صحيحة", "INVALID_SOCIAL_LINKS"),
            { status: 400 }
          )
        }
      }
      
      // Validate bio content
      if (bio) {
        const bioValidation = await ContentSecurity.validateTextContent(bio, {
          maxLength: 500,
          allowedPatterns: ['text'],
          blockPatterns: ['malicious', 'inappropriate', 'spam']
        })
        
        if (!bioValidation.isValid) {
          return NextResponse.json(
            failResponse(null, "النبذة التعريفية غير مناسبة", "INVALID_BIO"),
            { status: 400 }
          )
        }
      }
      
      // Update or create user profile
      const profile = await prisma.userProfile.upsert({
        where: { userId: auth.payload.userId },
        update: {
          profileImage: profileImage ?? undefined,
          coverImage: coverImage ?? undefined,
          bio: bio ?? undefined,
          company: company ?? undefined,
          jobTitle: jobTitle ?? undefined,
          location: location ?? undefined,
          website: website ?? undefined,
          socialLinks: socialLinks ? JSON.stringify(socialLinks) : undefined,
          updatedAt: new Date(),
          metadata: {
            lastModifiedBy: auth.payload.userId,
            requestId
          }
        },
        create: {
          userId: auth.payload.userId,
          profileImage: profileImage ?? null,
          coverImage: coverImage ?? null,
          bio: bio ?? null,
          company: company ?? null,
          jobTitle: jobTitle ?? null,
          location: location ?? null,
          website: website ?? null,
          socialLinks: socialLinks ? JSON.stringify(socialLinks) : null,
        },
      })
      
      result = { profile }
    }
    
    // Advanced Security Layer 14: Audit Logging
    await AuditLogger.log({
      event: 'USER_ACTION_EXECUTED',
      level: 'LOW',
      userId: auth.payload.userId,
      details: {
        action,
        dataFields: Object.keys(data),
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 15: Security Event Emission
    SecurityEventEmitter.emit('security.profile_action_executed', {
      userId: auth.payload.userId,
      action,
      dataClassification: 'PERSONAL',
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/users/profile',
      method: 'PATCH',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: auth.payload.userId,
      requestId
    })
    
    return NextResponse.json(
      successResponse(result, "تم تنفيذ العملية بنجاح"),
      { status: 200 }
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'USER_ACTION_ERROR',
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
      type: 'PROFILE_ACTION_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return NextResponse.json(
      failResponse(null, error.message || "فشلت العملية", "ACTION_ERROR"),
      { status: 500 }
    )
  }
}

export async function DELETE(req: NextRequest) {
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
      method: 'DELETE',
      endpoint: '/api/users/profile',
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
    
    // Advanced Security Layer 4: Enhanced Rate Limiting for Delete Operation
    const rateLimiter = new AdvancedRateLimiter('profile_delete')
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
      endpoint: '/api/users/profile',
      method: 'DELETE',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/users/profile'
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
      'profile:delete',
      auth.payload.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: auth.payload.userId,
        details: { 
          permission: 'profile:delete',
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
    
    // Advanced Security Layer 9: Active Bookings Check with Enhanced Security
    const activeBookings = await prisma.booking.count({
      where: {
        userId: auth.payload.userId,
        status: {
          in: ['PENDING', 'CONFIRMED', 'CHECKED_IN'],
        },
      },
    })
    
    if (activeBookings > 0) {
      await AuditLogger.log({
        event: 'DELETE_BLOCKED_ACTIVE_BOOKINGS',
        level: 'MEDIUM',
        userId: auth.payload.userId,
        details: { 
          activeBookings,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return NextResponse.json(
        failResponse(null, "لا يمكن حذف الحساب مع الحجوزات النشطة", "HAS_ACTIVE_BOOKINGS"),
        { status: 400 }
      )
    }
    
    // Advanced Security Layer 10: Soft Delete with Enhanced Security
    await prisma.user.update({
      where: { id: auth.payload.userId },
      data: {
        email: `deleted_${Date.now()}_${auth.payload.email}`,
        firstName: 'Deleted',
        lastName: 'User',
        password: '', // Remove password
        phone: null,
        bio: null,
        avatar: null,
        role: 'USER',
        isActive: false,
        deletedAt: new Date(),
        updatedAt: new Date(),
        metadata: {
          deletedAt: new Date().toISOString(),
          deletedBy: auth.payload.userId,
          deletionReason: 'USER_REQUEST',
          requestId
        }
      },
    })
    
    // Advanced Security Layer 11: Invalidate All Sessions
    await SessionManager.invalidateUserSessions(auth.payload.userId, auth.payload.userId)
    
    // Advanced Security Layer 12: Audit Logging
    await AuditLogger.log({
      event: 'USER_ACCOUNT_DELETED',
      level: 'HIGH',
      userId: auth.payload.userId,
      details: {
        deletionType: 'SOFT_DELETE',
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 13: Security Event Emission
    SecurityEventEmitter.emit('security.account_deleted', {
      userId: auth.payload.userId,
      action: 'DELETE',
      deletionType: 'SOFT_DELETE',
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/users/profile',
      method: 'DELETE',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: auth.payload.userId,
      requestId
    })
    
    return NextResponse.json(
      successResponse(null, "تم إلغاء تفعيل الحساب بنجاح"),
      { status: 200 }
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'DELETE_USER_ACCOUNT_ERROR',
      level: 'CRITICAL',
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
      type: 'ACCOUNT_DELETE_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    return NextResponse.json(
      failResponse(null, error.message || "فشل في حذف الحساب", "DELETE_ACCOUNT_ERROR"),
      { status: 500 }
    )
  }
}