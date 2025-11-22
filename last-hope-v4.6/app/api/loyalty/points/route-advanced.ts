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
import { SessionManager } from "@/lib/security/session-manager"
import { IPGeolocation } from "@/lib/security/ip-geolocation"
import { SecurityEventEmitter } from "@/lib/security/event-emitter"
import { LoyaltySecurityManager } from "@/lib/security/loyalty-security-manager"
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
      endpoint: '/api/loyalty/points',
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
    const rateLimiter = new AdvancedRateLimiter('loyalty_points_read')
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
      endpoint: '/api/loyalty/points',
      method: 'GET',
      timeOfDay: new Date().getHours(),
      userAgent
    })
    
    if (behavioralAnalysis.anomalyScore > 0.8) {
      SecurityEventEmitter.emit('security.behavioral_anomaly', {
        score: behavioralAnalysis.anomalyScore,
        source: clientIP,
        requestId,
        endpoint: '/api/loyalty/points'
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
      'loyalty:read',
      user.role
    )
    
    if (!permissionCheck.granted) {
      await AuditLogger.log({
        event: 'PERMISSION_DENIED',
        level: 'HIGH',
        userId: user.userId,
        details: { 
          permission: 'loyalty:read',
          role: user.role,
          clientIP,
          requestId 
        },
        requestId
      })
      
      return apiResponse.forbidden("صلاحيات غير كافية")
    }
    
    // Advanced Security Layer 9: User Status Verification
    const userStatus = await prisma.user.findUnique({
      where: { id: user.userId },
      select: { 
        id: true, 
        isActive: true,
        email: true,
        role: true
      }
    })
    
    if (!userStatus) {
      await AuditLogger.log({
        event: 'USER_NOT_FOUND',
        level: 'MEDIUM',
        userId: user.userId,
        details: { clientIP, requestId },
        requestId
      })
      
      return apiResponse.notFound("المستخدم غير موجود")
    }
    
    if (!userStatus.isActive) {
      await AuditLogger.log({
        event: 'INACTIVE_USER_ACCESS_ATTEMPT',
        level: 'MEDIUM',
        userId: user.userId,
        details: { clientIP, requestId },
        requestId
      })
      
      return apiResponse.forbidden("الحساب غير نشط")
    }
    
    // Advanced Security Layer 10: Loyalty Data Retrieval with Security
    const loyalty = await prisma.loyaltyPoint.findUnique({
      where: { userId: user.userId },
      include: {
        transactions: {
          orderBy: { createdAt: 'desc' },
          take: 10, // Security limit
          select: {
            id: true,
            points: true,
            type: true,
            description: true,
            createdAt: true,
            metadata: true
          }
        }
      }
    })
    
    // Advanced Security Layer 11: Default Loyalty Data if None Exists
    const loyaltyData = loyalty || { 
      points: 0, 
      tier: "BRONZE", 
      totalEarned: 0,
      transactions: []
    }
    
    // Advanced Security Layer 12: Loyalty Data Encryption & Protection
    const protectedLoyaltyData = await LoyaltySecurityManager.protectLoyaltyData(loyaltyData, {
      userId: user.userId,
      encryptPoints: true,
      maskSensitiveData: true,
      level: 'HIGH'
    })
    
    // Advanced Security Layer 13: Transaction Data Security
    const securedTransactions = await Promise.all(
      protectedLoyaltyData.transactions.map(async (transaction: any) => {
        return await LoyaltySecurityManager.secureTransactionData(transaction, {
          encryptDescription: true,
          maskMetadata: true
        })
      })
    )
    
    // Advanced Security Layer 14: Analytics & Insights (User's Own Data Only)
    const loyaltyAnalytics = await LoyaltySecurityManager.generateUserAnalytics(protectedLoyaltyData, {
      userId: user.userId,
      timeRange: 'ALL_TIME',
      includeProjections: false // Security: no projections for external API
    })
    
    // Advanced Security Layer 15: Audit Logging
    await AuditLogger.log({
      event: 'LOYALTY_POINTS_RETRIEVED',
      level: 'LOW',
      userId: user.userId,
      details: {
        currentPoints: protectedLoyaltyData.points,
        tier: protectedLoyaltyData.tier,
        totalEarned: protectedLoyaltyData.totalEarned,
        transactionCount: securedTransactions.length,
        clientIP,
        geoLocation,
        behavioralScore: behavioralAnalysis.anomalyScore,
        requestId
      },
      requestId
    })
    
    // Advanced Security Layer 16: Security Event Emission
    SecurityEventEmitter.emit('security.loyalty_data_accessed', {
      userId: user.userId,
      action: 'READ',
      pointsAccessed: protectedLoyaltyData.points,
      requestId
    })
    
    // Performance monitoring
    const processingTime = Date.now() - startTime
    await SecurityMetrics.recordRequest({
      endpoint: '/api/loyalty/points',
      method: 'GET',
      statusCode: 200,
      processingTime,
      threatLevel: threatAnalysis.threatLevel,
      userId: user.userId,
      requestId
    })
    
    // Return secured response
    return apiResponse.success(
      { 
        loyalty: {
          ...protectedLoyaltyData,
          transactions: securedTransactions,
          analytics: loyaltyAnalytics
        },
        metadata: {
          retrievedAt: new Date().toISOString(),
          requestId,
          encryptionLevel: 'HIGH',
          dataClassification: 'FINANCIAL',
          lastTransaction: loyalty?.transactions?.[0]?.createdAt || null
        }
      },
      "تم استرجاع نقاط الولاء بنجاح"
    )
    
  } catch (error: any) {
    // Advanced Security Error Handling
    const processingTime = Date.now() - startTime
    
    await AuditLogger.log({
      event: 'LOYALTY_POINTS_ERROR',
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
      type: 'LOYALTY_POINTS_FAILED',
      error: error.message,
      source: clientIP,
      requestId
    })
    
    // Log security metrics
    await SecurityMetrics.recordRequest({
      endpoint: '/api/loyalty/points',
      method: 'GET',
      statusCode: 500,
      processingTime,
      userId: user?.userId || 'unknown',
      requestId
    })
    
    return apiResponse.error(error.message || "فشل في استرجاع نقاط الولاء")
  }
}