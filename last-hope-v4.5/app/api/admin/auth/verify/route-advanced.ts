/**
 * Enhanced Admin Token Verification API with Advanced Security
 * واجهة برمجة تطبيقات التحقق من توكن المدير المحسنة مع حماية أمنية متقدمة
 */

import { NextRequest, NextResponse } from 'next/server'
import { verifyAdminToken } from '@/lib/admin-auth'
import { addSecurityHeaders } from '@/lib/security'
import { logAuditEvent, AuditAction } from '@/lib/audit-logger'
import { z } from 'zod'
import crypto from 'crypto'

// Enhanced admin verification request schema
const adminVerifyRequestSchema = z.object({
  clientInfo: z.object({
    userAgent: z.string().optional(),
    platform: z.string().optional(),
    browser: z.string().optional(),
    deviceId: z.string().optional(),
    ipAddress: z.string().optional(),
    sessionId: z.string().optional(),
    adminLevel: z.enum(['basic', 'elevated', 'super']).optional()
  }).optional(),
  operation: z.enum(['login', 'setup', 'recovery', 'maintenance', 'administration']).optional().default('administration'),
  requireSessionValidation: z.boolean().optional().default(true),
  enhancedSecurity: z.boolean().optional().default(true)
})

// Advanced admin token verification security manager
class AdminVerifySecurity {
  private static verifyDatabase = new Map<string, {
    attempts: number
    firstAttempt: Date
    lastAttempt: Date
    blockedUntil: Date | null
    adminLevel: string | null
    operation: string | null
    riskScore: number
    patterns: string[]
    securityFlags: string[]
    lastValidVerification: Date | null
    sessionData: any
  }>()
  
  private static readonly MAX_VERIFICATION_ATTEMPTS = 5
  private static readonly SUSPICIOUS_THRESHOLD = 10
  private static readonly BLOCK_THRESHOLD = 90
  private static readonly VERIFICATION_WINDOW = 5 * 60 * 1000 // 5 minutes
  private static readonly BLOCK_DURATION = 120 * 60 * 1000 // 2 hours
  private static readonly EMERGENCY_BLOCK_DURATION = 24 * 60 * 60 * 1000 // 24 hours

  static async analyzeAdminVerificationAttempt(
    token: string,
    clientIP: string,
    userAgent: string,
    adminLevel: string,
    operation: string,
    clientInfo: any
  ): Promise<{
    isAllowed: boolean
    riskScore: number
    reason?: string
    shouldBlock: boolean
    patterns: string[]
    securityFlags: string[]
    recommendations: string[]
  }> {
    const key = `${adminLevel}:${operation}:${clientIP}:${userAgent}`
    const currentTime = new Date()
    
    let verifyData = this.verifyDatabase.get(key)
    
    if (!verifyData) {
      verifyData = {
        attempts: 0,
        firstAttempt: currentTime,
        lastAttempt: currentTime,
        blockedUntil: null,
        adminLevel,
        operation,
        riskScore: 0,
        patterns: [],
        securityFlags: [],
        lastValidVerification: null,
        sessionData: null
      }
    }
    
    // Check if currently blocked
    if (verifyData.blockedUntil && currentTime < verifyData.blockedUntil) {
      const isEmergency = currentTime.getTime() - verifyData.firstAttempt.getTime() > this.EMERGENCY_BLOCK_DURATION
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: isEmergency ? 'Admin verification blocked due to security emergency' : 'Admin verification blocked due to suspicious activity',
        shouldBlock: true,
        patterns: isEmergency ? ['emergency_blocked'] : ['admin_blocked'],
        securityFlags: isEmergency ? ['EMERGENCY_ADMIN_BREACH'] : ['ADMIN_FRAUD_PREVENTION'],
        recommendations: isEmergency ? ['Contact system administrator immediately'] : ['Wait before attempting verification again']
      }
    }
    
    // Enhanced time-based analysis
    const timeDiff = currentTime.getTime() - verifyData.firstAttempt.getTime()
    const attemptRate = verifyData.attempts / (timeDiff / 60000)
    
    if (attemptRate > 2) { // Very restrictive for admin verification
      verifyData.patterns.push('admin_high_frequency')
      verifyData.securityFlags.push('ADMIN_FREQUENCY_ANOMALY')
      verifyData.riskScore += 35
    }
    
    // Operation-specific risk analysis
    const operationRisk = this.analyzeOperationRisk(operation, clientInfo)
    verifyData.riskScore += operationRisk.riskScore
    if (operationRisk.flag) {
      verifyData.securityFlags.push(operationRisk.flag)
      verifyData.patterns.push(operationRisk.pattern)
    }
    
    // Token security analysis
    const tokenRisk = this.analyzeTokenSecurity(token, clientInfo)
    verifyData.riskScore += tokenRisk.riskScore
    if (tokenRisk.flag) {
      verifyData.securityFlags.push(tokenRisk.flag)
      verifyData.patterns.push(tokenRisk.pattern)
    }
    
    // Session validation
    if (clientInfo?.sessionId) {
      const sessionRisk = this.analyzeSessionSecurity(clientInfo.sessionId, verifyData.sessionData)
      verifyData.riskScore += sessionRisk.riskScore
      if (sessionRisk.flag) {
        verifyData.securityFlags.push(sessionRisk.flag)
      }
      verifyData.sessionData = clientInfo.sessionId
    }
    
    // Admin level security checks
    const adminLevelRisk = this.validateAdminLevelSecurity(adminLevel, operation)
    verifyData.riskScore += adminLevelRisk.riskScore
    if (adminLevelRisk.flag) {
      verifyData.securityFlags.push(adminLevelRisk.flag)
      verifyData.patterns.push(adminLevelRisk.pattern)
    }
    
    // Update attempt tracking
    verifyData.attempts++
    verifyData.lastAttempt = currentTime
    verifyData.adminLevel = adminLevel
    verifyData.operation = operation
    
    // Emergency blocking for critical operations
    if (['setup', 'maintenance'].includes(operation) && verifyData.attempts > this.MAX_VERIFICATION_ATTEMPTS) {
      verifyData.blockedUntil = new Date(currentTime.getTime() + this.EMERGENCY_BLOCK_DURATION)
      verifyData.riskScore = 100
      verifyData.securityFlags.push('CRITICAL_OPERATION_ABUSE')
      
      this.verifyDatabase.set(key, verifyData)
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: 'Critical operation verification blocked due to suspicious activity',
        shouldBlock: true,
        patterns: verifyData.patterns,
        securityFlags: verifyData.securityFlags,
        recommendations: ['Contact system administrator for critical operations']
      }
    }
    
    // Standard blocking
    if (verifyData.riskScore >= this.BLOCK_THRESHOLD) {
      const blockDuration = operation === 'recovery' ? this.EMERGENCY_BLOCK_DURATION : this.BLOCK_DURATION
      verifyData.blockedUntil = new Date(currentTime.getTime() + blockDuration)
      verifyData.riskScore = 100
      verifyData.securityFlags.push('ADMIN_SECURITY_REVOCATION')
      
      this.verifyDatabase.set(key, verifyData)
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: 'Admin verification blocked due to security violations',
        shouldBlock: true,
        patterns: verifyData.patterns,
        securityFlags: verifyData.securityFlags,
        recommendations: ['Contact support if you believe this is an error']
      }
    }
    
    // Allow if under suspicious threshold
    const isAllowed = verifyData.riskScore < this.SUSPICIOUS_THRESHOLD && verifyData.attempts <= this.MAX_VERIFICATION_ATTEMPTS
    
    if (!isAllowed && verifyData.attempts > this.MAX_VERIFICATION_ATTEMPTS) {
      verifyData.patterns.push('admin_too_many_attempts')
      verifyData.securityFlags.push('ADMIN_EXCESSIVE_ATTEMPTS')
      verifyData.riskScore += 30
    }
    
    this.verifyDatabase.set(key, verifyData)
    
    const recommendations = this.generateVerificationRecommendations(verifyData.patterns, operation)
    
    return {
      isAllowed,
      riskScore: verifyData.riskScore,
      reason: !isAllowed ? 'Admin verification denied' : undefined,
      shouldBlock: verifyData.riskScore >= this.BLOCK_THRESHOLD,
      patterns: verifyData.patterns,
      securityFlags: verifyData.securityFlags,
      recommendations
    }
  }
  
  private static analyzeOperationRisk(operation: string, clientInfo: any): { riskScore: number; flag?: string; pattern?: string } {
    switch (operation) {
      case 'administration':
        return { riskScore: 0 } // Normal admin operation
      case 'login':
        return { riskScore: 0 } // Normal login operation
      case 'setup':
        return { riskScore: 5, flag: 'SETUP_OPERATION', pattern: 'system_setup' }
      case 'maintenance':
        return { riskScore: 10, flag: 'MAINTENANCE_OPERATION', pattern: 'system_maintenance' }
      case 'recovery':
        return { riskScore: 20, flag: 'RECOVERY_OPERATION', pattern: 'account_recovery' }
      default:
        return { riskScore: 25, flag: 'UNKNOWN_OPERATION', pattern: 'unauthorized_operation' }
    }
  }
  
  private static analyzeTokenSecurity(token: string, clientInfo: any): { riskScore: number; flag?: string; pattern?: string } {
    if (!token || token.length < 10) {
      return { riskScore: 40, flag: 'INVALID_TOKEN_FORMAT', pattern: 'malformed_token' }
    }
    
    // Check for token patterns that might indicate compromise
    if (token.includes('admin') || token.includes('temp') || token.includes('test')) {
      return { riskScore: 20, flag: 'SUSPICIOUS_TOKEN_CONTENT', pattern: 'token_content_anomaly' }
    }
    
    return { riskScore: 0 }
  }
  
  private static analyzeSessionSecurity(sessionId: string, previousSession: any): { riskScore: number; flag?: string } {
    if (!sessionId || sessionId.length < 8) {
      return { riskScore: 15, flag: 'WEAK_SESSION_ID' }
    }
    
    if (previousSession && previousSession !== sessionId) {
      return { riskScore: 25, flag: 'SESSION_MISMATCH' }
    }
    
    return { riskScore: 0 }
  }
  
  private static validateAdminLevelSecurity(adminLevel: string, operation: string): { riskScore: number; flag?: string; pattern?: string } {
    // Super admin should have access to all operations
    if (adminLevel === 'super') {
      return { riskScore: 0 }
    }
    
    // Basic admin should not have access to setup or maintenance
    if (adminLevel === 'basic' && ['setup', 'maintenance'].includes(operation)) {
      return { riskScore: 30, flag: 'INSUFFICIENT_ADMIN_PRIVILEGES', pattern: 'privilege_escalation' }
    }
    
    return { riskScore: 0 }
  }
  
  private static generateVerificationRecommendations(patterns: string[], operation: string): string[] {
    const recommendations: string[] = []
    
    if (patterns.includes('admin_high_frequency')) {
      recommendations.push('Reduce verification attempt frequency')
    }
    if (patterns.includes('system_setup') || patterns.includes('system_maintenance')) {
      recommendations.push('Ensure proper authorization for system operations')
    }
    if (patterns.includes('account_recovery')) {
      recommendations.push('Verify identity for account recovery operations')
    }
    if (patterns.includes('privilege_escalation')) {
      recommendations.push('Request appropriate admin level access')
    }
    if (patterns.includes('admin_too_many_attempts')) {
      recommendations.push('Wait before attempting verification again')
    }
    
    return recommendations
  }
  
  static updateSuccessfulVerification(adminLevel: string, operation: string, clientIP: string, userAgent: string): void {
    const key = `${adminLevel}:${operation}:${clientIP}:${userAgent}`
    const currentTime = new Date()
    
    let verifyData = this.verifyDatabase.get(key)
    if (verifyData) {
      verifyData.attempts = Math.max(0, verifyData.attempts - 2) // Reduce attempts more for admin
      verifyData.riskScore = Math.max(0, verifyData.riskScore - 10) // Reduce risk more for admin
      verifyData.lastValidVerification = currentTime
      verifyData.securityFlags = verifyData.securityFlags.filter(flag => 
        !['ADMIN_FREQUENCY_ANOMALY', 'ADMIN_EXCESSIVE_ATTEMPTS'].includes(flag)
      )
      this.verifyDatabase.set(key, verifyData)
    }
  }
  
  static cleanupOldEntries(): void {
    const currentTime = new Date()
    const maxAge = 6 * 60 * 60 * 1000 // 6 hours for admin verification
    
    for (const [key, data] of this.verifyDatabase.entries()) {
      const timeDiff = currentTime.getTime() - data.firstAttempt.getTime()
      if (timeDiff > maxAge) {
        this.verifyDatabase.delete(key)
      }
    }
  }
}

// Performance monitoring for admin verification
const adminVerifyMonitor = {
  startTime: 0,
  correlationId: '',
  
  init() {
    this.startTime = Date.now()
    this.correlationId = `AdminVerify_${crypto.randomUUID()}`
  },
  
  end(success: boolean, riskDetected: boolean = false, riskScore: number = 0, valid: boolean = false) {
    const duration = Date.now() - this.startTime
    const metadata = {
      correlationId: this.correlationId,
      duration,
      success,
      riskDetected,
      riskScore,
      valid,
      level: 'admin_verify',
      timestamp: new Date().toISOString()
    }
    
    console.log(`[Admin Verification Performance] ${JSON.stringify(metadata)}`)
    return metadata
  }
}

// Enhanced admin token verification handler
export async function POST(req: NextRequest) {
  adminVerifyMonitor.init()
  
  try {
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.headers.get("cf-connecting-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const correlationId = adminVerifyMonitor.correlationId
    
    console.log(`[Admin Verification Request] CorrelationID: ${correlationId}, IP: ${clientIP}, UA: ${userAgent}`)
    
    // Parse request body
    let requestData = {}
    try {
      requestData = await req.json()
    } catch (e) {
      // Continue with header-only verification if no JSON body
    }
    
    const validationResult = adminVerifyRequestSchema.safeParse(requestData)
    if (!validationResult.success) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid admin verification request format",
          validationError: validationResult.error.message,
          correlationId
        },
        clientIP
      )
      
      const endResult = adminVerifyMonitor.end(false, true, 60, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: 'تنسيق طلب التحقق غير صحيح',
            code: 'INVALID_REQUEST_FORMAT',
            correlationId,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    const { clientInfo, operation, requireSessionValidation, enhancedSecurity } = validationResult.data
    
    // Enhanced authorization header check
    const authHeader = req.headers.get('authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      const securityAnalysis = await AdminVerifySecurity.analyzeAdminVerificationAttempt(
        "no_token", clientIP, userAgent, "unknown", operation, clientInfo
      )
      
      await logAuditEvent(
        AuditAction.ADMIN_SECURITY_VIOLATION,
        "unknown",
        {
          error: "Missing admin authorization header",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          patterns: securityAnalysis.patterns,
          securityFlags: securityAnalysis.securityFlags,
          operation
        },
        clientIP
      )
      
      const endResult = adminVerifyMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: 'رمز الدخول مفقود',
            code: 'NO_ADMIN_TOKEN',
            correlationId,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    const token = authHeader.substring(7)
    
    // Enhanced admin token verification
    const verification = verifyAdminToken(token)
    
    if (!verification.valid) {
      const securityAnalysis = await AdminVerifySecurity.analyzeAdminVerificationAttempt(
        token, clientIP, userAgent, "unknown", operation, clientInfo
      )
      
      await logAuditEvent(
        AuditAction.ADMIN_SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid admin token during verification",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          patterns: securityAnalysis.patterns,
          securityFlags: securityAnalysis.securityFlags,
          verificationError: verification.message,
          tokenPreview: token.substring(0, 15) + "...",
          operation
        },
        clientIP
      )
      
      const endResult = adminVerifyMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: verification.message || 'رمز غير صالح',
            code: 'INVALID_ADMIN_TOKEN',
            correlationId,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    // Extract admin level from verification payload
    const adminEmail = verification.payload!.email
    const adminRole = verification.payload!.role
    
    let adminLevel = 'basic'
    if (adminRole === 'SUPER_ADMIN') {
      adminLevel = 'super'
    } else if (adminRole === 'MANAGER') {
      adminLevel = 'elevated'
    }
    
    // Advanced admin security analysis
    const securityAnalysis = await AdminVerifySecurity.analyzeAdminVerificationAttempt(
      token, clientIP, userAgent, adminLevel, operation, clientInfo
    )
    
    if (!securityAnalysis.isAllowed) {
      await logAuditEvent(
        AuditAction.ADMIN_VERIFICATION_BLOCKED,
        adminEmail,
        {
          error: "Admin verification blocked by security analysis",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          reason: securityAnalysis.reason,
          patterns: securityAnalysis.patterns,
          securityFlags: securityAnalysis.securityFlags,
          adminLevel,
          operation,
          adminRole
        },
        clientIP
      )
      
      const endResult = adminVerifyMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: securityAnalysis.reason || 'رمز التحقق مرفوض',
            code: 'ADMIN_VERIFICATION_BLOCKED',
            correlationId,
            riskScore: securityAnalysis.riskScore,
            recommendations: securityAnalysis.recommendations,
            securityFlags: securityAnalysis.securityFlags,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    // Session validation if required
    if (requireSessionValidation && clientInfo?.sessionId) {
      // In a real implementation, would validate against stored session data
      // For now, just log the session validation attempt
      console.log(`[Admin Session Validation] Session: ${clientInfo.sessionId}, User: ${adminEmail}`)
    }
    
    // Update security data for successful verification
    AdminVerifySecurity.updateSuccessfulVerification(adminLevel, operation, clientIP, userAgent)
    
    // Enhanced response with comprehensive admin security metadata
    const response = addSecurityHeaders(
      NextResponse.json({
        status: 'success',
        message: 'رمز صالح',
        valid: true,
        data: {
          admin: {
            email: adminEmail,
            role: adminRole,
            level: adminLevel,
            permissions: {
              canManageUsers: ['ADMIN', 'SUPER_ADMIN'].includes(adminRole),
              canManageSystem: adminRole === 'SUPER_ADMIN',
              canViewAnalytics: ['ADMIN', 'MANAGER', 'SUPER_ADMIN'].includes(adminRole),
              canSetup: adminRole === 'SUPER_ADMIN',
              canMaintain: ['ADMIN', 'SUPER_ADMIN'].includes(adminRole)
            }
          },
          operation,
          sessionInfo: requireSessionValidation ? { validated: true } : undefined
        },
        security: {
          correlationId,
          riskScore: securityAnalysis.riskScore,
          operation,
          adminLevel,
          adminRole,
          enhancedSecurity,
          requireSessionValidation,
          timestamp: new Date().toISOString()
        }
      })
    )
    
    // Enhanced security headers for admin verification
    response.headers.set("X-Admin-Verification-Timestamp", new Date().toISOString())
    response.headers.set("X-Security-Level", "admin_elevated")
    response.headers.set("X-Admin-Level", adminLevel)
    response.headers.set("X-Operation-Type", operation)
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set("X-Admin-Security", "verified")
    
    // Audit logging for successful admin verification
    await logAuditEvent(
      AuditAction.ADMIN_VERIFICATION_SUCCESS,
      adminEmail,
      {
        correlationId,
        riskScore: securityAnalysis.riskScore,
        clientInfo,
        adminLevel,
        operation,
        adminRole,
        enhancedSecurity,
        requireSessionValidation
      },
      clientIP
    )
    
    const endResult = adminVerifyMonitor.end(true, false, securityAnalysis.riskScore, true)
    console.log(`[Admin Verification Success] Email: ${adminEmail}, Role: ${adminRole}, Level: ${adminLevel}, Operation: ${operation}, Risk: ${securityAnalysis.riskScore}, Duration: ${endResult.duration}ms, CorrelationID: ${correlationId}`)
    
    return response
    
  } catch (error: any) {
    console.error('Enhanced Admin Token verification error:', error)
    
    await logAuditEvent(
      AuditAction.ADMIN_SYSTEM_ERROR,
      "system",
      {
        error: error.message,
        stack: error.stack,
        correlationId: adminVerifyMonitor.correlationId,
        endpoint: "/api/admin/auth/verify"
      },
      req.headers.get("x-forwarded-for") || "unknown"
    )
    
    const endResult = adminVerifyMonitor.end(false, false, 0, false)
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: 'error',
          message: 'حدث خطأ في التحقق',
          code: 'ADMIN_VERIFICATION_FAILED',
          correlationId: adminVerifyMonitor.correlationId,
          valid: false,
          timestamp: new Date().toISOString()
        },
        { status: 500 }
      )
    )
  }
}

// OPTIONS handler for CORS
export async function OPTIONS(req: NextRequest) {
  const response = new NextResponse(null, { status: 200 })
  return addSecurityHeaders(response)
}

// Cleanup function
export async function cleanup() {
  AdminVerifySecurity.cleanupOldEntries()
}
