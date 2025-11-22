/**
 * Enhanced Request OTP API with Advanced Security
 * واجهة برمجة تطبيقات OTP محسنة مع حماية أمنية متقدمة
 */

import { NextRequest, NextResponse } from 'next/server'
import { sendWhatsAppOTP } from '@/lib/whatsapp-otp'
import { isAdminConfigured } from '@/lib/admin-auth'
import { addSecurityHeaders } from '@/lib/security'
import { logAuditEvent, AuditAction } from '@/lib/audit-logger'
import { z } from 'zod'
import crypto from 'crypto'

// Enhanced OTP request schema with comprehensive validation
const otpRequestSchema = z.object({
  email: z.string().email(),
  adminLevel: z.enum(['basic', 'elevated', 'super']).optional().default('basic'),
  clientInfo: z.object({
    userAgent: z.string().optional(),
    platform: z.string().optional(),
    browser: z.string().optional(),
    ipAddress: z.string().optional(),
    deviceId: z.string().optional(),
    sessionId: z.string().optional()
  }).optional(),
  operation: z.enum(['login', 'setup', 'recovery', 'maintenance']).optional().default('login'),
  emergencyMode: z.boolean().optional().default(false)
})

// Advanced OTP request security manager
class AdvancedOTPSecurity {
  private static otpRequestDatabase = new Map<string, {
    attempts: number
    firstAttempt: Date
    lastAttempt: Date
    blockedUntil: Date | null
    adminLevel: string | null
    riskScore: number
    operation: string | null
    patterns: string[]
    securityFlags: string[]
    otpRequests: Date[]
  }>()
  
  private static readonly MAX_OTP_REQUESTS = 3
  private static readonly SUSPICIOUS_THRESHOLD = 12
  private static readonly BLOCK_THRESHOLD = 85
  private static readonly OTP_WINDOW = 5 * 60 * 1000 // 5 minutes
  private static readonly BLOCK_DURATION = 90 * 60 * 1000 // 1.5 hours
  private static readonly EMERGENCY_BLOCK_DURATION = 24 * 60 * 60 * 1000 // 24 hours

  static async analyzeOTPRequest(
    email: string,
    adminLevel: string,
    operation: string,
    clientIP: string,
    userAgent: string,
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
    const key = `${email}:${adminLevel}:${operation}`
    const currentTime = new Date()
    
    let otpData = this.otpRequestDatabase.get(key)
    
    if (!otpData) {
      otpData = {
        attempts: 0,
        firstAttempt: currentTime,
        lastAttempt: currentTime,
        blockedUntil: null,
        adminLevel,
        riskScore: 0,
        operation,
        patterns: [],
        securityFlags: [],
        otpRequests: []
      }
    }
    
    // Check if currently blocked
    if (otpData.blockedUntil && currentTime < otpData.blockedUntil) {
      const isEmergency = currentTime.getTime() - otpData.firstAttempt.getTime() > this.EMERGENCY_BLOCK_DURATION
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: isEmergency ? 'OTP requests blocked due to emergency security breach' : 'OTP requests blocked due to suspicious activity',
        shouldBlock: true,
        patterns: isEmergency ? ['emergency_blocked'] : ['otp_blocked'],
        securityFlags: isEmergency ? ['EMERGENCY_SECURITY_BREACH'] : ['OTP_FRAUD_PREVENTION'],
        recommendations: isEmergency ? ['Contact system administrator immediately'] : ['Wait before requesting OTP again']
      }
    }
    
    // Enhanced time-based analysis
    const timeDiff = currentTime.getTime() - otpData.firstAttempt.getTime()
    const attemptRate = otpData.attempts / (timeDiff / 60000)
    
    if (attemptRate > 1) { // More restrictive for OTP
      otpData.patterns.push('otp_high_frequency')
      otpData.securityFlags.push('OTP_FREQUENCY_ANOMALY')
      otpData.riskScore += 30
    }
    
    // Admin level validation
    if (!this.isValidAdminLevel(email, adminLevel)) {
      otpData.patterns.push('invalid_admin_level')
      otpData.securityFlags.push('ADMIN_LEVEL_MISMATCH')
      otpData.riskScore += 40
    }
    
    // Operation-specific security checks
    const operationRisk = this.analyzeOperationRisk(operation, clientInfo)
    otpData.riskScore += operationRisk.riskScore
    if (operationRisk.flag) {
      otpData.securityFlags.push(operationRisk.flag)
      otpData.patterns.push(operationRisk.pattern)
    }
    
    // Client fingerprint analysis
    if (clientInfo?.deviceId) {
      const deviceRisk = this.analyzeDeviceRisk(clientInfo.deviceId, email)
      otpData.riskScore += deviceRisk.riskScore
      if (deviceRisk.flag) {
        otpData.securityFlags.push(deviceRisk.flag)
      }
    }
    
    // Track OTP request timing
    otpData.otpRequests.push(currentTime)
    
    // Clean old requests (keep last 10)
    if (otpData.otpRequests.length > 10) {
      otpData.otpRequests = otpData.otpRequests.slice(-10)
    }
    
    // Update attempt tracking
    otpData.attempts++
    otpData.lastAttempt = currentTime
    otpData.adminLevel = adminLevel
    otpData.operation = operation
    
    // Emergency blocking for critical operations
    if (operation === 'setup' && otpData.attempts > this.MAX_OTP_REQUESTS * 2) {
      otpData.blockedUntil = new Date(currentTime.getTime() + this.EMERGENCY_BLOCK_DURATION)
      otpData.riskScore = 100
      otpData.securityFlags.push('SETUP_OPERATION_ABUSE')
      
      this.otpRequestDatabase.set(key, otpData)
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: 'Setup operation blocked due to suspicious activity',
        shouldBlock: true,
        patterns: otpData.patterns,
        securityFlags: otpData.securityFlags,
        recommendations: ['Contact system administrator for setup assistance']
      }
    }
    
    // Standard blocking
    if (otpData.riskScore >= this.BLOCK_THRESHOLD) {
      const blockDuration = operation === 'recovery' ? this.EMERGENCY_BLOCK_DURATION : this.BLOCK_DURATION
      otpData.blockedUntil = new Date(currentTime.getTime() + blockDuration)
      otpData.riskScore = 100
      otpData.securityFlags.push('OTP_SECURITY_REVOCATION')
      
      this.otpRequestDatabase.set(key, otpData)
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: 'OTP requests blocked due to security violations',
        shouldBlock: true,
        patterns: otpData.patterns,
        securityFlags: otpData.securityFlags,
        recommendations: ['Contact support if you believe this is an error']
      }
    }
    
    // Allow if under suspicious threshold
    const isAllowed = otpData.riskScore < this.SUSPICIOUS_THRESHOLD && otpData.attempts <= this.MAX_OTP_REQUESTS
    
    if (!isAllowed && otpData.attempts > this.MAX_OTP_REQUESTS) {
      otpData.patterns.push('otp_too_many_attempts')
      otpData.securityFlags.push('OTP_EXCESSIVE_REQUESTS')
      otpData.riskScore += 25
    }
    
    this.otpRequestDatabase.set(key, otpData)
    
    const recommendations = this.generateOTPRecommendations(otpData.patterns, operation)
    
    return {
      isAllowed,
      riskScore: otpData.riskScore,
      reason: !isAllowed ? 'OTP request denied' : undefined,
      shouldBlock: otpData.riskScore >= this.BLOCK_THRESHOLD,
      patterns: otpData.patterns,
      securityFlags: otpData.securityFlags,
      recommendations
    }
  }
  
  private static isValidAdminLevel(email: string, adminLevel: string): boolean {
    // Enhanced admin level validation logic
    const adminEmail = process.env.ADMIN_EMAIL?.toLowerCase()
    const superAdminEmail = process.env.SUPER_ADMIN_EMAIL?.toLowerCase()
    
    if (!adminEmail) return false
    
    if (email.toLowerCase() === superAdminEmail) {
      return ['elevated', 'super', 'basic'].includes(adminLevel)
    }
    
    if (email.toLowerCase() === adminEmail) {
      return ['basic', 'elevated'].includes(adminLevel)
    }
    
    return false
  }
  
  private static analyzeOperationRisk(operation: string, clientInfo: any): { riskScore: number; flag?: string; pattern?: string } {
    switch (operation) {
      case 'setup':
        return { riskScore: 0 } // Normal setup operation
      case 'login':
        return { riskScore: 0 } // Normal login operation
      case 'recovery':
        return { riskScore: 15, flag: 'RECOVERY_OPERATION', pattern: 'account_recovery' }
      case 'maintenance':
        return { riskScore: 10, flag: 'MAINTENANCE_OPERATION', pattern: 'system_maintenance' }
      default:
        return { riskScore: 20, flag: 'UNKNOWN_OPERATION', pattern: 'unauthorized_operation' }
    }
  }
  
  private static analyzeDeviceRisk(deviceId: string, email: string): { riskScore: number; flag?: string } {
    if (!deviceId || deviceId.length < 8) {
      return { riskScore: 15, flag: 'WEAK_DEVICE_ID' }
    }
    
    // Check for common device ID patterns
    const suspiciousPatterns = ['12345678', 'abcdefgh', 'device001']
    if (suspiciousPatterns.some(pattern => deviceId.includes(pattern))) {
      return { riskScore: 25, flag: 'SUSPICIOUS_DEVICE_ID' }
    }
    
    return { riskScore: 0 }
  }
  
  private static generateOTPRecommendations(patterns: string[], operation: string): string[] {
    const recommendations: string[] = []
    
    if (patterns.includes('otp_high_frequency')) {
      recommendations.push('Reduce OTP request frequency')
    }
    if (patterns.includes('invalid_admin_level')) {
      recommendations.push('Use correct admin access level')
    }
    if (patterns.includes('account_recovery')) {
      recommendations.push('Verify your identity for account recovery')
    }
    if (patterns.includes('system_maintenance')) {
      recommendations.push('Ensure proper authorization for maintenance operations')
    }
    if (patterns.includes('otp_too_many_attempts')) {
      recommendations.push('Wait before requesting another OTP')
    }
    
    return recommendations
  }
  
  static updateSuccessfulOTPRequest(email: string, adminLevel: string, operation: string): void {
    const key = `${email}:${adminLevel}:${operation}`
    
    let otpData = this.otpRequestDatabase.get(key)
    if (otpData) {
      otpData.attempts = Math.max(0, otpData.attempts - 1) // Reduce attempts on success
      otpData.riskScore = Math.max(0, otpData.riskScore - 5) // Reduce risk on success
      otpData.securityFlags = otpData.securityFlags.filter(flag => 
        !['OTP_FREQUENCY_ANOMALY', 'OTP_EXCESSIVE_REQUESTS'].includes(flag)
      )
      this.otpRequestDatabase.set(key, otpData)
    }
  }
  
  static cleanupOldEntries(): void {
    const currentTime = new Date()
    const maxAge = 12 * 60 * 60 * 1000 // 12 hours
    
    for (const [key, data] of this.otpRequestDatabase.entries()) {
      const timeDiff = currentTime.getTime() - data.firstAttempt.getTime()
      if (timeDiff > maxAge) {
        this.otpRequestDatabase.delete(key)
      }
    }
  }
}

// Performance monitoring for OTP requests
const otpRequestMonitor = {
  startTime: 0,
  correlationId: '',
  
  init() {
    this.startTime = Date.now()
    this.correlationId = `OTP_${crypto.randomUUID()}`
  },
  
  end(success: boolean, riskDetected: boolean = false, riskScore: number = 0) {
    const duration = Date.now() - this.startTime
    const metadata = {
      correlationId: this.correlationId,
      duration,
      success,
      riskDetected,
      riskScore,
      level: 'admin_otp',
      timestamp: new Date().toISOString()
    }
    
    console.log(`[OTP Request Performance] ${JSON.stringify(metadata)}`)
    return metadata
  }
}

// Enhanced OTP request handler
export async function POST(req: NextRequest) {
  otpRequestMonitor.init()
  
  try {
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.headers.get("cf-connecting-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const correlationId = otpRequestMonitor.correlationId
    
    console.log(`[OTP Request] CorrelationID: ${correlationId}, IP: ${clientIP}, UA: ${userAgent}`)
    
    // Enhanced admin configuration check
    if (!isAdminConfigured()) {
      await logAuditEvent(
        AuditAction.ADMIN_CONFIGURATION_ERROR,
        "system",
        {
          error: "Admin not configured for OTP request",
          correlationId,
          endpoint: "/api/admin/auth/request-otp"
        },
        clientIP
      )
      
      const endResult = otpRequestMonitor.end(false, true, 90)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: 'لم يتم إعداد حساب المدير. الرجاء زيارة /admin-setup',
            code: 'ADMIN_NOT_CONFIGURED',
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    // Parse and validate request
    let body: any = {}
    try {
      body = await req.json()
    } catch (e) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid JSON in OTP request",
          correlationId
        },
        clientIP
      )
      
      const endResult = otpRequestMonitor.end(false, true, 70)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: 'تنسيق طلب غير صحيح',
            code: 'INVALID_REQUEST_FORMAT',
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    const validationResult = otpRequestSchema.safeParse(body)
    if (!validationResult.success) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "OTP request validation failed",
          validationError: validationResult.error.errors,
          correlationId
        },
        clientIP
      )
      
      const endResult = otpRequestMonitor.end(false, true, 60)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: 'بيانات الطلب غير صحيحة',
            code: 'VALIDATION_FAILED',
            correlationId,
            errors: validationResult.error.errors,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    const { email, adminLevel, clientInfo, operation, emergencyMode } = validationResult.data
    
    // Enhanced email validation
    const adminEmail = process.env.ADMIN_EMAIL?.toLowerCase()
    const superAdminEmail = process.env.SUPER_ADMIN_EMAIL?.toLowerCase()
    
    if (!email || !adminEmail || 
        (email.toLowerCase() !== adminEmail && email.toLowerCase() !== superAdminEmail)) {
      
      await logAuditEvent(
        AuditAction.UNAUTHORIZED_OTP_ACCESS,
        "unknown",
        {
          error: "Unauthorized email for OTP request",
          correlationId,
          providedEmail: email,
          expectedEmails: [adminEmail, superAdminEmail].filter(Boolean)
        },
        clientIP
      )
      
      const endResult = otpRequestMonitor.end(false, true, 80)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: 'بريد إلكتروني غير مصرح له',
            code: 'UNAUTHORIZED_EMAIL',
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    // Advanced OTP security analysis
    const securityAnalysis = await AdvancedOTPSecurity.analyzeOTPRequest(
      email, adminLevel, operation, clientIP, userAgent, clientInfo
    )
    
    if (!securityAnalysis.isAllowed) {
      await logAuditEvent(
        AuditAction.OTP_REQUEST_BLOCKED,
        email,
        {
          error: "OTP request blocked by security analysis",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          reason: securityAnalysis.reason,
          patterns: securityAnalysis.patterns,
          securityFlags: securityAnalysis.securityFlags,
          adminLevel,
          operation,
          emergencyMode
        },
        clientIP
      )
      
      const endResult = otpRequestMonitor.end(false, true, securityAnalysis.riskScore)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: securityAnalysis.reason || 'طلب OTP مرفوض',
            code: 'OTP_REQUEST_BLOCKED',
            correlationId,
            riskScore: securityAnalysis.riskScore,
            recommendations: securityAnalysis.recommendations,
            securityFlags: securityAnalysis.securityFlags,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    // Enhanced phone number validation and retrieval
    const adminPhone = process.env.ADMIN_WHATSAPP_NUMBER || process.env.ADMIN_PHONE
    const superAdminPhone = process.env.SUPER_ADMIN_WHATSAPP_NUMBER || process.env.SUPER_ADMIN_PHONE
    
    const targetPhone = email.toLowerCase() === superAdminEmail?.toLowerCase() ? 
                       superAdminPhone : adminPhone
    
    if (!targetPhone) {
      await logAuditEvent(
        AuditAction.ADMIN_CONFIGURATION_ERROR,
        email,
        {
          error: "Admin phone number not configured",
          correlationId,
          adminLevel,
          operation,
          emailType: email.toLowerCase() === superAdminEmail?.toLowerCase() ? 'super_admin' : 'admin'
        },
        clientIP
      )
      
      const endResult = otpRequestMonitor.end(false, true, 85)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: 'رقم واتساب المدير غير مُعد',
            code: 'ADMIN_PHONE_NOT_CONFIGURED',
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 500 }
        )
      )
    }
    
    // Send OTP with enhanced error handling
    const otpResult = await sendWhatsAppOTP(targetPhone)
    
    if (!otpResult.success) {
      await logAuditEvent(
        AuditAction.OTP_DELIVERY_FAILED,
        email,
        {
          error: "OTP delivery failed",
          correlationId,
          adminLevel,
          operation,
          deliveryError: otpResult.message,
          targetPhone: targetPhone.replace(/(\d{4})\d+(\d{3})/, '$1****$2')
        },
        clientIP
      )
      
      const endResult = otpRequestMonitor.end(false, true, 70)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: 'error',
            message: otpResult.message || 'فشل في إرسال رمز OTP',
            code: 'OTP_DELIVERY_FAILED',
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 500 }
        )
      )
    }
    
    // Update security data for successful OTP request
    AdvancedOTPSecurity.updateSuccessfulOTPRequest(email, adminLevel, operation)
    
    // Enhanced response with security metadata
    const maskedPhone = targetPhone.replace(/(\d{4})\d+(\d{3})/, '$1****$2')
    
    const response = addSecurityHeaders(
      NextResponse.json({
        status: 'success',
        message: otpResult.message,
        data: {
          phone: maskedPhone,
          expiresIn: otpResult.expiresIn,
          operation,
          adminLevel
        },
        security: {
          correlationId,
          riskScore: securityAnalysis.riskScore,
          operation,
          adminLevel,
          emergencyMode,
          timestamp: new Date().toISOString()
        }
      })
    )
    
    // Enhanced security headers
    response.headers.set("X-OTP-Request-Timestamp", new Date().toISOString())
    response.headers.set("X-Security-Level", "admin_otp")
    response.headers.set("X-Admin-Level", adminLevel)
    response.headers.set("X-Operation-Type", operation)
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set("X-OTP-Security", "enabled")
    
    // Audit logging for successful OTP request
    await logAuditEvent(
      AuditAction.OTP_REQUEST_SUCCESS,
      email,
      {
        correlationId,
        riskScore: securityAnalysis.riskScore,
        clientInfo,
        adminLevel,
        operation,
        emergencyMode,
        targetPhone: maskedPhone,
        otpMethod: 'whatsapp'
      },
      clientIP
    )
    
    const endResult = otpRequestMonitor.end(true, false, securityAnalysis.riskScore)
    console.log(`[OTP Request Success] Email: ${email}, Level: ${adminLevel}, Operation: ${operation}, Risk: ${securityAnalysis.riskScore}, Duration: ${endResult.duration}ms, CorrelationID: ${correlationId}`)
    
    return response
    
  } catch (error: any) {
    console.error('Enhanced Request OTP error:', error)
    
    await logAuditEvent(
      AuditAction.SYSTEM_ERROR,
      "system",
      {
        error: error.message,
        stack: error.stack,
        correlationId: otpRequestMonitor.correlationId,
        endpoint: "/api/admin/auth/request-otp"
      },
      req.headers.get("x-forwarded-for") || "unknown"
    )
    
    const endResult = otpRequestMonitor.end(false, false, 0)
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: 'error',
          message: 'حدث خطأ في إرسال الرمز',
          code: 'OTP_REQUEST_FAILED',
          correlationId: otpRequestMonitor.correlationId,
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
  AdvancedOTPSecurity.cleanupOldEntries()
}
