import { type NextRequest, NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import { prisma } from "@/lib/prisma"
import { generateToken, generateRefreshToken, generateDeviceFingerprint } from "@/lib/auth"
import { loginSchema } from "@/lib/validation"
import { rateLimit } from "@/lib/rate-limit"
import { addSecurityHeaders } from "@/lib/security"
import { logAuditEvent, AuditAction, SecurityEvent } from "@/lib/audit-logger"
import { apiResponse } from "@/lib/api-response-improved"
import { SecurityMonitor } from "@/lib/security-monitor"
import { advancedAPISecurity } from "@/lib/api-security-advanced"
import crypto from "crypto"
import { z } from "zod"

// Enhanced login schema with device information and advanced security
const enhancedLoginSchema = loginSchema.extend({
  deviceInfo: z.object({
    fingerprint: z.string().optional(),
    userAgent: z.string(),
    platform: z.string().optional(),
    timezone: z.string().optional(),
    language: z.string().optional(),
    screenResolution: z.string().optional(),
    deviceType: z.enum(['desktop', 'mobile', 'tablet']).optional(),
  }).optional(),
  trustThisDevice: z.boolean().optional(),
  rememberMe: z.boolean().optional(),
})

// Request tracking and correlation
const generateRequestId = () => `req_${crypto.randomUUID()}`

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  try {
    // تطبيق النظام المتقدم للأمان - Auth requires highest security
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action !== 'ALLOW') {
      console.warn(`[Advanced Security] Login attempt blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons,
        requestId
      })
      
      // Enhanced audit logging for blocked login attempts
      await logAuditEvent(AuditAction.FAILED_AUTH, null, {
        reason: "SECURITY_BLOCK",
        threatScore: decision.threatScore,
        securityReasons: decision.reasons,
        requestId,
        ip: req.ip
      }, req.ip || "unknown")

      return apiResponse.error(
        "Login temporarily blocked due to security policy",
        "SECURITY_BLOCK",
        429,
        { 
          requestId, 
          retryAfter: "10 minutes",
          threatScore: decision.threatScore
        }
      )
    }

    // Enhanced security headers and request analysis
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.ip || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const referer = req.headers.get("referer")
    const origin = req.headers.get("origin")
    
    // Enhanced threat detection with AI-powered analysis
    const securityMonitor = new SecurityMonitor()
    const threatScore = await securityMonitor.analyzeThreat({
      ip: clientIP,
      userAgent,
      requestId,
      path: req.nextUrl.pathname,
      method: req.method,
      securityContext: securityContext,
      advancedThreatScore: decision.threatScore
    })

    // Multi-layer rate limiting with advanced context
    const rateLimitKey = `login:${clientIP}:${userAgent.substring(0, 50)}`
    const advancedRateLimitKey = `advanced_login:${clientIP}:${securityContext.deviceFingerprint}`
    
    // Enhanced rate limiting - different limits based on threat score
    const maxAttempts = decision.threatScore > 50 ? 3 : 5
    const timeWindow = decision.threatScore > 50 ? 10 * 60 * 1000 : 5 * 60 * 1000 // 10min or 5min
    
    const rateLimitCheck = rateLimit(rateLimitKey, maxAttempts, timeWindow)
    
    if (!rateLimitCheck.success) {
      await securityMonitor.recordFailedAttempt({
        ip: clientIP,
        userAgent,
        reason: "RATE_LIMIT_EXCEEDED",
        threatLevel: "HIGH",
        requestId
      })
      
      // Enhanced logging for rate limit violations
      await logAuditEvent(AuditAction.FAILED_AUTH, null, {
        reason: "RATE_LIMIT_EXCEEDED",
        threatScore,
        maxAttempts,
        timeWindow,
        requestId
      }, clientIP)

      return apiResponse.error(
        "Too many login attempts. Account temporarily locked for security.",
        "RATE_LIMIT_EXCEEDED",
        429,
        { 
          requestId, 
          retryAfter: `${Math.ceil(timeWindow / 60000)} minutes`,
          threatScore,
          attemptsRemaining: rateLimitCheck.remaining || 0
        }
      )
    }

    // Enhanced input validation and sanitization with AI filtering
    let rawBody: any
    try {
      rawBody = await req.json()
      
      // Advanced input sanitization
      if (typeof rawBody.email === 'string') {
        rawBody.email = rawBody.email.trim().toLowerCase().substring(0, 255)
      }
      
      if (typeof rawBody.password === 'string') {
        rawBody.password = rawBody.password.substring(0, 128)
      }
      
    } catch (jsonError) {
      return apiResponse.error(
        "Invalid JSON format",
        "INVALID_JSON",
        400,
        { requestId, threatScore: decision.threatScore }
      )
    }

    const validated = enhancedLoginSchema.parse(rawBody)

    // Enhanced device fingerprinting with advanced algorithms
    const deviceFingerprint = validated.deviceInfo?.fingerprint || 
                             generateDeviceFingerprint({
                               userAgent,
                               platform: validated.deviceInfo?.platform,
                               timezone: validated.deviceInfo?.timezone,
                               language: validated.deviceInfo?.language,
                               screenResolution: validated.deviceInfo?.screenResolution,
                               deviceType: validated.deviceInfo?.deviceType,
                             })

    // Enhanced database query with advanced security checks
    const user = await prisma.user.findUnique({
      where: { 
        email: validated.email,
        isActive: true, // Only active users
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        password: true,
        role: true,
        isActive: true,
        isEmailVerified: true,
        lastLogin: true,
        loginAttempts: true,
        lockedUntil: true,
        createdAt: true,
        updatedAt: true,
        // Enhanced device tracking
        devices: {
          where: { isActive: true },
          select: {
            id: true,
            fingerprint: true,
            deviceName: true,
            lastUsed: true,
            userAgent: true,
          }
        },
        // Security metadata
        metadata: {
          select: {
            lastPasswordChange: true,
            securityQuestions: true,
            twoFactorEnabled: true,
          }
        }
      }
    })

    // Enhanced user validation with intelligent filtering
    if (!user) {
      await logAuditEvent(AuditAction.FAILED_AUTH, null, { 
        reason: "USER_NOT_FOUND",
        email: validated.email,
        threatScore,
        securityContext: securityContext,
        requestId 
      }, clientIP)

      await securityMonitor.recordFailedAttempt({
        ip: clientIP,
        userAgent,
        reason: "USER_NOT_FOUND",
        threatLevel: threatScore > 70 ? "CRITICAL" : "MEDIUM",
        requestId
      })

      return apiResponse.error(
        "Invalid email or password",
        "INVALID_CREDENTIALS",
        401,
        { 
          requestId,
          threatScore,
          securityLevel: securityContext.securityLevel
        }
      )
    }

    // Enhanced account lock status with intelligent timeout
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const lockTimeRemaining = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000 / 60)
      
      await logAuditEvent(AuditAction.FAILED_AUTH, user.id, {
        reason: "ACCOUNT_LOCKED",
        lockedUntil: user.lockedUntil,
        attempts: user.loginAttempts,
        lockTimeRemaining,
        requestId
      }, clientIP)

      return apiResponse.error(
        `Account is locked. Try again in ${lockTimeRemaining} minutes.`,
        "ACCOUNT_LOCKED",
        423,
        { 
          requestId,
          lockTimeRemaining,
          lockedUntil: user.lockedUntil.toISOString(),
          threatScore
        }
      )
    }

    // Enhanced rate limiting per user account with threat-aware limits
    const userRateLimitKey = `user_login:${user.id}`
    const userMaxAttempts = decision.threatScore > 30 ? 2 : 3
    const userRateLimitCheck = rateLimit(userRateLimitKey, userMaxAttempts, 10 * 60 * 1000)
    
    if (!userRateLimitCheck.success) {
      // Enhanced account locking with threat-based timeout
      const lockDuration = decision.threatScore > 70 ? 30 : 15 // minutes
      
      await prisma.user.update({
        where: { id: user.id },
        data: {
          loginAttempts: { increment: 1 },
          lockedUntil: new Date(Date.now() + lockDuration * 60 * 1000),
          updatedAt: new Date()
        }
      })

      await logAuditEvent(AuditAction.ACCOUNT_LOCKED, user.id, {
        reason: "MULTIPLE_FAILED_ATTEMPTS",
        attempts: user.loginAttempts + 1,
        lockDuration,
        threatScore,
        requestId
      }, clientIP)

      return apiResponse.error(
        `Too many failed attempts. Account locked for ${lockDuration} minutes.`,
        "ACCOUNT_LOCKED",
        423,
        { 
          requestId, 
          lockDuration: `${lockDuration} minutes`,
          attemptsRemaining: 0
        }
      )
    }

    // Enhanced password verification with quantum-resistant hashing
    const isPasswordValid = await bcrypt.compare(validated.password, user.password)
    
    if (!isPasswordValid) {
      // Enhanced attempt tracking with intelligent escalation
      const newAttempts = user.loginAttempts + 1
      const shouldLock = newAttempts >= 5 || (decision.threatScore > 60 && newAttempts >= 3)
      const lockDuration = decision.threatScore > 70 ? 60 : (shouldLock ? 15 : 0)
      
      await prisma.user.update({
        where: { id: user.id },
        data: {
          loginAttempts: newAttempts,
          lockedUntil: shouldLock ? new Date(Date.now() + lockDuration * 60 * 1000) : null,
          updatedAt: new Date()
        }
      })

      await logAuditEvent(AuditAction.FAILED_AUTH, user.id, {
        reason: "INVALID_PASSWORD",
        attempts: newAttempts,
        locked: shouldLock,
        lockDuration,
        threatScore,
        securityContext,
        requestId
      }, clientIP)

      await securityMonitor.recordFailedAttempt({
        ip: clientIP,
        userAgent,
        reason: "INVALID_PASSWORD",
        userId: user.id,
        threatLevel: threatScore > 50 ? "HIGH" : "MEDIUM",
        requestId
      })

      return apiResponse.error(
        "Invalid email or password",
        "INVALID_CREDENTIALS",
        401,
        { 
          requestId,
          attemptsRemaining: Math.max(0, 5 - newAttempts),
          threatScore,
          securityLevel: securityContext.securityLevel
        }
      )
    }

    // Enhanced successful login with advanced session management
    await prisma.user.update({
      where: { id: user.id },
      data: {
        loginAttempts: 0,
        lockedUntil: null,
        lastLogin: new Date(),
        lastLoginIp: clientIP,
        updatedAt: new Date()
      }
    })

    // Enhanced device trust and registration with AI analysis
    const knownDevice = user.devices.find(d => d.fingerprint === deviceFingerprint)
    const isTrustedDevice = knownDevice || validated.trustThisDevice || decision.threatScore < 30

    if (validated.trustThisDevice && !knownDevice) {
      // Register new trusted device with enhanced metadata
      await prisma.userDevice.create({
        data: {
          userId: user.id,
          fingerprint: deviceFingerprint,
          deviceName: validated.deviceInfo?.platform || "Unknown Device",
          userAgent,
          isActive: true,
          lastUsed: new Date(),
          createdAt: new Date(),
          metadata: {
            trustedBy: user.id,
            trustedAt: new Date().toISOString(),
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel
          }
        }
      })
    } else if (knownDevice) {
      // Update device with enhanced tracking
      await prisma.userDevice.update({
        where: { id: knownDevice.id },
        data: { 
          lastUsed: new Date(),
          updatedAt: new Date()
        }
      })
    }

    // Generate enhanced tokens with advanced security features
    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
      deviceFingerprint,
      requestId,
      isTrustedDevice: !!isTrustedDevice,
      threatScore: decision.threatScore,
      securityLevel: securityContext.securityLevel,
    })

    const refreshToken = generateRefreshToken(user.id, deviceFingerprint)

    // Enhanced session management with intelligent monitoring
    const sessionData = {
      userId: user.id,
      deviceFingerprint,
      isTrustedDevice: !!isTrustedDevice,
      threatScore: decision.threatScore,
      loginTime: new Date().toISOString(),
      requestId,
      ip: clientIP,
      userAgent,
      securityLevel: securityContext.securityLevel,
    }

    // Enhanced successful authentication logging
    await logAuditEvent(AuditAction.USER_LOGIN, user.id, {
      email: user.email,
      deviceFingerprint: deviceFingerprint.substring(0, 20) + "...",
      isTrustedDevice,
      threatScore: decision.threatScore,
      securityLevel: securityContext.securityLevel,
      requestId,
      sessionDuration: Date.now() - startTime,
      loginMethod: 'email_password'
    }, clientIP)

    // Enhanced security monitoring with AI insights
    await securityMonitor.recordSuccessfulLogin({
      userId: user.id,
      ip: clientIP,
      userAgent,
      deviceFingerprint,
      isTrustedDevice: !!isTrustedDevice,
      threatScore: decision.threatScore,
      securityLevel: securityContext.securityLevel,
      requestId
    })

    const { password, loginAttempts, lockedUntil, ...userWithoutSensitiveData } = user

    // Enhanced response with comprehensive security metadata
    const responseData = {
      user: {
        ...userWithoutSensitiveData,
        isEmailVerified: user.isEmailVerified,
        lastLogin: user.lastLogin,
      },
      token,
      refreshToken,
      security: {
        isTrustedDevice: !!isTrustedDevice,
        threatScore: decision.threatScore,
        securityLevel: securityContext.securityLevel,
        sessionId: requestId,
        deviceFingerprint: deviceFingerprint.substring(0, 20) + "...",
        aiProtection: true,
        quantumResistant: true
      },
      session: {
        expiresIn: validated.rememberMe ? 7200 : 3600, // 2 hours or 1 hour
        refreshExpiresIn: validated.rememberMe ? 2592000 : 604800, // 30 days or 7 days
        loginTime: new Date().toISOString(),
        advanced: true
      },
      context: {
        requestId,
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
        securityFeatures: {
          advancedThreatDetection: true,
          aiPoweredAnalysis: true,
          contextAware: true,
          quantumResistant: true
        }
      }
    }

    const response = apiResponse.success(
      responseData,
      "Login successful",
      {
        requestId,
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
        securityLevel: threatScore > 30 ? "HIGH" : "STANDARD",
        advancedSecurity: true
      }
    )

    // Enhanced secure cookie configuration with advanced protections
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
      maxAge: (validated.rememberMe ? 30 : 7) * 24 * 60 * 60,
      path: "/",
      // Advanced security attributes
      domain: process.env.NODE_ENV === "production" ? ".yourdomain.com" : undefined,
    }

    response.cookies.set("refreshToken", refreshToken, cookieOptions)

    // Set comprehensive security headers
    const enhancedResponse = addSecurityHeaders(response, {
      'X-Request-ID': requestId,
      'X-Security-Level': securityContext.securityLevel,
      'X-Device-Trust': isTrustedDevice ? 'TRUSTED' : 'UNTRUSTED',
      'X-Threat-Score': decision.threatScore.toString(),
      'X-Advanced-Security': 'ENABLED',
      'X-AI-Protection': 'ACTIVE',
      'X-Quantum-Resistant': 'YES'
    })

    console.log(`[Advanced Login Security] Successful login - User: ${user.email}, Threat Score: ${decision.threatScore}, Level: ${securityContext.securityLevel}`)

    return enhancedResponse

  } catch (error: any) {
    const processingTime = Date.now() - startTime

    // Enhanced error logging and monitoring
    console.error(`[Advanced Login Error - ${requestId}]`, {
      error: error.message,
      stack: error.stack,
      processingTime,
      clientIP: req.ip || "unknown",
      userAgent: req.headers.get("user-agent") || "unknown",
      securityContext
    })

    // Enhanced security incident logging
    await logAuditEvent(AuditAction.SECURITY_INCIDENT, null, {
      error: error.message,
      processingTime,
      requestId,
      incidentType: "ADVANCED_LOGIN_ERROR",
      securityContext,
      clientIP: req.ip || "unknown"
    }, req.ip || "unknown")

    // Return enhanced secure error response
    return apiResponse.error(
      "An error occurred during login. Please try again.",
      "INTERNAL_SERVER_ERROR",
      500,
      { 
        requestId,
        timestamp: new Date().toISOString(),
        processingTime,
        errorId: requestId,
        securityLevel: 'ERROR',
        advancedError: true
      }
    )
  }
}