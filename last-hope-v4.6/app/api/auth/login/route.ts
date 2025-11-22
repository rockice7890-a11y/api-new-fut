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
import crypto from "crypto"
import { z } from "zod"

// Enhanced login schema with device information
const enhancedLoginSchema = loginSchema.extend({
  deviceInfo: z.object({
    fingerprint: z.string().optional(),
    userAgent: z.string(),
    platform: z.string().optional(),
    timezone: z.string().optional(),
    language: z.string().optional(),
  }).optional(),
  trustThisDevice: z.boolean().optional(),
})

// Request tracking and correlation
const generateRequestId = () => `req_${crypto.randomUUID()}`


export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  try {
    // Enhanced security headers and request analysis
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const referer = req.headers.get("referer")
    const origin = req.headers.get("origin")
    
    // Advanced threat detection
    const securityMonitor = new SecurityMonitor()
    const threatScore = await securityMonitor.analyzeThreat({
      ip: clientIP,
      userAgent,
      requestId,
      path: req.nextUrl.pathname,
      method: req.method,
    })

    // Multi-layer rate limiting
    const rateLimitKey = `login:${clientIP}:${userAgent.substring(0, 50)}`
    const rateLimitCheck = rateLimit(rateLimitKey, 5, 5 * 60 * 1000) // Stricter: 5 attempts per 5 minutes
    
    if (!rateLimitCheck.success) {
      await securityMonitor.recordFailedAttempt({
        ip: clientIP,
        userAgent,
        reason: "RATE_LIMIT_EXCEEDED",
        threatLevel: "HIGH"
      })
      
      return apiResponse.error(
        "Too many login attempts. Account temporarily locked for security.",
        "RATE_LIMIT_EXCEEDED",
        429,
        { requestId, retryAfter: "5 minutes" }
      )
    }

    // Input validation and sanitization
    const rawBody = await req.json()
    const validated = enhancedLoginSchema.parse(rawBody)

    // Device fingerprinting and validation
    const deviceFingerprint = validated.deviceInfo?.fingerprint || 
                             generateDeviceFingerprint({
                               userAgent,
                               platform: validated.deviceInfo?.platform,
                               timezone: validated.deviceInfo?.timezone,
                               language: validated.deviceInfo?.language,
                             })

    // Database query with enhanced security
    const user = await prisma.user.findUnique({
      where: { 
        email: validated.email.toLowerCase().trim(),
        isActive: true, // Only active users
      },
      select: {
        id: true,
        email: true,
        name: true,
        password: true,
        role: true,
        isActive: true,
        isEmailVerified: true,
        lastLogin: true,
        loginAttempts: true,
        lockedUntil: true,
        createdAt: true,
        updatedAt: true,
        // Add device tracking
        devices: {
          where: { isActive: true },
          select: {
            id: true,
            fingerprint: true,
            deviceName: true,
            lastUsed: true,
          }
        }
      }
    })

    // Enhanced user validation
    if (!user) {
      await logAuditEvent(AuditAction.FAILED_AUTH, null, { 
        reason: "USER_NOT_FOUND",
        email: validated.email,
        threatScore,
        requestId 
      }, clientIP)

      await securityMonitor.recordFailedAttempt({
        ip: clientIP,
        userAgent,
        reason: "USER_NOT_FOUND",
        threatLevel: threatScore > 70 ? "CRITICAL" : "MEDIUM"
      })

      return apiResponse.error(
        "Invalid email or password",
        "INVALID_CREDENTIALS",
        401,
        { requestId }
      )
    }

    // Check account lock status
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const lockTimeRemaining = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000 / 60)
      
      await logAuditEvent(AuditAction.FAILED_AUTH, user.id, {
        reason: "ACCOUNT_LOCKED",
        lockedUntil: user.lockedUntil,
        requestId
      }, clientIP)

      return apiResponse.error(
        `Account is locked. Try again in ${lockTimeRemaining} minutes.`,
        "ACCOUNT_LOCKED",
        423,
        { 
          requestId,
          lockTimeRemaining,
          lockedUntil: user.lockedUntil.toISOString()
        }
      )
    }

    // Rate limiting per user account
    const userRateLimitKey = `user_login:${user.id}`
    const userRateLimitCheck = rateLimit(userRateLimitKey, 3, 10 * 60 * 1000)
    
    if (!userRateLimitCheck.success) {
      // Increment login attempts and potentially lock account
      await prisma.user.update({
        where: { id: user.id },
        data: {
          loginAttempts: { increment: 1 },
          lockedUntil: new Date(Date.now() + 15 * 60 * 1000), // Lock for 15 minutes
        }
      })

      await logAuditEvent(AuditAction.ACCOUNT_LOCKED, user.id, {
        reason: "MULTIPLE_FAILED_ATTEMPTS",
        attempts: user.loginAttempts + 1,
        requestId
      }, clientIP)

      return apiResponse.error(
        "Too many failed attempts. Account locked for 15 minutes.",
        "ACCOUNT_LOCKED",
        423,
        { requestId, lockDuration: "15 minutes" }
      )
    }

    // Secure password verification with constant-time comparison
    const isPasswordValid = await bcrypt.compare(validated.password, user.password)
    
    if (!isPasswordValid) {
      // Increment login attempts
      const newAttempts = user.loginAttempts + 1
      const shouldLock = newAttempts >= 5
      
      await prisma.user.update({
        where: { id: user.id },
        data: {
          loginAttempts: newAttempts,
          lockedUntil: shouldLock ? new Date(Date.now() + 15 * 60 * 1000) : null,
        }
      })

      await logAuditEvent(AuditAction.FAILED_AUTH, user.id, {
        reason: "INVALID_PASSWORD",
        attempts: newAttempts,
        locked: shouldLock,
        threatScore,
        requestId
      }, clientIP)

      await securityMonitor.recordFailedAttempt({
        ip: clientIP,
        userAgent,
        reason: "INVALID_PASSWORD",
        userId: user.id,
        threatLevel: threatScore > 50 ? "HIGH" : "MEDIUM"
      })

      return apiResponse.error(
        "Invalid email or password",
        "INVALID_CREDENTIALS",
        401,
        { 
          requestId,
          attemptsRemaining: Math.max(0, 5 - newAttempts)
        }
      )
    }

    // Successful login - reset attempts and update last login
    await prisma.user.update({
      where: { id: user.id },
      data: {
        loginAttempts: 0,
        lockedUntil: null,
        lastLogin: new Date(),
      }
    })

    // Device trust and registration
    const knownDevice = user.devices.find(d => d.fingerprint === deviceFingerprint)
    const isTrustedDevice = knownDevice || validated.trustThisDevice

    if (validated.trustThisDevice && !knownDevice) {
      // Register new trusted device
      await prisma.userDevice.create({
        data: {
          userId: user.id,
          fingerprint: deviceFingerprint,
          deviceName: validated.deviceInfo?.platform || "Unknown Device",
          userAgent,
          isActive: true,
          lastUsed: new Date(),
        }
      })
    } else if (knownDevice) {
      // Update device last used
      await prisma.userDevice.update({
        where: { id: knownDevice.id },
        data: { lastUsed: new Date() }
      })
    }

    // Generate tokens with enhanced security
    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
      deviceFingerprint,
      requestId,
      isTrustedDevice: !!isTrustedDevice,
    })

    const refreshToken = generateRefreshToken(user.id, deviceFingerprint)

    // Enhanced session management
    const sessionData = {
      userId: user.id,
      deviceFingerprint,
      isTrustedDevice: !!isTrustedDevice,
      threatScore,
      loginTime: new Date().toISOString(),
      requestId,
      ip: clientIP,
      userAgent,
    }

    // Log successful authentication
    await logAuditEvent(AuditAction.USER_LOGIN, user.id, {
      email: user.email,
      deviceFingerprint: deviceFingerprint.substring(0, 20) + "...",
      isTrustedDevice,
      threatScore,
      requestId,
      sessionDuration: Date.now() - startTime,
    }, clientIP)

    // Security monitoring
    await securityMonitor.recordSuccessfulLogin({
      userId: user.id,
      ip: clientIP,
      userAgent,
      deviceFingerprint,
      isTrustedDevice: !!isTrustedDevice,
      threatScore,
    })

    const { password, loginAttempts, lockedUntil, ...userWithoutSensitiveData } = user

    // Enhanced response with security metadata
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
        threatScore,
        sessionId: requestId,
        deviceFingerprint: deviceFingerprint.substring(0, 20) + "...",
      },
      session: {
        expiresIn: 3600, // 1 hour
        refreshExpiresIn: 604800, // 7 days
        loginTime: new Date().toISOString(),
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
      }
    )

    // Secure cookie configuration with additional protections
    response.cookies.set("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60,
      path: "/",
      // Additional security attributes
      domain: process.env.NODE_ENV === "production" ? ".yourdomain.com" : undefined,
    })

    // Set security headers
    const enhancedResponse = addSecurityHeaders(response, {
      'X-Request-ID': requestId,
      'X-Security-Level': threatScore > 30 ? 'HIGH' : 'STANDARD',
      'X-Device-Trust': isTrustedDevice ? 'TRUSTED' : 'UNTRUSTED',
    })

    return enhancedResponse

  } catch (error: any) {
    const processingTime = Date.now() - startTime

    // Enhanced error logging and monitoring
    console.error(`[Login Error - ${requestId}]`, {
      error: error.message,
      stack: error.stack,
      processingTime,
      clientIP: req.headers.get("x-forwarded-for") || "unknown",
      userAgent: req.headers.get("user-agent") || "unknown",
    })

    // Log security incident
    await logAuditEvent(AuditAction.SECURITY_INCIDENT, null, {
      error: error.message,
      processingTime,
      requestId,
      incidentType: "LOGIN_ERROR",
    }, req.headers.get("x-forwarded-for") || "unknown")

    // Return secure error response
    return apiResponse.error(
      "An error occurred during login. Please try again.",
      "INTERNAL_SERVER_ERROR",
      500,
      { 
        requestId,
        timestamp: new Date().toISOString(),
        processingTime,
        errorId: requestId
      }
    )
  }
}
