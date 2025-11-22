import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { generateToken, verifyRefreshToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"
import { z } from "zod"
import crypto from "crypto"

// Enhanced refresh token request schema
const refreshRequestSchema = z.object({
  clientInfo: z.object({
    deviceId: z.string().min(1).optional(),
    userAgent: z.string().optional(),
    platform: z.string().optional(),
    browser: z.string().optional(),
    fingerprint: z.string().optional()
  }).optional(),
  forceRefresh: z.boolean().optional().default(false)
})

// Advanced refresh token security manager
class AdvancedRefreshSecurity {
  private static refreshDatabase = new Map<string, {
    userId: string
    refreshCount: number
    lastRefresh: Date
    deviceInfo: any
    riskScore: number
    isCompromised: boolean
  }>()
  
  private static readonly MAX_REFRESH_ATTEMPTS = 20
  private static readonly SUSPICIOUS_THRESHOLD = 15
  private static readonly COMPROMISE_THRESHOLD = 80
  private static readonly REFRESH_WINDOW = 300000 // 5 minutes

  static async validateRefreshAttempt(
    userId: string,
    clientIP: string,
    userAgent: string,
    deviceInfo: any
  ): Promise<{
    isValid: boolean
    riskScore: number
    reason?: string
    shouldRevoke: boolean
  }> {
    const key = `${userId}:${clientIP}:${userAgent}`
    const currentTime = new Date()
    
    let refreshData = this.refreshDatabase.get(key)
    
    if (!refreshData) {
      refreshData = {
        userId,
        refreshCount: 0,
        lastRefresh: currentTime,
        deviceInfo,
        riskScore: 0,
        isCompromised: false
      }
    }
    
    // Time-based validation
    const timeDiff = currentTime.getTime() - refreshData.lastRefresh.getTime()
    
    if (timeDiff < this.REFRESH_WINDOW) {
      refreshData.refreshCount++
      refreshData.riskScore += 5 // Gradual risk increase
    } else {
      refreshData.refreshCount = 1 // Reset counter for new window
      refreshData.riskScore = Math.max(0, refreshData.riskScore - 10) // Gradual risk decrease
    }
    
    // Device fingerprint validation
    const isNewDevice = this.isNewDevicePattern(refreshData.deviceInfo, deviceInfo)
    if (isNewDevice) {
      refreshData.riskScore += 25
    }
    
    // Pattern analysis
    if (refreshData.refreshCount > this.MAX_REFRESH_ATTEMPTS) {
      refreshData.riskScore = Math.min(100, refreshData.riskScore + 40)
      refreshData.isCompromised = true
    } else if (refreshData.refreshCount > this.SUSPICIOUS_THRESHOLD) {
      refreshData.riskScore = Math.min(100, refreshData.riskScore + 20)
    }
    
    // User agent analysis
    if (this.isSuspiciousUserAgent(userAgent)) {
      refreshData.riskScore = Math.min(100, refreshData.riskScore + 15)
    }
    
    // IP change detection
    if (this.detectIPChange(userId, clientIP)) {
      refreshData.riskScore = Math.min(100, refreshData.riskScore + 30)
    }
    
    refreshData.lastRefresh = currentTime
    refreshData.deviceInfo = deviceInfo
    
    this.refreshDatabase.set(key, refreshData)
    
    const isValid = refreshData.riskScore < this.COMPROMISE_THRESHOLD
    const shouldRevoke = refreshData.riskScore >= this.COMPROMISE_THRESHOLD
    
    return {
      isValid,
      riskScore: refreshData.riskScore,
      reason: shouldRevoke ? 'Token compromised' : 
             !isValid ? 'High risk detected' : undefined,
      shouldRevoke
    }
  }
  
  private static isNewDevicePattern(oldDevice: any, newDevice: any): boolean {
    if (!oldDevice || !newDevice) return false
    
    const oldFingerprint = oldDevice.fingerprint || 'unknown'
    const newFingerprint = newDevice.fingerprint || 'unknown'
    
    const oldBrowser = oldDevice.browser || 'unknown'
    const newBrowser = newDevice.browser || 'unknown'
    
    const oldPlatform = oldDevice.platform || 'unknown'
    const newPlatform = newDevice.platform || 'unknown'
    
    return oldFingerprint !== newFingerprint || 
           oldBrowser !== newBrowser || 
           oldPlatform !== newPlatform
  }
  
  private static isSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      'bot', 'crawler', 'spider', 'scraper', 'automation',
      'python-requests', 'curl', 'wget', 'postman', 'insomnia'
    ]
    
    return suspiciousPatterns.some(pattern => 
      userAgent.toLowerCase().includes(pattern)
    )
  }
  
  private static async detectIPChange(userId: string, newIP: string): Promise<boolean> {
    // In a real implementation, would query database for recent IP history
    return false // Simplified for demo
  }
  
  static async revokeAllUserTokens(userId: string): Promise<void> {
    // Remove all refresh data for this user
    const keysToDelete: string[] = []
    
    for (const [key, data] of this.refreshDatabase.entries()) {
      if (data.userId === userId) {
        keysToDelete.push(key)
      }
    }
    
    keysToDelete.forEach(key => this.refreshDatabase.delete(key))
  }
  
  static getRefreshContext(): string {
    return `Refresh_${crypto.randomUUID()}`
  }
  
  static cleanupOldEntries(): void {
    const currentTime = new Date()
    const maxAge = 24 * 60 * 60 * 1000 // 24 hours
    
    for (const [key, data] of this.refreshDatabase.entries()) {
      const timeDiff = currentTime.getTime() - data.lastRefresh.getTime()
      if (timeDiff > maxAge) {
        this.refreshDatabase.delete(key)
      }
    }
  }
}

// Performance and security monitoring
const refreshMonitor = {
  startTime: 0,
  correlationId: '',
  
  init() {
    this.startTime = Date.now()
    this.correlationId = crypto.randomUUID()
  },
  
  end(success: boolean, riskDetected: boolean = false, riskScore: number = 0) {
    const duration = Date.now() - this.startTime
    const metadata = {
      correlationId: this.correlationId,
      duration,
      success,
      riskDetected,
      riskScore,
      timestamp: new Date().toISOString()
    }
    
    console.log(`[Refresh Performance] ${JSON.stringify(metadata)}`)
    return metadata
  }
}

// Enhanced refresh token handler
export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  refreshMonitor.init()
  
  try {
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.headers.get("cf-connecting-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const correlationId = refreshMonitor.correlationId
    
    console.log(`[Refresh Request] CorrelationID: ${correlationId}, IP: ${clientIP}, UA: ${userAgent}`)
    
    // Parse and validate request
    let requestData = {}
    try {
      requestData = await req.json()
    } catch (e) {
      // Continue with cookie-only refresh if no JSON body
    }
    
    const validationResult = refreshRequestSchema.safeParse(requestData)
    if (!validationResult.success) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid refresh request format",
          validationError: validationResult.error.message,
          correlationId
        },
        clientIP
      )
      
      const endResult = refreshMonitor.end(false, true, 50)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid request format",
            code: "INVALID_FORMAT",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    const { clientInfo, forceRefresh } = validationResult.data
    const refreshToken = req.cookies.get("refreshToken")?.value
    
    if (!refreshToken) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Missing refresh token",
          correlationId,
          clientInfo
        },
        clientIP
      )
      
      const endResult = refreshMonitor.end(false, true, 60)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Refresh token missing",
            code: "NO_REFRESH_TOKEN",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    // Enhanced refresh token verification
    const payload = verifyRefreshToken(refreshToken)
    if (!payload) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid refresh token",
          correlationId,
          tokenPreview: refreshToken.substring(0, 15) + "...",
          clientInfo
        },
        clientIP
      )
      
      const endResult = refreshMonitor.end(false, true, 70)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid or expired refresh token",
            code: "INVALID_REFRESH_TOKEN",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    const userId = payload.userId as string
    
    // Validate user still exists and is active
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { 
        id: true, 
        email: true, 
        role: true, 
        isActive: true,
        lastLoginAt: true,
        failedLoginAttempts: true
      },
    })
    
    if (!user) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        userId,
        {
          error: "User not found during refresh",
          correlationId
        },
        clientIP
      )
      
      const endResult = refreshMonitor.end(false, true, 80)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "User account not found",
            code: "USER_NOT_FOUND",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 404 }
        )
      )
    }
    
    if (!user.isActive) {
      await logAuditEvent(
        AuditAction.ACCOUNT_BLOCKED,
        userId,
        {
          error: "Attempted refresh on inactive account",
          correlationId
        },
        clientIP
      )
      
      const endResult = refreshMonitor.end(false, true, 90)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Account is deactivated",
            code: "ACCOUNT_INACTIVE",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    // Advanced security validation
    const securityValidation = await AdvancedRefreshSecurity.validateRefreshAttempt(
      userId, clientIP, userAgent, clientInfo
    )
    
    if (!securityValidation.isValid) {
      // Revoke compromised tokens
      await AdvancedRefreshSecurity.revokeAllUserTokens(userId)
      
      await logAuditEvent(
        AuditAction.SUSPICIOUS_ACTIVITY,
        userId,
        {
          error: "Suspicious refresh token activity",
          correlationId,
          riskScore: securityValidation.riskScore,
          riskReason: securityValidation.reason,
          securityValidation
        },
        clientIP
      )
      
      // Force logout by clearing all tokens
      const response = addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Token refresh denied due to security concerns",
            code: "SECURITY_VIOLATION",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
      
      // Clear all potentially compromised tokens
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict" as const,
        path: "/",
        maxAge: 0
      }
      
      response.cookies.set("refreshToken", "", cookieOptions)
      response.cookies.set("authToken", "", cookieOptions)
      response.cookies.set("sessionToken", "", cookieOptions)
      
      const endResult = refreshMonitor.end(false, true, securityValidation.riskScore)
      return response
    }
    
    // Generate new tokens with enhanced security
    const newTokens = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    })
    
    const newRefreshToken = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
      tokenType: "refresh"
    })
    
    // Update user login information
    await prisma.user.update({
      where: { id: user.id },
      data: { 
        lastLoginAt: new Date(),
        updatedAt: new Date()
      }
    })
    
    // Enhanced response with security metadata
    const response = addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          message: "Token refreshed successfully",
          data: {
            token: newTokens,
            refreshToken: newRefreshToken,
            user: {
              id: user.id,
              email: user.email,
              role: user.role
            }
          },
          security: {
            correlationId,
            riskScore: securityValidation.riskScore,
            refreshCount: "tracked", // Simplified
            timestamp: new Date().toISOString()
          }
        },
        { status: 200 }
      )
    )
    
    // Set enhanced refresh token cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
      path: "/",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      // Security enhancements
      signed: true,
      domain: process.env.NODE_ENV === "production" ? ".yourdomain.com" : undefined
    }
    
    response.cookies.set("refreshToken", newRefreshToken, cookieOptions)
    
    // Security headers
    response.headers.set("X-Refresh-Timestamp", new Date().toISOString())
    response.headers.set("X-Security-Level", securityValidation.riskScore > 50 ? "elevated" : "normal")
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    
    await logAuditEvent(
      AuditAction.TOKEN_REFRESH,
      userId,
      {
        correlationId,
        riskScore: securityValidation.riskScore,
        clientInfo,
        forceRefresh
      },
      clientIP
    )
    
    const endResult = refreshMonitor.end(true, false, securityValidation.riskScore)
    console.log(`[Refresh Success] User: ${userId}, Risk: ${securityValidation.riskScore}, Duration: ${endResult.duration}ms, CorrelationID: ${correlationId}`)
    
    return response
    
  } catch (error: any) {
    console.error("[Refresh Token Error]", error)
    
    await logAuditEvent(
      AuditAction.SYSTEM_ERROR,
      "system",
      {
        error: error.message,
        stack: error.stack,
        correlationId: refreshMonitor.correlationId,
        endpoint: "/api/auth/refresh"
      },
      req.headers.get("x-forwarded-for") || "unknown"
    )
    
    const endResult = refreshMonitor.end(false, false, 0)
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "error",
          message: "Token refresh operation failed",
          code: "REFRESH_FAILED",
          correlationId: refreshMonitor.correlationId,
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

// Cleanup function (to be called periodically)
export async function cleanup() {
  AdvancedRefreshSecurity.cleanupOldEntries()
}
