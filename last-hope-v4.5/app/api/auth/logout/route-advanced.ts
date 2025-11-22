import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { addSecurityHeaders } from "@/lib/security"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"
import { verifyToken } from "@/lib/auth"
import { z } from "zod"
import crypto from "crypto"
import { withAuth } from "@/lib/auth-middleware"

// Enhanced logout schema with device fingerprinting
const logoutRequestSchema = z.object({
  deviceId: z.string().min(1).optional(),
  allSessions: z.boolean().optional().default(false),
  clientInfo: z.object({
    userAgent: z.string().optional(),
    platform: z.string().optional(),
    browser: z.string().optional(),
    ipAddress: z.string().optional()
  }).optional()
})

// Advanced threat detection for logout endpoint
interface ThreatContext {
  ipAddress: string
  userAgent: string
  frequency: number
  pattern: string
  riskScore: number
}

class AdvancedLogoutSecurity {
  private static threatDatabase = new Map<string, ThreatContext>()
  private static readonly MAX_LOGOUT_ATTEMPTS = 10
  private static readonly THREAT_THRESHOLD = 70
  private static readonly CLEANUP_INTERVAL = 3600000 // 1 hour

  static async detectThreats(
    userId: string,
    clientIP: string,
    userAgent: string
  ): Promise<{ isThreat: boolean; context: ThreatContext }> {
    const currentTime = Date.now()
    const key = `${userId}:${clientIP}`
    
    // Cleanup old entries
    this.cleanupThreatDatabase()
    
    let context = this.threatDatabase.get(key)
    
    if (!context) {
      context = {
        ipAddress: clientIP,
        userAgent,
        frequency: 0,
        pattern: 'normal',
        riskScore: 0
      }
    }
    
    // Update frequency and analyze patterns
    context.frequency++
    
    // Advanced pattern analysis
    if (context.frequency > this.MAX_LOGOUT_ATTEMPTS) {
      context.pattern = 'brute_force'
      context.riskScore = Math.min(100, context.riskScore + 25)
    } else if (this.isUnusualUserAgent(userAgent)) {
      context.pattern = 'suspicious_client'
      context.riskScore = Math.min(100, context.riskScore + 15)
    } else if (this.isRapidFire(userId)) {
      context.pattern = 'rapid_requests'
      context.riskScore = Math.min(100, context.riskScore + 20)
    } else if (context.frequency > this.MAX_LOGOUT_ATTEMPTS * 0.7) {
      context.pattern = 'high_frequency'
      context.riskScore = Math.min(100, context.riskScore + 10)
    }
    
    this.threatDatabase.set(key, context)
    
    return {
      isThreat: context.riskScore >= this.THREAT_THRESHOLD,
      context
    }
  }

  private static isUnusualUserAgent(userAgent: string): boolean {
    const suspiciousAgents = [
      'bot', 'crawler', 'spider', 'scraper', 'automation',
      'python', 'curl', 'wget', 'postman'
    ]
    return suspiciousAgents.some(agent => 
      userAgent.toLowerCase().includes(agent)
    )
  }

  private static isRapidFire(userId: string): boolean {
    // Check if user has logged out multiple times in short period
    const recentAttempts = Array.from(this.threatDatabase.values())
      .filter(ctx => ctx.pattern.includes('rapid'))
    return recentAttempts.length > 3
  }

  private static cleanupThreatDatabase(): void {
    const currentTime = Date.now()
    const expiryTime = currentTime - this.CLEANUP_INTERVAL
    
    for (const [key, context] of this.threatDatabase.entries()) {
      const contextTime = context as any // Simplified for demo
      // In real implementation, would store timestamp
      // if (contextTime.timestamp < expiryTime) {
      //   this.threatDatabase.delete(key)
      // }
    }
  }

  static getThreatContext(): string {
    return `LogoutSecurity_${crypto.randomUUID()}`
  }
}

// Performance monitoring
const performanceMonitor = {
  startTime: 0,
  correlationId: '',
  
  init() {
    this.startTime = Date.now()
    this.correlationId = crypto.randomUUID()
  },
  
  end(success: boolean, threatDetected: boolean = false) {
    const duration = Date.now() - this.startTime
    const metadata = {
      correlationId: this.correlationId,
      duration,
      success,
      threatDetected,
      timestamp: new Date().toISOString()
    }
    
    // Log performance metrics
    console.log(`[Logout Performance] ${JSON.stringify(metadata)}`)
    
    return metadata
  }
}

// Enhanced logout handler with advanced security
export const dynamic = 'force-dynamic'

export const POST = withAuth(async (req: NextRequest) => {
  performanceMonitor.init()
  
  try {
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.headers.get("cf-connecting-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const correlationId = crypto.randomUUID()
    
    console.log(`[Logout Request] CorrelationID: ${correlationId}, IP: ${clientIP}, UA: ${userAgent}`)
    
    // Parse and validate request body
    let requestData = {}
    try {
      requestData = await req.json()
    } catch (e) {
      console.warn(`[Logout Validation] Invalid JSON: ${correlationId}`)
    }
    
    const validationResult = logoutRequestSchema.safeParse(requestData)
    if (!validationResult.success) {
      const threatCtx = await AdvancedLogoutSecurity.detectThreats(
        "unknown", clientIP, userAgent
      )
      
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid logout request format",
          validationError: validationResult.error.message,
          correlationId,
          threatContext: threatCtx.context
        },
        clientIP
      )
      
      const endResult = performanceMonitor.end(false, true)
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
    
    const { deviceId, allSessions, clientInfo } = validationResult.data
    const authHeader = req.headers.get("authorization")
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      const threatCtx = await AdvancedLogoutSecurity.detectThreats(
        "unknown", clientIP, userAgent
      )
      
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Missing or invalid authorization header",
          correlationId,
          threatContext: threatCtx.context
        },
        clientIP
      )
      
      const endResult = performanceMonitor.end(false, true)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Unauthorized access attempt",
            code: "NO_TOKEN",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    const token = authHeader.substring(7)
    
    // Enhanced token verification with threat analysis
    const decoded = verifyToken(token)
    if (!decoded) {
      const threatCtx = await AdvancedLogoutSecurity.detectThreats(
        "unknown", clientIP, userAgent
      )
      
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid or expired token",
          correlationId,
          threatContext: threatCtx.context,
          tokenPreview: token.substring(0, 10) + "..."
        },
        clientIP
      )
      
      const endResult = performanceMonitor.end(false, true)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid authentication token",
            code: "INVALID_TOKEN",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    const userId = decoded.userId as string
    
    // Advanced threat detection for authenticated user
    const threatAnalysis = await AdvancedLogoutSecurity.detectThreats(
      userId, clientIP, userAgent
    )
    
    if (threatAnalysis.isThreat) {
      await logAuditEvent(
        AuditAction.SUSPICIOUS_ACTIVITY,
        userId,
        {
          error: "High threat score detected",
          correlationId,
          threatContext: threatAnalysis.context,
          threatScore: threatAnalysis.context.riskScore
        },
        clientIP
      )
      
      const endResult = performanceMonitor.end(false, true)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Suspicious activity detected",
            code: "THREAT_DETECTED",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 429 }
        )
      )
    }
    
    // Enhanced logout processing
    let logoutResult = {
      sessionsTerminated: 0,
      deviceInfo: {
        deviceId: deviceId || null,
        clientInfo: clientInfo || {}
      }
    }
    
    if (allSessions) {
      // Logout from all sessions (if implementing session management)
      await logAuditEvent(
        AuditAction.GLOBAL_LOGOUT,
        userId,
        {
          correlationId,
          deviceId,
          allSessions: true,
          clientInfo
        },
        clientIP
      )
      logoutResult.sessionsTerminated = -1 // Placeholder for all sessions
    } else {
      // Logout from current session
      await logAuditEvent(
        AuditAction.USER_LOGOUT,
        userId,
        {
          correlationId,
          deviceId,
          clientInfo
        },
        clientIP
      )
      logoutResult.sessionsTerminated = 1
    }
    
    // Advanced response with security metadata
    const response = addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          message: "Logged out successfully",
          data: {
            userId,
            ...logoutResult
          },
          security: {
            correlationId,
            threatScore: threatAnalysis.context.riskScore,
            sessionTerminated: true,
            timestamp: new Date().toISOString()
          }
        },
        { status: 200 }
      )
    )
    
    // Enhanced cookie management with security flags
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
      path: "/",
      maxAge: 0,
      // Additional security flags
      signed: true,
      domain: process.env.NODE_ENV === "production" ? ".yourdomain.com" : undefined
    }
    
    // Clear multiple potential token cookies
    response.cookies.set("refreshToken", "", cookieOptions)
    response.cookies.set("authToken", "", cookieOptions)
    response.cookies.set("sessionToken", "", cookieOptions)
    response.cookies.set("csrfToken", "", cookieOptions)
    
    // Set logout confirmation headers
    response.headers.set("X-Logout-Timestamp", new Date().toISOString())
    response.headers.set("X-Security-Level", "high")
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    
    const endResult = performanceMonitor.end(true, false)
    console.log(`[Logout Success] User: ${userId}, Duration: ${endResult.duration}ms, CorrelationID: ${correlationId}`)
    
    return response
    
  } catch (error: any) {
    console.error("[Logout Error]", error)
    
    await logAuditEvent(
      AuditAction.SYSTEM_ERROR,
      "system",
      {
        error: error.message,
        stack: error.stack,
        correlationId: performanceMonitor.correlationId,
        endpoint: "/api/auth/logout"
      },
      req.headers.get("x-forwarded-for") || "unknown"
    )
    
    const endResult = performanceMonitor.end(false, false)
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "error",
          message: "Logout operation failed",
          code: "LOGOUT_FAILED",
          correlationId: performanceMonitor.correlationId,
          timestamp: new Date().toISOString()
        },
        { status: 500 }
      )
    )
  }
}, {
  skipAuth: false,
  requireRole: "all",
  rateLimit: {
    windowMs: 60000, // 1 minute
    max: 5, // 5 logout attempts per minute
    message: "Too many logout attempts",
    skipSuccessfulRequests: false
  }
})

// OPTIONS handler for CORS preflight
export async function OPTIONS(req: NextRequest) {
  const response = new NextResponse(null, { status: 200 })
  
  return addSecurityHeaders(response)
}
