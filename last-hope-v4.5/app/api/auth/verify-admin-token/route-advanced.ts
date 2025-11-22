import { type NextRequest, NextResponse } from "next/server"
import { addSecurityHeaders } from "@/lib/security"
import { verifyToken } from "@/lib/auth"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"
import { z } from "zod"
import crypto from "crypto"

// Enhanced admin token verification with elevated security
const verifyAdminTokenRequestSchema = z.object({
  clientInfo: z.object({
    userAgent: z.string().optional(),
    platform: z.string().optional(),
    browser: z.string().optional(),
    deviceId: z.string().optional(),
    ipAddress: z.string().optional(),
    adminLevel: z.enum(['basic', 'elevated', 'super']).optional()
  }).optional(),
  requireRecentActivity: z.boolean().optional().default(true)
})

// Advanced admin token security with enterprise-level protection
class AdminTokenVerificationSecurity {
  private static adminVerificationDatabase = new Map<string, {
    attempts: number
    firstAttempt: Date
    lastAttempt: Date
    blockedUntil: Date | null
    adminLevel: string | null
    riskScore: number
    lastValidVerification: Date | null
    patterns: string[]
    securityFlags: string[]
  }>()
  
  private static readonly MAX_ADMIN_VERIFICATION_ATTEMPTS = 5
  private static readonly SUSPICIOUS_THRESHOLD = 10
  private static readonly BLOCK_THRESHOLD = 95
  private static readonly VERIFICATION_WINDOW = 3 * 60 * 1000 // 3 minutes (stricter for admin)
  private static readonly BLOCK_DURATION = 60 * 60 * 1000 // 1 hour (longer for admin)

  static async analyzeAdminVerificationAttempt(
    clientIP: string,
    userAgent: string,
    token: string,
    clientInfo: any,
    adminLevel: string
  ): Promise<{
    isAllowed: boolean
    riskScore: number
    reason?: string
    shouldBlock: boolean
    patterns: string[]
    securityFlags: string[]
  }> {
    const key = `${adminLevel}:${clientIP}:${userAgent}`
    const currentTime = new Date()
    
    let verifyData = this.adminVerificationDatabase.get(key)
    
    if (!verifyData) {
      verifyData = {
        attempts: 0,
        firstAttempt: currentTime,
        lastAttempt: currentTime,
        blockedUntil: null,
        adminLevel,
        riskScore: 0,
        lastValidVerification: null,
        patterns: [],
        securityFlags: []
      }
    }
    
    // Check if currently blocked (stricter for admin)
    if (verifyData.blockedUntil && currentTime < verifyData.blockedUntil) {
      return {
        isAllowed: false,
        riskScore: 100,
        reason: "Admin token verification blocked",
        shouldBlock: true,
        patterns: ["admin_blocked"],
        securityFlags: ["ADMIN_SECURITY_BREACH"]
      }
    }
    
    // Enhanced time-based analysis for admin access
    const timeDiff = currentTime.getTime() - verifyData.firstAttempt.getTime()
    const attemptRate = verifyData.attempts / (timeDiff / 60000)
    
    if (attemptRate > 2) { // More restrictive for admin
      verifyData.patterns.push("admin_high_frequency")
      verifyData.securityFlags.push("SUSPICIOUS_ADMIN_ACTIVITY")
      verifyData.riskScore += 35
    }
    
    // Admin-specific security checks
    if (this.isUnauthorizedAdminAccess(userAgent, clientInfo)) {
      verifyData.patterns.push("unauthorized_admin_access")
      verifyData.securityFlags.push("UNAUTHORIZED_ADMIN_REQUEST")
      verifyData.riskScore += 50
    }
    
    // Admin level escalation detection
    if (clientInfo?.adminLevel && clientInfo.adminLevel !== adminLevel) {
      verifyData.patterns.push("admin_escalation")
      verifyData.securityFlags.push("ADMIN_LEVEL_ESCALATION")
      verifyData.riskScore += 40
    }
    
    // IP range security for admin access
    if (this.isRestrictedAdminIP(clientIP)) {
      verifyData.patterns.push("restricted_admin_ip")
      verifyData.securityFlags.push("RESTRICTED_ADMIN_NETWORK")
      verifyData.riskScore += 60
    }
    
    // Update attempt tracking
    verifyData.attempts++
    verifyData.lastAttempt = currentTime
    verifyData.adminLevel = adminLevel
    
    // Stricter blocking for admin access
    if (verifyData.riskScore >= this.BLOCK_THRESHOLD) {
      verifyData.blockedUntil = new Date(currentTime.getTime() + this.BLOCK_DURATION)
      verifyData.riskScore = 100
      verifyData.securityFlags.push("ADMIN_ACCESS_REVOKED")
      
      this.adminVerificationDatabase.set(key, verifyData)
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: "Admin access revoked due to security violations",
        shouldBlock: true,
        patterns: verifyData.patterns,
        securityFlags: verifyData.securityFlags
      }
    }
    
    // More restrictive allowance for admin
    const isAllowed = verifyData.riskScore < this.SUSPICIOUS_THRESHOLD && verifyData.attempts <= this.MAX_ADMIN_VERIFICATION_ATTEMPTS
    
    if (!isAllowed && verifyData.attempts > this.MAX_ADMIN_VERIFICATION_ATTEMPTS) {
      verifyData.patterns.push("admin_too_many_attempts")
      verifyData.securityFlags.push("EXCESSIVE_ADMIN_ATTEMPTS")
      verifyData.riskScore += 30
    }
    
    this.adminVerificationDatabase.set(key, verifyData)
    
    return {
      isAllowed,
      riskScore: verifyData.riskScore,
      reason: !isAllowed ? "Admin verification attempt denied" : undefined,
      shouldBlock: verifyData.riskScore >= this.BLOCK_THRESHOLD,
      patterns: verifyData.patterns,
      securityFlags: verifyData.securityFlags
    }
  }
  
  private static isUnauthorizedAdminAccess(userAgent: string, clientInfo: any): boolean {
    // Check for automation or unauthorized tools
    const unauthorizedPatterns = [
      'bot', 'crawler', 'scraper', 'automation', 'python', 'curl', 'wget'
    ]
    
    return unauthorizedPatterns.some(pattern => 
      userAgent.toLowerCase().includes(pattern)
    ) || this.isUnusualAdminClient(clientInfo)
  }
  
  private static isUnusualAdminClient(clientInfo: any): boolean {
    if (!clientInfo) return false
    
    // Check for common admin interfaces
    const expectedClients = ['chrome', 'firefox', 'safari', 'edge', 'admin-panel']
    const browser = clientInfo.browser?.toLowerCase()
    
    return !browser || !expectedClients.some(expected => browser.includes(expected))
  }
  
  private static isRestrictedAdminIP(ip: string): boolean {
    // Define restricted IP ranges for admin access
    const restrictedPatterns = [
      /^192\.168\./, // Private network
      /^10\./, // Private network
      /^172\.(1[6-9]|2[0-9]|3[01])\./, // Private network
      /^127\./, // Localhost
      /^0\.0\.0\.0$/ // Unknown
    ]
    
    return restrictedPatterns.some(pattern => pattern.test(ip))
  }
  
  static updateLastValidAdminVerification(clientIP: string, userAgent: string, adminLevel: string): void {
    const key = `${adminLevel}:${clientIP}:${userAgent}`
    const currentTime = new Date()
    
    let verifyData = this.adminVerificationDatabase.get(key)
    if (verifyData) {
      verifyData.lastValidVerification = currentTime
      verifyData.attempts = Math.max(0, verifyData.attempts - 2) // Reduce attempts more for admin
      verifyData.riskScore = Math.max(0, verifyData.riskScore - 10) // Reduce risk more for admin
      verifyData.securityFlags = verifyData.securityFlags.filter(flag => 
        !['SUSPICIOUS_ADMIN_ACTIVITY', 'EXCESSIVE_ADMIN_ATTEMPTS'].includes(flag)
      )
      this.adminVerificationDatabase.set(key, verifyData)
    }
  }
  
  static cleanupOldEntries(): void {
    const currentTime = new Date()
    const maxAge = 6 * 60 * 60 * 1000 // 6 hours for admin (shorter retention)
    
    for (const [key, data] of this.adminVerificationDatabase.entries()) {
      const timeDiff = currentTime.getTime() - data.firstAttempt.getTime()
      if (timeDiff > maxAge) {
        this.adminVerificationDatabase.delete(key)
      }
    }
  }
}

// Performance monitoring for admin verification
const adminVerificationMonitor = {
  startTime: 0,
  correlationId: '',
  
  init() {
    this.startTime = Date.now()
    this.correlationId = `Admin_${crypto.randomUUID()}`
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
      level: 'admin',
      timestamp: new Date().toISOString()
    }
    
    console.log(`[Admin Token Verification Performance] ${JSON.stringify(metadata)}`)
    return metadata
  }
}

// Enhanced admin token verification handler
export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  adminVerificationMonitor.init()
  
  try {
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.headers.get("cf-connecting-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const correlationId = adminVerificationMonitor.correlationId
    
    console.log(`[Admin Token Verification Request] CorrelationID: ${correlationId}, IP: ${clientIP}, UA: ${userAgent}`)
    
    // Parse request body
    let requestData = {}
    try {
      requestData = await req.json()
    } catch (e) {
      // Continue with header-only verification if no JSON body
    }
    
    const validationResult = verifyAdminTokenRequestSchema.safeParse(requestData)
    if (!validationResult.success) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid admin verification request format",
          validationError: validationResult.error.message,
          correlationId,
          level: 'admin'
        },
        clientIP
      )
      
      const endResult = adminVerificationMonitor.end(false, true, 70, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid request format",
            code: "INVALID_FORMAT",
            correlationId,
            valid: false,
            level: "admin",
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    const { clientInfo, requireRecentActivity } = validationResult.data
    
    // Enhanced authorization header check
    const authHeader = req.headers.get("authorization")
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      const securityAnalysis = await AdminTokenVerificationSecurity.analyzeAdminVerificationAttempt(
        clientIP, userAgent, "no_token", clientInfo, "unknown"
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
          level: 'admin'
        },
        clientIP
      )
      
      const endResult = adminVerificationMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Admin authorization token required",
            code: "NO_ADMIN_TOKEN",
            correlationId,
            valid: false,
            level: "admin",
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    const token = authHeader.substring(7)
    
    // Extract admin level from token
    const decoded = verifyToken(token)
    if (!decoded) {
      await logAuditEvent(
        AuditAction.ADMIN_SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid admin token during verification",
          correlationId,
          tokenPreview: token.substring(0, 15) + "...",
          level: 'admin'
        },
        clientIP
      )
      
      const endResult = adminVerificationMonitor.end(false, true, 80, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid admin authentication token",
            code: "INVALID_ADMIN_TOKEN",
            correlationId,
            valid: false,
            level: "admin",
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    // Check if user has admin privileges
    if (!decoded.role || !['ADMIN', 'SUPER_ADMIN', 'MANAGER'].includes(decoded.role)) {
      await logAuditEvent(
        AuditAction.UNAUTHORIZED_ADMIN_ACCESS,
        decoded.userId,
        {
          error: "Non-admin user attempted admin verification",
          correlationId,
          userRole: decoded.role,
          level: 'admin'
        },
        clientIP
      )
      
      const endResult = adminVerificationMonitor.end(false, true, 90, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Insufficient privileges for admin verification",
            code: "INSUFFICIENT_ADMIN_PRIVILEGES",
            correlationId,
            valid: false,
            level: "admin",
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    const adminLevel = decoded.role === 'SUPER_ADMIN' ? 'super' : 
                      decoded.role === 'MANAGER' ? 'elevated' : 'basic'
    
    // Advanced admin security analysis
    const securityAnalysis = await AdminTokenVerificationSecurity.analyzeAdminVerificationAttempt(
      clientIP, userAgent, token, clientInfo, adminLevel
    )
    
    if (!securityAnalysis.isAllowed) {
      await logAuditEvent(
        AuditAction.ADMIN_SUSPICIOUS_ACTIVITY,
        decoded.userId,
        {
          error: "Admin verification blocked by security analysis",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          reason: securityAnalysis.reason,
          patterns: securityAnalysis.patterns,
          securityFlags: securityAnalysis.securityFlags,
          adminLevel,
          userRole: decoded.role
        },
        clientIP
      )
      
      const endResult = adminVerificationMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: securityAnalysis.reason || "Admin verification not allowed",
            code: "ADMIN_VERIFICATION_BLOCKED",
            correlationId,
            riskScore: securityAnalysis.riskScore,
            valid: false,
            level: "admin",
            securityFlags: securityAnalysis.securityFlags,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    // Recent activity check for admin access
    if (requireRecentActivity && decoded.iat) {
      const tokenAge = Date.now() / 1000 - decoded.iat
      const maxAge = 4 * 60 * 60 // 4 hours for admin (shorter than regular users)
      
      if (tokenAge > maxAge) {
        await logAuditEvent(
          AuditAction.STALE_ADMIN_TOKEN,
          decoded.userId,
          {
            error: "Stale admin token detected",
            correlationId,
            tokenAge,
            maxAge,
            adminLevel
          },
          clientIP
        )
        
        const endResult = adminVerificationMonitor.end(false, true, 75, false)
        return addSecurityHeaders(
          NextResponse.json(
            {
              status: "error",
              message: "Admin token has expired. Please re-authenticate.",
              code: "STALE_ADMIN_TOKEN",
              correlationId,
              valid: false,
              level: "admin",
              timestamp: new Date().toISOString()
            },
            { status: 401 }
          )
        )
      }
    }
    
    // Update security data for successful admin verification
    AdminTokenVerificationSecurity.updateLastValidAdminVerification(clientIP, userAgent, adminLevel)
    
    // Enhanced response with comprehensive admin security metadata
    const response = addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          valid: true,
          level: "admin",
          data: { 
            userId: decoded.userId, 
            email: decoded.email, 
            role: decoded.role,
            adminLevel,
            permissions: {
              canManageUsers: ['ADMIN', 'SUPER_ADMIN'].includes(decoded.role),
              canManageSystem: decoded.role === 'SUPER_ADMIN',
              canViewAnalytics: ['ADMIN', 'MANAGER', 'SUPER_ADMIN'].includes(decoded.role)
            },
            tokenInfo: {
              issued: decoded.iat ? new Date(decoded.iat * 1000).toISOString() : null,
              expires: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : null,
              age: decoded.iat ? Math.floor((Date.now() / 1000 - decoded.iat) / 60) : null
            }
          },
          security: {
            correlationId,
            riskScore: securityAnalysis.riskScore,
            verificationMethod: "admin",
            securityFlags: securityAnalysis.securityFlags,
            requireRecentActivity,
            timestamp: new Date().toISOString()
          }
        },
        { status: 200 }
      )
    )
    
    // Enhanced security headers for admin access
    response.headers.set("X-Admin-Verification-Timestamp", new Date().toISOString())
    response.headers.set("X-Security-Level", "admin_elevated")
    response.headers.set("X-Admin-Level", adminLevel)
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set("X-Admin-Security", "enabled")
    
    // Audit logging for successful admin verification
    await logAuditEvent(
      AuditAction.ADMIN_TOKEN_VERIFICATION,
      decoded.userId,
      {
        correlationId,
        riskScore: securityAnalysis.riskScore,
        clientInfo,
        adminLevel,
        userRole: decoded.role,
        securityFlags: securityAnalysis.securityFlags,
        requireRecentActivity,
        email: decoded.email
      },
      clientIP
    )
    
    const endResult = adminVerificationMonitor.end(true, false, securityAnalysis.riskScore, true)
    console.log(`[Admin Token Verification Success] User: ${decoded.userId}, Role: ${decoded.role}, AdminLevel: ${adminLevel}, Risk: ${securityAnalysis.riskScore}, Duration: ${endResult.duration}ms, CorrelationID: ${correlationId}`)
    
    return response
    
  } catch (error: any) {
    console.error("[Admin Token Verification Error]", error)
    
    await logAuditEvent(
      AuditAction.ADMIN_SYSTEM_ERROR,
      "system",
      {
        error: error.message,
        stack: error.stack,
        correlationId: adminVerificationMonitor.correlationId,
        endpoint: "/api/auth/verify-admin-token",
        level: 'admin'
      },
      req.headers.get("x-forwarded-for") || "unknown"
    )
    
    const endResult = adminVerificationMonitor.end(false, false, 0, false)
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "error",
          message: "Admin token verification process failed",
          code: "ADMIN_VERIFICATION_FAILED",
          correlationId: adminVerificationMonitor.correlationId,
          valid: false,
          level: "admin",
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
  AdminTokenVerificationSecurity.cleanupOldEntries()
}
