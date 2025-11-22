import { type NextRequest, NextResponse } from "next/server"
import { addSecurityHeaders } from "@/lib/security"
import { verifyToken } from "@/lib/auth"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"
import { z } from "zod"
import crypto from "crypto"

// Enhanced verification request schema
const verifyTokenRequestSchema = z.object({
  clientInfo: z.object({
    userAgent: z.string().optional(),
    platform: z.string().optional(),
    browser: z.string().optional(),
    deviceId: z.string().optional(),
    ipAddress: z.string().optional(),
    sessionId: z.string().optional()
  }).optional(),
  refreshIfValid: z.boolean().optional().default(false)
})

// Advanced token verification security manager
class AdvancedTokenVerificationSecurity {
  private static verificationDatabase = new Map<string, {
    attempts: number
    firstAttempt: Date
    lastAttempt: Date
    blockedUntil: Date | null
    tokenHash: string | null
    patterns: string[]
    riskScore: number
    lastValidVerification: Date | null
  }>()
  
  private static readonly MAX_VERIFICATION_ATTEMPTS = 10
  private static readonly SUSPICIOUS_THRESHOLD = 15
  private static readonly BLOCK_THRESHOLD = 90
  private static readonly VERIFICATION_WINDOW = 5 * 60 * 1000 // 5 minutes
  private static readonly BLOCK_DURATION = 30 * 60 * 1000 // 30 minutes

  static async analyzeVerificationAttempt(
    clientIP: string,
    userAgent: string,
    token: string,
    clientInfo: any
  ): Promise<{
    isAllowed: boolean
    riskScore: number
    reason?: string
    shouldBlock: boolean
    patterns: string[]
  }> {
    const key = `${clientIP}:${userAgent}`
    const currentTime = new Date()
    const tokenHash = this.hashToken(token)
    
    let verifyData = this.verificationDatabase.get(key)
    
    if (!verifyData) {
      verifyData = {
        attempts: 0,
        firstAttempt: currentTime,
        lastAttempt: currentTime,
        blockedUntil: null,
        tokenHash: null,
        patterns: [],
        riskScore: 0,
        lastValidVerification: null
      }
    }
    
    // Check if currently blocked
    if (verifyData.blockedUntil && currentTime < verifyData.blockedUntil) {
      return {
        isAllowed: false,
        riskScore: 100,
        reason: "Token verification blocked due to suspicious activity",
        shouldBlock: true,
        patterns: ["blocked"]
      }
    }
    
    // Time-based analysis
    const timeDiff = currentTime.getTime() - verifyData.firstAttempt.getTime()
    const attemptRate = verifyData.attempts / (timeDiff / 60000) // attempts per minute
    
    if (attemptRate > 5) {
      verifyData.patterns.push("high_frequency")
      verifyData.riskScore += 25
    }
    
    // Token reuse detection
    if (verifyData.tokenHash === tokenHash) {
      verifyData.patterns.push("token_reuse")
      verifyData.riskScore += 20
    } else {
      verifyData.tokenHash = tokenHash
    }
    
    // User agent analysis
    if (this.isBotUserAgent(userAgent)) {
      verifyData.patterns.push("bot_verification")
      verifyData.riskScore += 30
    }
    
    // Client info analysis
    if (clientInfo?.sessionId) {
      const sessionRisk = this.analyzeSessionId(clientInfo.sessionId)
      verifyData.riskScore += sessionRisk
    }
    
    // Update attempt tracking
    verifyData.attempts++
    verifyData.lastAttempt = currentTime
    
    // Block if risk is too high
    if (verifyData.riskScore >= this.BLOCK_THRESHOLD) {
      verifyData.blockedUntil = new Date(currentTime.getTime() + this.BLOCK_DURATION)
      verifyData.riskScore = 100
      
      this.verificationDatabase.set(key, verifyData)
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: "Token verification blocked due to high risk score",
        shouldBlock: true,
        patterns: verifyData.patterns
      }
    }
    
    // Allow if under suspicious threshold
    const isAllowed = verifyData.riskScore < this.SUSPICIOUS_THRESHOLD && verifyData.attempts <= this.MAX_VERIFICATION_ATTEMPTS
    
    if (!isAllowed && verifyData.attempts > this.MAX_VERIFICATION_ATTEMPTS) {
      verifyData.patterns.push("too_many_attempts")
      verifyData.riskScore += 20
    }
    
    this.verificationDatabase.set(key, verifyData)
    
    return {
      isAllowed,
      riskScore: verifyData.riskScore,
      reason: !isAllowed ? "Token verification attempt denied" : undefined,
      shouldBlock: verifyData.riskScore >= this.BLOCK_THRESHOLD,
      patterns: verifyData.patterns
    }
  }
  
  private static hashToken(token: string): string {
    // Simple hash for token tracking (not cryptographically secure)
    return crypto.createHash('md5').update(token).digest('hex').substring(0, 16)
  }
  
  private static isBotUserAgent(userAgent: string): boolean {
    const botPatterns = [
      'bot', 'crawler', 'spider', 'scraper', 'automation',
      'python', 'curl', 'wget', 'postman', 'insomnia',
      'selenium', 'phantom', 'puppeteer', 'playwright'
    ]
    
    return botPatterns.some(pattern => 
      userAgent.toLowerCase().includes(pattern)
    )
  }
  
  private static analyzeSessionId(sessionId: string): number {
    if (!sessionId || sessionId.length < 8) {
      return 15 // Suspicious short session ID
    }
    
    // Check for predictable patterns
    if (sessionId.includes('123') || sessionId.includes('abc')) {
      return 20
    }
    
    return 0 // Normal session ID
  }
  
  static updateLastValidVerification(clientIP: string, userAgent: string): void {
    const key = `${clientIP}:${userAgent}`
    const currentTime = new Date()
    
    let verifyData = this.verificationDatabase.get(key)
    if (verifyData) {
      verifyData.lastValidVerification = currentTime
      verifyData.attempts = Math.max(0, verifyData.attempts - 1) // Reduce attempts on success
      verifyData.riskScore = Math.max(0, verifyData.riskScore - 5) // Reduce risk on success
      verifyData.patterns = verifyData.patterns.filter(p => 
        !['high_frequency', 'suspicious'].includes(p)
      )
      this.verificationDatabase.set(key, verifyData)
    }
  }
  
  static cleanupOldEntries(): void {
    const currentTime = new Date()
    const maxAge = 12 * 60 * 60 * 1000 // 12 hours
    
    for (const [key, data] of this.verificationDatabase.entries()) {
      const timeDiff = currentTime.getTime() - data.firstAttempt.getTime()
      if (timeDiff > maxAge) {
        this.verificationDatabase.delete(key)
      }
    }
  }
  
  static getVerificationContext(): string {
    return `Verify_${crypto.randomUUID()}`
  }
}

// Performance monitoring
const verificationMonitor = {
  startTime: 0,
  correlationId: '',
  
  init() {
    this.startTime = Date.now()
    this.correlationId = crypto.randomUUID()
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
      timestamp: new Date().toISOString()
    }
    
    console.log(`[Token Verification Performance] ${JSON.stringify(metadata)}`)
    return metadata
  }
}

// Enhanced token verification handler
export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  verificationMonitor.init()
  
  try {
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.headers.get("cf-connecting-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const correlationId = verificationMonitor.correlationId
    
    console.log(`[Token Verification Request] CorrelationID: ${correlationId}, IP: ${clientIP}, UA: ${userAgent}`)
    
    // Parse request body
    let requestData = {}
    try {
      requestData = await req.json()
    } catch (e) {
      // Continue with header-only verification if no JSON body
    }
    
    const validationResult = verifyTokenRequestSchema.safeParse(requestData)
    if (!validationResult.success) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid verification request format",
          validationError: validationResult.error.message,
          correlationId
        },
        clientIP
      )
      
      const endResult = verificationMonitor.end(false, true, 60, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid request format",
            code: "INVALID_FORMAT",
            correlationId,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    const { clientInfo, refreshIfValid } = validationResult.data
    
    // Check authorization header
    const authHeader = req.headers.get("authorization")
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      const securityAnalysis = await AdvancedTokenVerificationSecurity.analyzeVerificationAttempt(
        clientIP, userAgent, "no_token", clientInfo
      )
      
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Missing authorization header",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          patterns: securityAnalysis.patterns
        },
        clientIP
      )
      
      const endResult = verificationMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Authorization token required",
            code: "NO_TOKEN",
            correlationId,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    const token = authHeader.substring(7)
    
    // Advanced security analysis
    const securityAnalysis = await AdvancedTokenVerificationSecurity.analyzeVerificationAttempt(
      clientIP, userAgent, token, clientInfo
    )
    
    if (!securityAnalysis.isAllowed) {
      await logAuditEvent(
        AuditAction.SUSPICIOUS_ACTIVITY,
        "unknown",
        {
          error: "Token verification blocked by security analysis",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          reason: securityAnalysis.reason,
          patterns: securityAnalysis.patterns,
          tokenPreview: token.substring(0, 15) + "..."
        },
        clientIP
      )
      
      const endResult = verificationMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: securityAnalysis.reason || "Token verification not allowed",
            code: "VERIFICATION_BLOCKED",
            correlationId,
            riskScore: securityAnalysis.riskScore,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    // Token verification
    const decoded = verifyToken(token)
    const isValid = !!decoded
    
    if (!isValid) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid token during verification",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          patterns: securityAnalysis.patterns,
          tokenPreview: token.substring(0, 15) + "..."
        },
        clientIP
      )
      
      const endResult = verificationMonitor.end(false, true, securityAnalysis.riskScore, false)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid authentication token",
            code: "INVALID_TOKEN",
            correlationId,
            valid: false,
            timestamp: new Date().toISOString()
          },
          { status: 401 }
        )
      )
    }
    
    // Update security data for successful verification
    AdvancedTokenVerificationSecurity.updateLastValidVerification(clientIP, userAgent)
    
    // Enhanced response with comprehensive security metadata
    const response = addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          valid: true,
          data: { 
            userId: decoded.userId, 
            email: decoded.email, 
            role: decoded.role,
            tokenInfo: {
              issued: decoded.iat ? new Date(decoded.iat * 1000).toISOString() : null,
              expires: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : null
            }
          },
          security: {
            correlationId,
            riskScore: securityAnalysis.riskScore,
            verificationMethod: "standard",
            timestamp: new Date().toISOString()
          }
        },
        { status: 200 }
      )
    )
    
    // Security headers
    response.headers.set("X-Verification-Timestamp", new Date().toISOString())
    response.headers.set("X-Security-Level", securityAnalysis.riskScore > 50 ? "elevated" : "normal")
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    
    // Audit logging for successful verification
    await logAuditEvent(
      AuditAction.TOKEN_VERIFICATION,
      decoded.userId,
      {
        correlationId,
        riskScore: securityAnalysis.riskScore,
        clientInfo,
        refreshIfValid,
        email: decoded.email
      },
      clientIP
    )
    
    const endResult = verificationMonitor.end(true, false, securityAnalysis.riskScore, true)
    console.log(`[Token Verification Success] User: ${decoded.userId}, Risk: ${securityAnalysis.riskScore}, Duration: ${endResult.duration}ms, CorrelationID: ${correlationId}`)
    
    return response
    
  } catch (error: any) {
    console.error("[Token Verification Error]", error)
    
    await logAuditEvent(
      AuditAction.SYSTEM_ERROR,
      "system",
      {
        error: error.message,
        stack: error.stack,
        correlationId: verificationMonitor.correlationId,
        endpoint: "/api/auth/verify-token"
      },
      req.headers.get("x-forwarded-for") || "unknown"
    )
    
    const endResult = verificationMonitor.end(false, false, 0, false)
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "error",
          message: "Token verification process failed",
          code: "VERIFICATION_FAILED",
          correlationId: verificationMonitor.correlationId,
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
  AdvancedTokenVerificationSecurity.cleanupOldEntries()
}
