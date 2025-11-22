import { type NextRequest, NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import { prisma } from "@/lib/prisma"
import { generateToken, generateRefreshToken } from "@/lib/auth"
import { registerSchema } from "@/lib/validation"
import { rateLimit } from "@/lib/rate-limit"
import { addSecurityHeaders } from "@/lib/security"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"
import { z } from "zod"
import crypto from "crypto"

// Enhanced registration request schema with comprehensive validation
const enhancedRegisterSchema = registerSchema.extend({
  clientInfo: z.object({
    userAgent: z.string().optional(),
    platform: z.string().optional(),
    browser: z.string().optional(),
    ipAddress: z.string().optional(),
    deviceFingerprint: z.string().optional(),
    timezone: z.string().optional(),
    language: z.string().optional()
  }).optional(),
  marketingConsent: z.boolean().optional().default(false),
  termsAccepted: z.boolean().refine(val => val === true, {
    message: "Terms and conditions must be accepted"
  }),
  privacyAccepted: z.boolean().refine(val => val === true, {
    message: "Privacy policy must be accepted"
  })
})

// Advanced registration security manager
class AdvancedRegistrationSecurity {
  private static registrationDatabase = new Map<string, {
    attempts: number
    firstAttempt: Date
    lastAttempt: Date
    blockedUntil: Date | null
    email: string | null
    patterns: string[]
    riskScore: number
  }>()
  
  private static readonly MAX_REGISTRATION_ATTEMPTS = 3
  private static readonly SUSPICIOUS_THRESHOLD = 10
  private static readonly BLOCK_THRESHOLD = 80
  private static readonly REGISTRATION_WINDOW = 10 * 60 * 1000 // 10 minutes
  private static readonly BLOCK_DURATION = 60 * 60 * 1000 // 1 hour

  static async analyzeRegistrationAttempt(
    email: string,
    clientIP: string,
    userAgent: string,
    clientInfo: any
  ): Promise<{
    isAllowed: boolean
    riskScore: number
    reason?: string
    shouldBlock: boolean
    recommendations: string[]
  }> {
    const key = `${email}:${clientIP}`
    const currentTime = new Date()
    
    let regData = this.registrationDatabase.get(key)
    
    if (!regData) {
      regData = {
        attempts: 0,
        firstAttempt: currentTime,
        lastAttempt: currentTime,
        blockedUntil: null,
        email,
        patterns: [],
        riskScore: 0
      }
    }
    
    // Check if currently blocked
    if (regData.blockedUntil && currentTime < regData.blockedUntil) {
      return {
        isAllowed: false,
        riskScore: 100,
        reason: "Registration blocked due to suspicious activity",
        shouldBlock: true,
        recommendations: ["Contact support if you believe this is an error"]
      }
    }
    
    // Time-based analysis
    const timeDiff = currentTime.getTime() - regData.firstAttempt.getTime()
    const attemptRate = regData.attempts / (timeDiff / 60000) // attempts per minute
    
    if (attemptRate > 2) {
      regData.patterns.push("high_frequency")
      regData.riskScore += 25
    }
    
    // Email pattern analysis
    if (this.isSuspiciousEmailPattern(email)) {
      regData.patterns.push("suspicious_email")
      regData.riskScore += 30
    }
    
    // User agent analysis
    if (this.isBotUserAgent(userAgent)) {
      regData.patterns.push("bot_registration")
      regData.riskScore += 40
    }
    
    // IP analysis
    if (this.isSuspiciousIP(clientIP)) {
      regData.patterns.push("suspicious_ip")
      regData.riskScore += 35
    }
    
    // Device fingerprinting
    if (clientInfo?.deviceFingerprint) {
      const deviceRisk = this.analyzeDeviceFingerprint(clientInfo.deviceFingerprint)
      regData.riskScore += deviceRisk
    }
    
    // Update attempt tracking
    regData.attempts++
    regData.lastAttempt = currentTime
    regData.email = email
    
    // Block if risk is too high
    if (regData.riskScore >= this.BLOCK_THRESHOLD) {
      regData.blockedUntil = new Date(currentTime.getTime() + this.BLOCK_DURATION)
      regData.riskScore = 100
      
      this.registrationDatabase.set(key, regData)
      
      return {
        isAllowed: false,
        riskScore: 100,
        reason: "Registration blocked due to high risk score",
        shouldBlock: true,
        recommendations: ["Contact support for assistance"]
      }
    }
    
    // Allow if under suspicious threshold
    const isAllowed = regData.riskScore < this.SUSPICIOUS_THRESHOLD && regData.attempts <= this.MAX_REGISTRATION_ATTEMPTS
    
    if (!isAllowed && regData.attempts > this.MAX_REGISTRATION_ATTEMPTS) {
      regData.patterns.push("too_many_attempts")
      regData.riskScore += 20
    }
    
    this.registrationDatabase.set(key, regData)
    
    const recommendations = this.generateRecommendations(regData.patterns)
    
    return {
      isAllowed,
      riskScore: regData.riskScore,
      reason: !isAllowed ? "Registration attempt denied" : undefined,
      shouldBlock: regData.riskScore >= this.BLOCK_THRESHOLD,
      recommendations
    }
  }
  
  private static isSuspiciousEmailPattern(email: string): boolean {
    const suspiciousPatterns = [
      /^temp\d+@/, // temp emails
      /^user\d+@/, // generic usernames
      /^admin\d*@/, // admin attempts
      /^test\d*@/, // test accounts
      /^guest\d*@/, // guest attempts
      /@10minutemail\.com$/, // temp email domains
      /@guerrillamail\.com$/,
      /@mailinator\.com$/,
      /@yopmail\.com$/
    ]
    
    return suspiciousPatterns.some(pattern => pattern.test(email.toLowerCase()))
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
  
  private static isSuspiciousIP(ip: string): boolean {
    // Check against known suspicious IP ranges or patterns
    const suspiciousPatterns = [
      /^192\.168\./, // Private IP range
      /^10\./, // Private IP range  
      /^172\.(1[6-9]|2[0-9]|3[01])\./, // Private IP range
      /^127\./, // Localhost
      /^0\.0\.0\.0$/, // Unknown
    ]
    
    return suspiciousPatterns.some(pattern => pattern.test(ip))
  }
  
  private static analyzeDeviceFingerprint(fingerprint: string): number {
    // Simplified device fingerprint analysis
    if (!fingerprint || fingerprint.length < 10) {
      return 20 // Unknown device
    }
    
    // Check for common patterns that might indicate automation
    if (fingerprint.includes('automation') || fingerprint.includes('bot')) {
      return 30
    }
    
    return 0 // Normal fingerprint
  }
  
  private static generateRecommendations(patterns: string[]): string[] {
    const recommendations: string[] = []
    
    if (patterns.includes('high_frequency')) {
      recommendations.push("Reduce registration frequency")
    }
    if (patterns.includes('suspicious_email')) {
      recommendations.push("Use a valid email address")
    }
    if (patterns.includes('bot_registration')) {
      recommendations.push("Use a standard web browser")
    }
    if (patterns.includes('suspicious_ip')) {
      recommendations.push("Check your network connection")
    }
    if (patterns.includes('too_many_attempts')) {
      recommendations.push("Wait before attempting again")
    }
    
    return recommendations
  }
  
  static cleanupOldEntries(): void {
    const currentTime = new Date()
    const maxAge = 24 * 60 * 60 * 1000 // 24 hours
    
    for (const [key, data] of this.registrationDatabase.entries()) {
      const timeDiff = currentTime.getTime() - data.firstAttempt.getTime()
      if (timeDiff > maxAge) {
        this.registrationDatabase.delete(key)
      }
    }
  }
  
  static getRegistrationContext(): string {
    return `Registration_${crypto.randomUUID()}`
  }
}

// Performance monitoring
const registrationMonitor = {
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
    
    console.log(`[Registration Performance] ${JSON.stringify(metadata)}`)
    return metadata
  }
}

// Enhanced registration handler
export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  registrationMonitor.init()
  
  try {
    const clientIP = req.headers.get("x-forwarded-for")?.split(',')[0]?.trim() || 
                    req.headers.get("x-real-ip") || 
                    req.headers.get("cf-connecting-ip") || 
                    "unknown"
    
    const userAgent = req.headers.get("user-agent") || "unknown"
    const correlationId = registrationMonitor.correlationId
    
    console.log(`[Registration Request] CorrelationID: ${correlationId}, IP: ${clientIP}, UA: ${userAgent}`)
    
    // Basic rate limiting check
    const rateLimitCheck = rateLimit(`register:${clientIP}`, 3, 10 * 60 * 1000) // 3 attempts per 10 min
    if (!rateLimitCheck.success) {
      await logAuditEvent(
        AuditAction.RATE_LIMIT_EXCEEDED,
        "unknown",
        {
          error: "Rate limit exceeded for registration",
          correlationId,
          clientIP
        },
        clientIP
      )
      
      const endResult = registrationMonitor.end(false, true, 90)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Too many registration attempts. Try again later.",
            code: "RATE_LIMIT_EXCEEDED",
            correlationId,
            retryAfter: Math.ceil(rateLimitCheck.remainingTime / 1000),
            timestamp: new Date().toISOString()
          },
          { status: 429 }
        )
      )
    }
    
    // Parse request body
    let body: any = {}
    try {
      body = await req.json()
    } catch (e) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Invalid JSON in registration request",
          correlationId
        },
        clientIP
      )
      
      const endResult = registrationMonitor.end(false, true, 70)
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
    
    // Enhanced validation with comprehensive schema
    const validationResult = enhancedRegisterSchema.safeParse(body)
    if (!validationResult.success) {
      await logAuditEvent(
        AuditAction.SECURITY_VIOLATION,
        "unknown",
        {
          error: "Registration validation failed",
          validationErrors: validationResult.error.errors,
          correlationId
        },
        clientIP
      )
      
      const endResult = registrationMonitor.end(false, true, 60)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Invalid registration data",
            code: "VALIDATION_FAILED",
            correlationId,
            errors: validationResult.error.errors,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    const validated = validationResult.data
    const { clientInfo, marketingConsent, termsAccepted, privacyAccepted } = validated
    
    // Advanced security analysis
    const securityAnalysis = await AdvancedRegistrationSecurity.analyzeRegistrationAttempt(
      validated.email.toLowerCase(),
      clientIP,
      userAgent,
      clientInfo
    )
    
    if (!securityAnalysis.isAllowed) {
      await logAuditEvent(
        AuditAction.SUSPICIOUS_ACTIVITY,
        "unknown",
        {
          error: "Registration blocked by security analysis",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          reason: securityAnalysis.reason,
          patterns: securityAnalysis.recommendations,
          email: validated.email.toLowerCase()
        },
        clientIP
      )
      
      const endResult = registrationMonitor.end(false, true, securityAnalysis.riskScore)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: securityAnalysis.reason || "Registration not allowed",
            code: "REGISTRATION_BLOCKED",
            correlationId,
            riskScore: securityAnalysis.riskScore,
            recommendations: securityAnalysis.recommendations,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        )
      )
    }
    
    // Check for existing user
    const existingUser = await prisma.user.findUnique({
      where: { email: validated.email.toLowerCase() },
      select: { 
        id: true, 
        email: true, 
        isActive: true,
        failedLoginAttempts: true,
        lastLoginAt: true
      }
    })
    
    if (existingUser) {
      await logAuditEvent(
        AuditAction.DUPLICATE_REGISTRATION,
        existingUser.id,
        {
          error: "Registration attempted for existing user",
          correlationId,
          riskScore: securityAnalysis.riskScore,
          existingUser: {
            id: existingUser.id,
            isActive: existingUser.isActive,
            lastLoginAt: existingUser.lastLoginAt
          }
        },
        clientIP
      )
      
      const endResult = registrationMonitor.end(false, false, securityAnalysis.riskScore)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "User with this email already exists",
            code: "USER_EXISTS",
            correlationId,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    // Password strength validation (additional layer)
    const passwordAnalysis = this.analyzePasswordStrength(validated.password)
    if (passwordAnalysis.riskScore > 30) {
      await logAuditEvent(
        AuditAction.WEAK_PASSWORD,
        "unknown",
        {
          error: "Weak password attempted",
          correlationId,
          passwordAnalysis,
          email: validated.email.toLowerCase()
        },
        clientIP
      )
      
      const endResult = registrationMonitor.end(false, true, passwordAnalysis.riskScore)
      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Password does not meet security requirements",
            code: "WEAK_PASSWORD",
            correlationId,
            passwordRecommendations: passwordAnalysis.recommendations,
            timestamp: new Date().toISOString()
          },
          { status: 400 }
        )
      )
    }
    
    // Hash password with enhanced security
    const hashedPassword = await bcrypt.hash(validated.password, 14) // Increased rounds
    
    // Create user with comprehensive data
    const user = await prisma.user.create({
      data: {
        email: validated.email.toLowerCase(),
        password: hashedPassword,
        firstName: validated.firstName,
        lastName: validated.lastName,
        role: "USER",
        isActive: true,
        marketingConsent,
        termsAcceptedAt: termsAccepted ? new Date() : null,
        privacyAcceptedAt: privacyAccepted ? new Date() : null,
        lastLoginAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date()
      },
      select: { 
        id: true, 
        email: true, 
        role: true, 
        firstName: true, 
        lastName: true,
        isActive: true,
        createdAt: true
      },
    })
    
    // Generate tokens
    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    })
    
    const refreshToken = generateRefreshToken(user.id)
    
    // Enhanced audit logging
    await logAuditEvent(
      AuditAction.USER_REGISTER,
      user.id,
      {
        correlationId,
        riskScore: securityAnalysis.riskScore,
        clientInfo,
        marketingConsent,
        email: user.email,
        registrationMethod: "standard"
      },
      clientIP
    )
    
    // Enhanced response with security metadata
    const response = addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          message: "User registered successfully",
          data: { 
            user: {
              id: user.id,
              email: user.email,
              role: user.role,
              firstName: user.firstName,
              lastName: user.lastName,
              createdAt: user.createdAt
            }, 
            token, 
            refreshToken 
          },
          security: {
            correlationId,
            riskScore: securityAnalysis.riskScore,
            registrationMethod: "standard",
            timestamp: new Date().toISOString()
          }
        },
        { status: 201 }
      )
    )
    
    // Set secure refresh token cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
      path: "/",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      signed: true,
      domain: process.env.NODE_ENV === "production" ? ".yourdomain.com" : undefined
    }
    
    response.cookies.set("refreshToken", refreshToken, cookieOptions)
    
    // Security headers
    response.headers.set("X-Registration-Timestamp", new Date().toISOString())
    response.headers.set("X-Security-Level", securityAnalysis.riskScore > 50 ? "elevated" : "normal")
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    
    const endResult = registrationMonitor.end(true, false, securityAnalysis.riskScore)
    console.log(`[Registration Success] User: ${user.id}, Email: ${user.email}, Risk: ${securityAnalysis.riskScore}, Duration: ${endResult.duration}ms, CorrelationID: ${correlationId}`)
    
    return response
    
  } catch (error: any) {
    console.error("[Registration Error]", error)
    
    await logAuditEvent(
      AuditAction.SYSTEM_ERROR,
      "system",
      {
        error: error.message,
        stack: error.stack,
        correlationId: registrationMonitor.correlationId,
        endpoint: "/api/auth/register"
      },
      req.headers.get("x-forwarded-for") || "unknown"
    )
    
    const endResult = registrationMonitor.end(false, false, 0)
    
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "error",
          message: "Registration process failed",
          code: "REGISTRATION_FAILED",
          correlationId: registrationMonitor.correlationId,
          timestamp: new Date().toISOString()
        },
        { status: 500 }
      )
    )
  }
}

// Password strength analysis
function analyzePasswordStrength(password: string): { riskScore: number; recommendations: string[] } {
  let riskScore = 0
  const recommendations: string[] = []
  
  // Length check
  if (password.length < 8) {
    riskScore += 30
    recommendations.push("Use at least 8 characters")
  } else if (password.length < 12) {
    riskScore += 15
    recommendations.push("Consider using 12+ characters for better security")
  }
  
  // Complexity checks
  if (!/[A-Z]/.test(password)) {
    riskScore += 10
    recommendations.push("Include uppercase letters")
  }
  
  if (!/[a-z]/.test(password)) {
    riskScore += 10
    recommendations.push("Include lowercase letters")
  }
  
  if (!/[0-9]/.test(password)) {
    riskScore += 10
    recommendations.push("Include numbers")
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    riskScore += 15
    recommendations.push("Include special characters")
  }
  
  // Common patterns
  const commonPatterns = ['123', 'abc', 'password', 'qwerty', '111', '000']
  if (commonPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
    riskScore += 25
    recommendations.push("Avoid common patterns")
  }
  
  return { riskScore, recommendations }
}

// OPTIONS handler for CORS
export async function OPTIONS(req: NextRequest) {
  const response = new NextResponse(null, { status: 200 })
  return addSecurityHeaders(response)
}

// Cleanup function
export async function cleanup() {
  AdvancedRegistrationSecurity.cleanupOldEntries()
}
