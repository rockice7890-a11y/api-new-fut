import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse } from "@/lib/api-response"
import { auditLogger } from "@/lib/audit-logger"
import { securityMonitor } from "@/lib/security-monitor"
import { securitySafe } from "@/lib/security-safe"
import { rateLimit } from "@/lib/rate-limit"
import { jwtVerify } from "jose"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Security constants
const SECURITY_CONFIG = {
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 30,
  CACHE_TTL: 60 * 1000, // 1 minute
  SESSION_VALIDATION_TIMEOUT: 5 * 60 * 1000, // 5 minutes
  ANALYTICS_RETENTION_DAYS: 30,
  SENSITIVE_DATA_MASKING: true,
  ENCRYPTION_ENABLED: true
}

// Advanced analytics security state
interface AnalyticsSecurityState {
  requestId: string
  deviceFingerprint: string
  userAgent: string
  ipAddress: string
  riskScore: number
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  sessionToken: string
  correlationId: string
  accessLevel: 'BASIC' | 'ADVANCED' | 'EXECUTIVE'
  dataScope: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'
}

class AdvancedAnalyticsSecurity {
  private static instance: AdvancedAnalyticsSecurity
  private securityContext: Map<string, AnalyticsSecurityState> = new Map()
  private requestPatterns: Map<string, number[]> = new Map()
  private analyticsPatterns: Map<string, any> = new Map()

  private constructor() {}

  static getInstance(): AdvancedAnalyticsSecurity {
    if (!AdvancedAnalyticsSecurity.instance) {
      AdvancedAnalyticsSecurity.instance = new AdvancedAnalyticsSecurity()
    }
    return AdvancedAnalyticsSecurity.instance
  }

  // Generate unique identifiers
  private generateRequestId(): string {
    return crypto.randomUUID()
  }

  private generateCorrelationId(): string {
    return crypto.randomUUID()
  }

  // Extract and validate device information
  private extractDeviceInfo(req: NextRequest): { fingerprint: string; userAgent: string } {
    const userAgent = req.headers.get('user-agent') || 'Unknown'
    
    const fingerprintComponents = [
      userAgent,
      req.headers.get('accept-language') || '',
      req.headers.get('accept-encoding') || '',
      req.headers.get('sec-ch-ua') || '',
      req.headers.get('sec-ch-ua-platform') || '',
    ].join('|')

    const fingerprint = crypto
      .createHash('sha256')
      .update(fingerprintComponents)
      .digest('hex')
      .substring(0, 32)

    return { fingerprint, userAgent }
  }

  // AI-powered threat detection for analytics access
  private analyzeAnalyticsThreat(context: AnalyticsSecurityState): {
    threatScore: number
    detectedThreats: string[]
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    accessLevel: 'BASIC' | 'ADVANCED' | 'EXECUTIVE'
    dataScope: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'
  } {
    const threats: string[] = []
    let threatScore = 0

    // Analyze access patterns
    const recentRequests = this.requestPatterns.get(context.ipAddress) || []
    const now = Date.now()
    const recentRequestCount = recentRequests.filter(timestamp => 
      now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW
    ).length

    // High frequency analytics access
    if (recentRequestCount > 15) {
      threats.push('EXCESSIVE_ANALYTICS_ACCESS')
      threatScore += 25
    }

    // Unusual access times (potential automated scraping)
    if (this.isUnusualTimeForAnalytics()) {
      threats.push('UNUSUAL_TIME_ACCESS')
      threatScore += 20
    }

    // Check for suspicious user agents (bots, scrapers)
    if (this.isSuspiciousUserAgent(context.userAgent)) {
      threats.push('SUSPICIOUS_USER_AGENT')
      threatScore += 30
    }

    // Geographic anomaly detection (simplified)
    if (this.isHighRiskIP(context.ipAddress)) {
      threats.push('HIGH_RISK_IP_ADDRESS')
      threatScore += 40
    }

    // Device fingerprinting anomalies
    if (this.isDeviceAnomaly(context.deviceFingerprint)) {
      threats.push('DEVICE_ANOMALY')
      threatScore += 15
    }

    // Determine access level based on risk and user role
    let accessLevel: 'BASIC' | 'ADVANCED' | 'EXECUTIVE' = 'BASIC'
    let dataScope: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' = 'INTERNAL'

    if (threatScore === 0 && recentRequestCount < 5) {
      accessLevel = 'EXECUTIVE'
      dataScope = 'CONFIDENTIAL'
    } else if (threatScore < 15) {
      accessLevel = 'ADVANCED'
      dataScope = 'INTERNAL'
    }

    // Risk level determination
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    if (threatScore >= 60) riskLevel = 'CRITICAL'
    else if (threatScore >= 40) riskLevel = 'HIGH'
    else if (threatScore >= 20) riskLevel = 'MEDIUM'

    return { threatScore, detectedThreats: threats, riskLevel, accessLevel, dataScope }
  }

  private isUnusualTimeForAnalytics(): boolean {
    const hour = new Date().getHours()
    const dayOfWeek = new Date().getDay()
    
    // Flag access during off-hours (11 PM - 6 AM) or weekends for high-frequency access
    if (hour >= 23 || hour <= 6) return true
    if (dayOfWeek === 0 || dayOfWeek === 6) return true // Sunday or Saturday
    return false
  }

  private isSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      /bot|crawler|spider/i,
      /scraper|harvester/i,
      /python|curl|wget/i,
      /postman/i,
      /automation/i
    ]
    return suspiciousPatterns.some(pattern => pattern.test(userAgent))
  }

  private isHighRiskIP(ipAddress: string): boolean {
    // Simplified high-risk IP detection
    // In production, integrate with threat intelligence feeds
    const privateRanges = ['127.', '192.168.', '10.', '172.16.']
    const isPrivate = privateRanges.some(range => ipAddress.startsWith(range))
    
    // For demo: Flag localhost or test IPs as potentially suspicious for analytics
    return isPrivate && ipAddress !== '127.0.0.1'
  }

  private isDeviceAnomaly(fingerprint: string): boolean {
    // Simple anomaly detection based on fingerprint patterns
    // In production, maintain device fingerprint history
    return fingerprint.length < 16 || !/^[a-f0-9]+$/.test(fingerprint)
  }

  // Advanced session validation for analytics
  private async validateAnalyticsSession(req: NextRequest, userId: string): Promise<{
    isValid: boolean
    sessionState: any
    violations: string[]
    accessLevel: 'BASIC' | 'ADVANCED' | 'EXECUTIVE'
  }> {
    const violations: string[] = []
    
    try {
      const sessionToken = req.headers.get('x-session-token')
      const refreshToken = req.headers.get('x-refresh-token')
      
      if (!sessionToken) {
        violations.push('MISSING_SESSION_TOKEN')
        return { isValid: false, sessionState: null, violations, accessLevel: 'BASIC' }
      }

      // JWT session validation
      const secret = new TextEncoder().encode(process.env.REFRESH_TOKEN_SECRET || 'fallback-secret')
      const { payload } = await jwtVerify(sessionToken, secret)
      
      // Session expiration check
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        violations.push('SESSION_EXPIRED')
        return { isValid: false, sessionState: null, violations, accessLevel: 'BASIC' }
      }

      // Analytics-specific session validation
      const sessionRole = payload.role as string
      const analyticsAccessLevel = this.determineAccessLevel(sessionRole)
      
      return { 
        isValid: violations.length === 0, 
        sessionState: payload, 
        violations,
        accessLevel: analyticsAccessLevel
      }
    } catch (error) {
      violations.push('SESSION_VALIDATION_ERROR')
      return { isValid: false, sessionState: null, violations, accessLevel: 'BASIC' }
    }
  }

  private determineAccessLevel(role: string): 'BASIC' | 'ADVANCED' | 'EXECUTIVE' {
    switch (role?.toUpperCase()) {
      case 'SUPER_ADMIN':
      case 'EXECUTIVE':
        return 'EXECUTIVE'
      case 'ADMIN':
      case 'MANAGER':
        return 'ADVANCED'
      default:
        return 'BASIC'
    }
  }

  // Mask sensitive analytics data
  private maskAnalyticsData(data: any, accessLevel: string, threatLevel: string): any {
    // Apply different masking based on access level and threat level
    const masked = { ...data }

    if (accessLevel === 'BASIC' || threatLevel === 'HIGH' || threatLevel === 'CRITICAL') {
      // Mask or reduce sensitive metrics for basic access or high threat
      if (masked.totalRevenue !== undefined) {
        masked.totalRevenue = this.maskFinancialData(masked.totalRevenue)
      }
      if (masked.avgBookingValue !== undefined) {
        masked.avgBookingValue = this.maskFinancialData(masked.avgBookingValue)
      }
    }

    return masked
  }

  private maskFinancialData(amount: number): number {
    // Round to nearest thousand for basic access
    return Math.round(amount / 1000) * 1000
  }

  // Record security event
  private recordSecurityEvent(event: any): void {
    try {
      auditLogger.log({
        event: 'ANALYTICS_ACCESS',
        level: 'INFO',
        userId: event.userId,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: {
          requestId: event.requestId,
          correlationId: event.correlationId,
          accessLevel: event.accessLevel,
          dataScope: event.dataScope,
          threatLevel: event.threatLevel,
          riskScore: event.riskScore
        }
      })
    } catch (error) {
      console.error('Failed to record analytics security event:', error)
    }
  }

  // Main security processing
  public async processRequest(req: NextRequest): Promise<{
    isAllowed: boolean
    context: AnalyticsSecurityState
    violations: string[]
    recommendations: string[]
    accessLevel: 'BASIC' | 'ADVANCED' | 'EXECUTIVE'
    dataScope: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'
  }> {
    const requestId = this.generateRequestId()
    const correlationId = this.generateCorrelationId()
    
    const { fingerprint, userAgent } = this.extractDeviceInfo(req)
    const ipAddress = req.headers.get('x-forwarded-for') || req.ip || 'unknown'

    const context: AnalyticsSecurityState = {
      requestId,
      deviceFingerprint: fingerprint,
      userAgent,
      ipAddress,
      riskScore: 0,
      threatLevel: 'LOW',
      sessionToken: req.headers.get('x-session-token') || '',
      correlationId,
      accessLevel: 'BASIC',
      dataScope: 'INTERNAL'
    }

    const violations: string[] = []
    const recommendations: string[] = []

    try {
      // Rate limiting check
      const rateLimitKey = `${ipAddress}:analytics-summary`
      const rateLimitResult = await rateLimit.check(rateLimitKey, SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS, SECURITY_CONFIG.RATE_LIMIT_WINDOW)
      
      if (!rateLimitResult.allowed) {
        violations.push('RATE_LIMIT_EXCEEDED')
        recommendations.push('Implement exponential backoff for analytics requests')
      }

      // Record request pattern
      const now = Date.now()
      const requests = this.requestPatterns.get(ipAddress) || []
      requests.push(now)
      this.requestPatterns.set(ipAddress, requests.filter(timestamp => now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW))

      // Threat analysis
      const threatAnalysis = this.analyzeAnalyticsThreat(context)
      context.riskScore = threatAnalysis.threatScore
      context.threatLevel = threatAnalysis.riskLevel
      context.accessLevel = threatAnalysis.accessLevel
      context.dataScope = threatAnalysis.dataScope

      if (threatAnalysis.detectedThreats.length > 0) {
        violations.push(...threatAnalysis.detectedThreats)
        recommendations.push('Review analytics access patterns')
      }

      // Final security decision
      const isAllowed = violations.length === 0 || context.threatLevel !== 'CRITICAL'

      // Record security event
      this.recordSecurityEvent({
        event: 'ANALYTICS_SECURITY_CHECK',
        userId: 'unknown',
        ipAddress,
        userAgent,
        requestId,
        correlationId,
        accessLevel: context.accessLevel,
        dataScope: context.dataScope,
        threatLevel: context.threatLevel,
        riskScore: context.riskScore,
        violations
      })

      return { 
        isAllowed, 
        context, 
        violations, 
        recommendations,
        accessLevel: context.accessLevel,
        dataScope: context.dataScope
      }

    } catch (error) {
      violations.push('SECURITY_PROCESSING_ERROR')
      return { 
        isAllowed: false, 
        context, 
        violations,
        recommendations: ['Contact system administrator'],
        accessLevel: 'BASIC',
        dataScope: 'INTERNAL'
      }
    }
  }
}

// Initialize security processor
const securityProcessor = AdvancedAnalyticsSecurity.getInstance()

export async function GET(req: NextRequest) {
  const startTime = Date.now()
  let securityContext: AnalyticsSecurityState | null = null

  try {
    // Perform advanced security analysis
    const securityResult = await securityProcessor.processRequest(req)
    
    if (!securityResult.isAllowed) {
      await auditLogger.log({
        event: 'ANALYTICS_ACCESS_DENIED',
        level: 'HIGH',
        userId: 'unknown',
        ipAddress: securityResult.context.ipAddress,
        userAgent: securityResult.context.userAgent,
        metadata: {
          requestId: securityResult.context.requestId,
          correlationId: securityResult.context.correlationId,
          violations: securityResult.violations,
          threatLevel: securityResult.context.threatLevel,
          riskScore: securityResult.context.riskScore,
          accessLevel: securityResult.accessLevel,
          dataScope: securityResult.dataScope
        }
      })

      return NextResponse.json(
        {
          status: "error",
          message: "Analytics access denied due to security policy violations",
          security: {
            violations: securityResult.violations,
            recommendations: securityResult.recommendations,
            threatLevel: securityResult.context.threatLevel,
            accessLevel: securityResult.accessLevel,
            dataScope: securityResult.dataScope
          }
        },
        { status: 403 }
      )
    }

    securityContext = securityResult.context

    // Enhanced authentication
    const auth = await withAuth(req)
    if (!auth.isValid) {
      return auth.response!
    }

    // Additional admin role verification
    const user = auth.user
    if (!user || !['ADMIN', 'SUPER_ADMIN', 'MANAGER'].includes(user.role)) {
      await auditLogger.log({
        event: 'UNAUTHORIZED_ANALYTICS_ATTEMPT',
        level: 'HIGH',
        userId: user?.id || 'unknown',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        metadata: {
          requestId: securityContext.requestId,
          correlationId: securityContext.correlationId,
          userRole: user?.role
        }
      })

      return NextResponse.json(
        { status: "error", message: "Insufficient privileges for analytics access" },
        { status: 403 }
      )
    }

    // Enhanced session validation
    const sessionValidation = await securityProcessor.validateAnalyticsSession(req, user.id)
    if (!sessionValidation.isValid) {
      await auditLogger.log({
        event: 'INVALID_SESSION_ANALYTICS_ACCESS',
        level: 'HIGH',
        userId: user.id,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        metadata: {
          requestId: securityContext.requestId,
          violations: sessionValidation.violations
        }
      })

      return NextResponse.json(
        {
          status: "error",
          message: "Analytics session validation failed",
          security: {
            violations: sessionValidation.violations
          }
        },
        { status: 401 }
      )
    }

    // Determine final access level
    const finalAccessLevel = sessionValidation.accessLevel || securityResult.accessLevel

    // Execute analytics queries with enhanced security
    const [totalUsers, totalBookings, totalRevenue, revenueByMonth, bookingsByStatus] = await Promise.all([
      // Total users with date filtering
      prisma.user.count({
        where: {
          createdAt: {
            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
          }
        }
      }),
      
      // Total bookings
      prisma.booking.count(),
      
      // Total revenue
      prisma.booking.aggregate({
        _sum: { totalPrice: true },
      }),
      
      // Monthly revenue trends
      prisma.booking.groupBy({
        by: ['createdAt'],
        _sum: { totalPrice: true },
        where: {
          createdAt: {
            gte: new Date(Date.now() - 12 * 30 * 24 * 60 * 60 * 1000) // Last 12 months
          }
        }
      }),
      
      // Booking status distribution
      prisma.booking.groupBy({
        by: ['status'],
        _count: { _all: true }
      })
    ])

    // Calculate advanced metrics based on access level
    const baseMetrics = {
      totalUsers,
      totalBookings,
      totalRevenue: totalRevenue._sum.totalPrice || 0,
      avgBookingValue: totalBookings > 0 ? (totalRevenue._sum.totalPrice || 0) / totalBookings : 0,
    }

    // Add advanced metrics for higher access levels
    let analyticsData: any = baseMetrics

    if (finalAccessLevel === 'ADVANCED' || finalAccessLevel === 'EXECUTIVE') {
      const monthlyRevenue = revenueByMonth.reduce((sum, month) => 
        sum + (month._sum.totalPrice || 0), 0
      )
      const revenueGrowth = monthlyRevenue > 0 ? 
        ((totalRevenue._sum.totalPrice || 0) - monthlyRevenue) / monthlyRevenue * 100 : 0

      analyticsData = {
        ...analyticsData,
        monthlyRevenue,
        revenueGrowth,
        bookingsByStatus: bookingsByStatus.reduce((acc, status) => ({
          ...acc,
          [status.status]: status._count._all
        }), {}),
        conversionRate: totalUsers > 0 ? (totalBookings / totalUsers) * 100 : 0,
        avgRevenuePerUser: totalUsers > 0 ? (totalRevenue._sum.totalPrice || 0) / totalUsers : 0
      }
    }

    if (finalAccessLevel === 'EXECUTIVE') {
      // Additional executive-level metrics
      analyticsData = {
        ...analyticsData,
        bookingTrends: this.calculateBookingTrends(revenueByMonth),
        performanceIndicators: {
          customerSatisfaction: 4.2, // Mock data - would integrate with review system
          operationalEfficiency: 87.5, // Mock data
          revenuePerRoom: (totalRevenue._sum.totalPrice || 0) / (await prisma.room.count())
        }
      }
    }

    // Apply data masking based on security context
    const securedData = securityProcessor.maskAnalyticsData(
      analyticsData,
      finalAccessLevel,
      securityContext.threatLevel
    )

    // Performance monitoring
    const processingTime = Date.now() - startTime

    // Log successful analytics access
    await auditLogger.log({
      event: 'ANALYTICS_ACCESS_SUCCESS',
      level: 'INFO',
      userId: user.id,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      metadata: {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        accessLevel: finalAccessLevel,
        dataScope: securityContext.dataScope,
        metricsCount: Object.keys(securedData).length,
        processingTime,
        threatLevel: securityContext.threatLevel,
        riskScore: securityContext.riskScore
      }
    })

    // Update security monitoring
    securityMonitor.recordMetric('analytics_access_duration', processingTime)
    securityMonitor.recordMetric('analytics_metrics_retrieved', Object.keys(securedData).length)
    securityMonitor.recordSecurityEvent({
      type: 'ANALYTICS_SUMMARY_ACCESS',
      severity: 'LOW',
      details: {
        userId: user.id,
        accessLevel: finalAccessLevel,
        dataScope: securityContext.dataScope,
        processingTime
      }
    })

    return NextResponse.json(
      successResponse(
        securedData,
        "Analytics summary retrieved successfully",
        {
          requestId: securityContext.requestId,
          correlationId: securityContext.correlationId,
          processingTime,
          accessLevel: finalAccessLevel,
          dataScope: securityContext.dataScope,
          threatLevel: securityContext.threatLevel,
          riskScore: securityContext.riskScore
        }
      ),
    )

  } catch (error: any) {
    const processingTime = Date.now() - startTime

    // Log analytics error
    await auditLogger.log({
      event: 'ANALYTICS_ACCESS_ERROR',
      level: 'HIGH',
      userId: securityContext?.sessionToken || 'unknown',
      ipAddress: securityContext?.ipAddress || 'unknown',
      userAgent: securityContext?.userAgent || 'unknown',
      metadata: {
        requestId: securityContext?.requestId,
        correlationId: securityContext?.correlationId,
        error: error.message,
        processingTime
      }
    })

    console.error("[Analytics API Error]:", error)

    return NextResponse.json(
      { 
        status: "error", 
        message: "Failed to fetch analytics: " + (error.message || "Unknown error"),
        data: null,
        security: securityContext ? {
          requestId: securityContext.requestId,
          correlationId: securityContext.correlationId,
          threatLevel: securityContext.threatLevel
        } : null
      }, 
      { status: 500 }
    )
  }
}

// Helper function for executive analytics (would be implemented in production)
function calculateBookingTrends(revenueByMonth: any[]): any {
  // Mock trend calculation - would implement actual trend analysis
  return {
    trend: 'GROWING',
    growthRate: 12.5,
    projection: 'POSITIVE'
  }
}