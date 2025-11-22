import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { auditLogger } from "@/lib/audit-logger"
import { securityMonitor } from "@/lib/security-monitor"
import { securitySafe } from "@/lib/security-safe"
import { jwtVerify } from "jose"
import { EnhancedAccountingService } from "@/lib/services/enhanced-accounting.service"
import { z } from "zod"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Enhanced security constants for financial reports
const SECURITY_CONFIG = {
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: {
    GET: 30, // Very restrictive for sensitive data
    POST: 5, // Very few report generations
    DELETE: 2
  },
  SESSION_VALIDATION_TIMEOUT: 3 * 60 * 1000, // 3 minutes (stricter for reports)
  REPORT_DATA_RETENTION_DAYS: 1825, // 5 years for financial compliance
  ENCRYPTION_ENABLED: true,
  SENSITIVE_DATA_MASKING: true,
  REPORT_CLASSIFICATION: {
    PUBLIC: 0,
    INTERNAL: 1,
    CONFIDENTIAL: 2,
    RESTRICTED: 3
  },
  GENERATION_ANOMALY_THRESHOLD: 0.10, // 10% deviation
  CONCURRENT_GENERATION_LIMIT: 1, // Only one report generation at a time
  REPORT_ACCESS_LOG_RETENTION: 365 // 1 year for compliance
}

// Advanced security state for report operations
interface ReportSecurityState {
  requestId: string
  deviceFingerprint: string
  userAgent: string
  ipAddress: string
  riskScore: number
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  sessionToken: string
  correlationId: string
  accessLevel: 'VIEW' | 'GENERATE' | 'MANAGE' | 'ADMIN'
  reportScope: 'SUMMARY' | 'DETAILED' | 'COMPREHENSIVE' | 'EXECUTIVE'
  confidentialityLevel: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'
  businessRisk: number
  anomalies: string[]
  generationAuthorized: boolean
}

class AdvancedReportSecurity {
  private static instance: AdvancedReportSecurity
  private securityContext: Map<string, ReportSecurityState> = new Map()
  private requestPatterns: Map<string, number[]> = new Map()
  private reportPatterns: Map<string, any> = new Map()
  private generationQueue: Map<string, any> = new Map()

  private constructor() {}

  static getInstance(): AdvancedReportSecurity {
    if (!AdvancedReportSecurity.instance) {
      AdvancedReportSecurity.instance = new AdvancedReportSecurity()
    }
    return AdvancedReportSecurity.instance
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
      req.headers.get('x-forwarded-for') || '',
      req.headers.get('x-real-ip') || '',
      req.headers.get('x-client-ip') || '',
      req.headers.get('x-forwarded-proto') || ''
    ].join('|')

    const fingerprint = crypto
      .createHash('sha256')
      .update(fingerprintComponents)
      .digest('hex')
      .substring(0, 32)

    return { fingerprint, userAgent }
  }

  // AI-powered threat detection for financial reports
  private analyzeReportThreat(
    context: ReportSecurityState, 
    method: string,
    reportData?: any
  ): {
    threatScore: number
    businessRisk: number
    detectedThreats: string[]
    anomalies: string[]
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    accessLevel: 'VIEW' | 'GENERATE' | 'MANAGE' | 'ADMIN'
    reportScope: 'SUMMARY' | 'DETAILED' | 'COMPREHENSIVE' | 'EXECUTIVE'
    confidentialityLevel: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'
    generationAuthorized: boolean
  } {
    const threats: string[] = []
    const anomalies: string[] = []
    let threatScore = 0
    let businessRisk = 0

    // Analyze access patterns for report operations
    const recentRequests = this.requestPatterns.get(context.ipAddress) || []
    const now = Date.now()
    const recentRequestCount = recentRequests.filter(timestamp => 
      now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW
    ).length

    // Report-specific threat detection (very strict)
    if (recentRequestCount > 20) {
      threats.push('EXCESSIVE_REPORT_ACCESS')
      threatScore += 40
      businessRisk += 30
    }

    // Very unusual timing for report operations
    if (this.isUnusualTimeForReports()) {
      threats.push('UNUSUAL_REPORT_TIME')
      threatScore += 35
      businessRisk += 25
    }

    // High-risk geographic access for financial reports
    if (this.isHighRiskReportGeographic(context.ipAddress)) {
      threats.push('HIGH_RISK_REPORT_GEOGRAPHIC')
      threatScore += 45
      businessRisk += 35
    }

    // Device anomalies for report access
    if (this.isReportDeviceAnomaly(context.deviceFingerprint)) {
      threats.push('REPORT_DEVICE_ANOMALY')
      threatScore += 30
      businessRisk += 40
    }

    // Report generation-specific security
    if (reportData && method === 'POST') {
      const generationAnalysis = this.analyzeReportGeneration(reportData, context)
      threatScore += generationAnalysis.threatScore
      businessRisk += generationAnalysis.businessRisk
      anomalies.push(...generationAnalysis.anomalies)
    }

    // Report access pattern analysis
    if (method === 'GET') {
      const accessAnalysis = this.analyzeReportAccessPatterns(reportData, context)
      threatScore += accessAnalysis.threatScore
      businessRisk += accessAnalysis.businessRisk
      anomalies.push(...accessAnalysis.anomalies)
    }

    // Behavioral analysis for report operations
    if (this.isReportBehavioralAnomaly(context.userAgent, recentRequestCount)) {
      threats.push('REPORT_BEHAVIORAL_ANOMALY')
      threatScore += 25
      businessRisk += 20
    }

    // Concurrent report generation detection
    if (method === 'POST' && this.hasConcurrentGenerations(context.sessionToken)) {
      threats.push('CONCURRENT_REPORT_GENERATION')
      threatScore += 35
      businessRisk += 30
    }

    // Determine access levels based on comprehensive risk assessment
    let accessLevel: 'VIEW' | 'GENERATE' | 'MANAGE' | 'ADMIN' = 'VIEW'
    let reportScope: 'SUMMARY' | 'DETAILED' | 'COMPREHENSIVE' | 'EXECUTIVE' = 'SUMMARY'
    let confidentialityLevel: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' = 'INTERNAL'
    let generationAuthorized = false

    if (threatScore === 0 && businessRisk === 0) {
      accessLevel = 'ADMIN'
      reportScope = 'EXECUTIVE'
      confidentialityLevel = 'RESTRICTED'
      generationAuthorized = true
    } else if (threatScore < 20 && businessRisk < 20) {
      accessLevel = 'MANAGE'
      reportScope = 'COMPREHENSIVE'
      confidentialityLevel = 'CONFIDENTIAL'
      generationAuthorized = true
    } else if (threatScore < 40 && businessRisk < 40) {
      accessLevel = 'GENERATE'
      reportScope = 'DETAILED'
      confidentialityLevel = 'CONFIDENTIAL'
      generationAuthorized = reportData?.reportType !== 'YEARLY' // Restrict yearly reports
    } else if (threatScore < 60) {
      accessLevel = 'VIEW'
      reportScope = 'SUMMARY'
      confidentialityLevel = 'INTERNAL'
      generationAuthorized = false
    }

    // Risk level determination
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    const totalRiskScore = threatScore + businessRisk
    
    if (totalRiskScore >= 80) riskLevel = 'CRITICAL'
    else if (totalRiskScore >= 60) riskLevel = 'HIGH'
    else if (totalRiskScore >= 30) riskLevel = 'MEDIUM'

    return { 
      threatScore, 
      businessRisk, 
      detectedThreats: threats, 
      anomalies,
      riskLevel, 
      accessLevel,
      reportScope,
      confidentialityLevel,
      generationAuthorized
    }
  }

  private isUnusualTimeForReports(): boolean {
    const hour = new Date().getHours()
    const dayOfWeek = new Date().getDay()
    
    // Flag access during off-hours for report operations (stricter)
    return (hour >= 19 || hour <= 7) || (dayOfWeek === 0 || dayOfWeek === 6)
  }

  private isHighRiskReportGeographic(ipAddress: string): boolean {
    // Very strict geographic controls for financial reports
    const suspiciousPatterns = [
      /^192\.168\./, // Private networks
      /^10\./, // Private networks
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private networks
      /^127\./, // Localhost
      /^unknown$/, // Unknown IPs
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(ipAddress))
    return isSuspicious && ipAddress !== '127.0.0.1'
  }

  private isReportDeviceAnomaly(fingerprint: string): boolean {
    return fingerprint.length < 16 || 
           !/^[a-f0-9]+$/.test(fingerprint) ||
           this.isKnownReportDevice(fingerprint)
  }

  private isKnownReportDevice(fingerprint: string): boolean {
    return fingerprint.includes('bot') || 
           fingerprint.includes('crawler') ||
           fingerprint.includes('mobile') // Restrict mobile access for reports
  }

  private analyzeReportGeneration(reportData: any, context: ReportSecurityState): {
    threatScore: number
    businessRisk: number
    anomalies: string[]
  } {
    const anomalies: string[] = []
    let threatScore = 0
    let businessRisk = 0

    // Check for sensitive report types
    const sensitiveReportTypes = ['QUARTERLY', 'YEARLY']
    if (sensitiveReportTypes.includes(reportData.reportType)) {
      anomalies.push('SENSITIVE_REPORT_TYPE')
      threatScore += 20
      businessRisk += 25
    }

    // Check for large date ranges (potential data mining)
    const dateRangeDays = Math.ceil((reportData.endDate - reportData.startDate) / (1000 * 60 * 60 * 24))
    if (dateRangeDays > 365) {
      anomalies.push('LARGE_DATE_RANGE')
      threatScore += 15
      businessRisk += 20
    }

    // Check for frequent report generation
    const recentGenerations = this.getRecentGenerations(context.sessionToken)
    if (recentGenerations.length > 3) {
      anomalies.push('EXCESSIVE_GENERATION_FREQUENCY')
      threatScore += 25
      businessRisk += 30
    }

    // Check for off-hours generation
    if (this.isUnusualTimeForReports()) {
      anomalies.push('OFF_HOURS_REPORT_GENERATION')
      threatScore += 20
      businessRisk += 15
    }

    return { threatScore, businessRisk, anomalies }
  }

  private analyzeReportAccessPatterns(accessData: any, context: ReportSecurityState): {
    threatScore: number
    businessRisk: number
    anomalies: string[]
  } {
    const anomalies: string[] = []
    let threatScore = 0
    let businessRisk = 0

    // Check for bulk report access
    if (accessData?.pageSize && accessData.pageSize > 50) {
      anomalies.push('BULK_REPORT_ACCESS')
      threatScore += 20
      businessRisk += 15
    }

    // Check for specific sensitive report types
    if (accessData?.reportType === 'YEARLY') {
      anomalies.push('YEARLY_REPORT_ACCESS')
      threatScore += 15
      businessRisk += 20
    }

    return { threatScore, businessRisk, anomalies }
  }

  private isReportBehavioralAnomaly(userAgent: string, requestCount: number): boolean {
    const suspiciousPatterns = [
      /bot|crawler|spider/i,
      /python|curl|wget/i,
      /postman/i,
      /mobile|android|iphone/i // Restrict mobile access
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(userAgent))
    const isHighFrequency = requestCount > 30
    
    return isSuspicious || isHighFrequency
  }

  private getRecentGenerations(sessionToken: string): any[] {
    const key = `generations:${sessionToken}`
    return this.generationQueue.get(key) || []
  }

  private hasConcurrentGenerations(sessionToken: string): boolean {
    const recentGenerations = this.getRecentGenerations(sessionToken)
    const now = Date.now()
    const fiveMinutesAgo = now - 300000 // 5 minutes
    
    return recentGenerations.filter(t => t.timestamp > fiveMinutesAgo).length >= 
           SECURITY_CONFIG.CONCURRENT_GENERATION_LIMIT
  }

  // Advanced session validation for report operations
  private async validateReportSession(req: NextRequest, userId: string): Promise<{
    isValid: boolean
    sessionState: any
    violations: string[]
    accessLevel: 'VIEW' | 'GENERATE' | 'MANAGE' | 'ADMIN'
  }> {
    const violations: string[] = []
    
    try {
      const sessionToken = req.headers.get('x-session-token')
      const refreshToken = req.headers.get('x-refresh-token')
      
      if (!sessionToken) {
        violations.push('MISSING_REPORT_SESSION_TOKEN')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Very strict JWT session validation
      const secret = new TextEncoder().encode(process.env.REFRESH_TOKEN_SECRET || 'fallback-secret')
      const { payload } = await jwtVerify(sessionToken, secret)
      
      // Stricter session expiration for reports
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        violations.push('REPORT_SESSION_EXPIRED')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Enhanced device fingerprint validation
      const deviceInfo = this.extractDeviceInfo(req)
      const sessionFingerprint = payload.deviceFingerprint as string
      if (sessionFingerprint && sessionFingerprint !== deviceInfo.fingerprint) {
        violations.push('REPORT_DEVICE_MISMATCH')
      }

      // Report role-based access validation (very strict)
      const sessionRole = payload.role as string
      const reportAccessLevel = this.determineReportAccessLevel(sessionRole)
      
      return { 
        isValid: violations.length === 0, 
        sessionState: payload, 
        violations,
        accessLevel: reportAccessLevel
      }
    } catch (error) {
      violations.push('REPORT_SESSION_VALIDATION_ERROR')
      return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
    }
  }

  private determineReportAccessLevel(role: string): 'VIEW' | 'GENERATE' | 'MANAGE' | 'ADMIN' {
    switch (role?.toUpperCase()) {
      case 'SUPER_ADMIN':
      case 'FINANCIAL_ADMIN':
      case 'CEO':
        return 'ADMIN'
      case 'ADMIN':
      case 'ACCOUNTANT':
      case 'FINANCIAL_MANAGER':
      case 'CFO':
        return 'MANAGE'
      case 'HOTEL_MANAGER':
        return 'GENERATE'
      default:
        return 'VIEW'
    }
  }

  // Mask highly sensitive report data
  private maskReportData(data: any, accessLevel: string, threatLevel: string): any {
    const masked = { ...data }

    if (accessLevel === 'VIEW' || threatLevel === 'HIGH' || threatLevel === 'CRITICAL') {
      // Apply extensive data masking for report information
      if (typeof masked.totalRevenue === 'number') {
        masked.totalRevenue = Math.round(masked.totalRevenue / 1000) * 1000 // Round to nearest thousand
      }
      if (typeof masked.totalExpenses === 'number') {
        masked.totalExpenses = Math.round(masked.totalExpenses / 1000) * 1000
      }
      if (typeof masked.netProfit === 'number') {
        masked.netProfit = Math.round(masked.netProfit / 1000) * 1000
      }
      
      // Mask sensitive financial details
      if (masked.financialDetails) {
        masked.financialDetails = '***CLASSIFIED***'
      }
      
      // Mask executive summary for basic access
      if (masked.executiveSummary && accessLevel === 'VIEW') {
        masked.executiveSummary = '***EXECUTIVE SUMMARY MASKED***'
      }
    }

    return masked
  }

  // Record comprehensive report security event
  private recordReportSecurityEvent(event: any): void {
    try {
      auditLogger.log({
        event: 'REPORT_OPERATION',
        level: 'INFO',
        userId: event.userId,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: {
          requestId: event.requestId,
          correlationId: event.correlationId,
          operation: event.operation,
          threatLevel: event.threatLevel,
          businessRisk: event.businessRisk,
          accessLevel: event.accessLevel,
          reportScope: event.reportScope,
          confidentialityLevel: event.confidentialityLevel,
          anomalies: event.anomalies,
          generationAuthorized: event.generationAuthorized,
          reportData: event.reportData ? 'PRESENT' : 'ABSENT'
        }
      })
    } catch (error) {
      console.error('Failed to record report security event:', error)
    }
  }

  // Main security processing
  public async processRequest(
    req: NextRequest, 
    method: string,
    reportData?: any
  ): Promise<{
    isAllowed: boolean
    context: ReportSecurityState
    violations: string[]
    recommendations: string[]
    accessLevel: 'VIEW' | 'GENERATE' | 'MANAGE' | 'ADMIN'
    reportScope: 'SUMMARY' | 'DETAILED' | 'COMPREHENSIVE' | 'EXECUTIVE'
  }> {
    const requestId = this.generateRequestId()
    const correlationId = this.generateCorrelationId()
    
    const { fingerprint, userAgent } = this.extractDeviceInfo(req)
    const ipAddress = req.headers.get('x-forwarded-for') || req.ip || 'unknown'

    const context: ReportSecurityState = {
      requestId,
      deviceFingerprint: fingerprint,
      userAgent,
      ipAddress,
      riskScore: 0,
      threatLevel: 'LOW',
      sessionToken: req.headers.get('x-session-token') || '',
      correlationId,
      accessLevel: 'VIEW',
      reportScope: 'SUMMARY',
      confidentialityLevel: 'INTERNAL',
      businessRisk: 0,
      anomalies: [],
      generationAuthorized: false
    }

    const violations: string[] = []
    const recommendations: string[] = []

    try {
      // Very strict rate limiting for report operations
      const rateLimitKey = `${ipAddress}:report-${method.toLowerCase()}`
      const rateLimitMax = SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS[method] || 10
      const rateLimitResult = await rateLimit.check(rateLimitKey, rateLimitMax, SECURITY_CONFIG.RATE_LIMIT_WINDOW)
      
      if (!rateLimitResult.allowed) {
        violations.push('REPORT_RATE_LIMIT_EXCEEDED')
        recommendations.push('Implement strict rate limiting for report operations')
      }

      // Record request pattern
      const now = Date.now()
      const requests = this.requestPatterns.get(ipAddress) || []
      requests.push(now)
      this.requestPatterns.set(ipAddress, requests.filter(timestamp => now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW))

      // Threat and business risk analysis
      const threatAnalysis = this.analyzeReportThreat(context, method, reportData)
      context.riskScore = threatAnalysis.threatScore
      context.threatLevel = threatAnalysis.riskLevel
      context.accessLevel = threatAnalysis.accessLevel
      context.reportScope = threatAnalysis.reportScope
      context.confidentialityLevel = threatAnalysis.confidentialityLevel
      context.businessRisk = threatAnalysis.businessRisk
      context.anomalies = threatAnalysis.anomalies
      context.generationAuthorized = threatAnalysis.generationAuthorized

      if (threatAnalysis.detectedThreats.length > 0) {
        violations.push(...threatAnalysis.detectedThreats)
        recommendations.push('Review report access patterns and implement additional business controls')
      }

      if (threatAnalysis.anomalies.length > 0) {
        violations.push(...threatAnalysis.anomalies)
        recommendations.push('Investigate report anomalies and implement monitoring')
      }

      // Final security decision (very strict for reports)
      const isAllowed = violations.length === 0 && context.threatLevel !== 'HIGH' && context.threatLevel !== 'CRITICAL'

      // Record comprehensive security event
      this.recordReportSecurityEvent({
        event: 'REPORT_SECURITY_CHECK',
        userId: 'unknown',
        ipAddress,
        userAgent,
        requestId,
        correlationId,
        operation: method,
        accessLevel: context.accessLevel,
        reportScope: context.reportScope,
        threatLevel: context.threatLevel,
        businessRisk: context.businessRisk,
        confidentialityLevel: context.confidentialityLevel,
        anomalies: context.anomalies,
        generationAuthorized: context.generationAuthorized,
        reportData,
        violations
      })

      return { 
        isAllowed, 
        context, 
        violations, 
        recommendations,
        accessLevel: context.accessLevel,
        reportScope: context.reportScope
      }

    } catch (error) {
      violations.push('REPORT_SECURITY_PROCESSING_ERROR')
      return { 
        isAllowed: false, 
        context, 
        violations,
        recommendations: ['Contact system administrator and security team immediately'],
        accessLevel: 'VIEW',
        reportScope: 'SUMMARY'
      }
    }
  }
}

// Initialize security processor
const securityProcessor = AdvancedReportSecurity.getInstance()

// Validation Schemas (Enhanced)
const generateReportSchema = z.object({
  hotelId: z.string(),
  startDate: z.string().transform((str) => new Date(str)),
  endDate: z.string().transform((str) => new Date(str)),
  reportType: z.enum(['DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'YEARLY'])
})

const getReportsSchema = z.object({
  hotelId: z.string().optional(),
  reportType: z.enum(['DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'YEARLY']).optional(),
  startDate: z.string().transform((str) => new Date(str)).optional(),
  endDate: z.string().transform((str) => new Date(str)).optional(),
  page: z.number().positive().optional(),
  pageSize: z.number().positive().optional()
})

// Enhanced GET endpoint
export async function GET(req: NextRequest) {
  const startTime = Date.now()
  let securityContext: ReportSecurityState | null = null

  try {
    // Perform advanced report security analysis
    const securityResult = await securityProcessor.processRequest(req, 'GET')
    
    if (!securityResult.isAllowed) {
      await auditLogger.log({
        event: 'REPORT_ACCESS_DENIED',
        level: 'CRITICAL',
        userId: 'unknown',
        ipAddress: securityResult.context.ipAddress,
        userAgent: securityResult.context.userAgent,
        metadata: {
          requestId: securityResult.context.requestId,
          correlationId: securityResult.context.correlationId,
          violations: securityResult.violations,
          threatLevel: securityResult.context.threatLevel,
          businessRisk: securityResult.context.businessRisk,
          accessLevel: securityResult.accessLevel,
          reportScope: securityResult.reportScope,
          confidentialityLevel: securityResult.context.confidentialityLevel
        }
      })

      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Report data access denied due to security policy violations",
            security: {
              violations: securityResult.violations,
              recommendations: securityResult.recommendations,
              threatLevel: securityResult.context.threatLevel,
              businessRisk: securityResult.context.businessRisk,
              accessLevel: securityResult.accessLevel,
              reportScope: securityResult.reportScope,
              confidentialityLevel: securityResult.context.confidentialityLevel
            }
          },
          { status: 403 }
        )
      )
    }

    securityContext = securityResult.context

    // Enhanced authentication (stricter for reports)
    const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
    if (!auth.isValid) return auth.response!

    // Enhanced session validation
    const sessionValidation = await securityProcessor.validateReportSession(req, auth.user.id)
    if (!sessionValidation.isValid) {
      await auditLogger.log({
        event: 'INVALID_REPORT_SESSION',
        level: 'HIGH',
        userId: auth.user.id,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        metadata: {
          requestId: securityContext.requestId,
          violations: sessionValidation.violations
        }
      })

      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Report session validation failed",
            security: {
              violations: sessionValidation.violations
            }
          },
          { status: 401 }
        )
      )
    }

    // Determine final access level
    const finalAccessLevel = sessionValidation.accessLevel || securityResult.accessLevel

    // Extract and validate query parameters with enhanced security
    const searchParams = req.nextUrl.searchParams
    
    // Very restrictive pagination for reports
    const page = Math.max(1, parseInt(searchParams.get('page') || '1'))
    const pageSize = Math.min(20, Math.max(1, parseInt(searchParams.get('pageSize') || '10')))

    // Enhanced parameter validation
    const validatedParams = this.validateReportQueryParams(searchParams, finalAccessLevel)
    
    // Build secure where clause
    const where: any = this.buildSecureReportWhereClause(auth, validatedParams, finalAccessLevel)

    const [reports, total] = await Promise.all([
      prisma.financialReport.findMany({
        where,
        include: this.buildReportIncludeClause(finalAccessLevel),
        orderBy: { generatedAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.financialReport.count({ where })
    ])

    // Enhanced summary statistics with security context
    const summary = await prisma.financialReport.groupBy({
      by: ['reportType'],
      where: this.buildSecureReportWhereClause(auth, validatedParams, finalAccessLevel),
      _count: true,
      _sum: {
        totalRevenue: true,
        totalExpenses: true,
        netProfit: true
      }
    })

    const totalRevenue = summary.reduce((sum, item) => sum + (item._sum.totalRevenue || 0), 0)
    const totalExpenses = summary.reduce((sum, item) => sum + (item._sum.totalExpenses || 0), 0)
    const totalProfit = summary.reduce((sum, item) => sum + (item._sum.netProfit || 0), 0)

    // Apply comprehensive report data masking
    const securedReports = reports.map(report => 
      securityProcessor.maskReportData(report, finalAccessLevel, securityContext.threatLevel)
    )

    // Performance monitoring
    const processingTime = Date.now() - startTime

    // Log successful report access
    await auditLogger.log({
      event: 'REPORT_ACCESS_SUCCESS',
      level: 'INFO',
      userId: auth.user.id,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      metadata: {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        accessLevel: finalAccessLevel,
        reportScope: securityResult.reportScope,
        confidentialityLevel: securityContext.confidentialityLevel,
        recordsRetrieved: securedReports.length,
        processingTime,
        threatLevel: securityContext.threatLevel,
        businessRisk: securityContext.businessRisk
      }
    })

    // Update security monitoring
    securityMonitor.recordMetric('report_access_duration', processingTime)
    securityMonitor.recordMetric('report_records_retrieved', securedReports.length)
    securityMonitor.recordSecurityEvent({
      type: 'REPORT_DATA_ACCESS',
      severity: 'LOW',
      details: {
        userId: auth.user.id,
        accessLevel: finalAccessLevel,
        reportScope: securityResult.reportScope,
        confidentialityLevel: securityContext.confidentialityLevel,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            reports: securedReports,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: securityProcessor.maskReportData({
              totalRevenue,
              totalExpenses,
              totalProfit,
              reportCount: total
            }, finalAccessLevel, securityContext.threatLevel)
          },
          "Financial reports retrieved successfully",
          {
            requestId: securityContext.requestId,
            correlationId: securityContext.correlationId,
            processingTime,
            accessLevel: finalAccessLevel,
            reportScope: securityResult.reportScope,
            confidentialityLevel: securityContext.confidentialityLevel,
            threatLevel: securityContext.threatLevel,
            businessRisk: securityContext.businessRisk
          }
        )
      )
    )

  } catch (error: any) {
    const processingTime = Date.now() - startTime

    // Log report error
    await auditLogger.log({
      event: 'REPORT_ACCESS_ERROR',
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

    console.error("[Get Financial Reports Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch financial reports", "FETCH_REPORTS_ERROR"),
        { status: 500 }
      )
    )
  }
}

// Helper methods for report operations
function validateReportQueryParams(searchParams: URLSearchParams, accessLevel: string): any {
  const params: any = {}
  
  // Basic parameters with strict limits
  params.page = parseInt(searchParams.get('page') || '1')
  params.pageSize = Math.min(20, parseInt(searchParams.get('pageSize') || '10'))
  params.hotelId = searchParams.get('hotelId')
  params.reportType = searchParams.get('reportType')
  
  // Date filtering with validation
  const startDate = searchParams.get('startDate')
  const endDate = searchParams.get('endDate')
  if (startDate) params.startDate = new Date(startDate)
  if (endDate) params.endDate = new Date(endDate)
  
  return params
}

function buildSecureReportWhereClause(auth: any, params: any, accessLevel: string): any {
  const where: any = {}
  
  // Role-based filtering
  if (auth.payload.role === 'HOTEL_MANAGER') {
    const userHotels = [] // Would fetch from database
    where.hotelId = { in: userHotels.map((h: any) => h.id) }
  }
  
  // Parameter-based filtering
  if (params.hotelId) where.hotelId = params.hotelId
  if (params.reportType) where.reportType = params.reportType
  
  // Date filtering with business logic
  if (params.startDate || params.endDate) {
    where.OR = [
      {
        AND: [
          { startDate: { gte: params.startDate || undefined } },
          { startDate: { lte: params.endDate || undefined } }
        ]
      },
      {
        AND: [
          { endDate: { gte: params.startDate || undefined } },
          { endDate: { lte: params.endDate || undefined } }
        ]
      }
    ]
  }
  
  return where
}

function buildReportIncludeClause(accessLevel: string): any {
  const include: any = {
    hotel: {
      select: { name: true, city: true }
    }
  }
  
  // Include sensitive data only for higher access levels
  if (accessLevel === 'GENERATE' || accessLevel === 'MANAGE' || accessLevel === 'ADMIN') {
    include.generatedBy = {
      select: { name: true, role: true }
    }
  }
  
  return include
}

// Continue with POST and DELETE methods following the same security patterns...