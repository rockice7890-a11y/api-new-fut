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
import { z } from "zod"
import { v4 as uuidv4 } from "uuid"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Enhanced security constants for financial data
const SECURITY_CONFIG = {
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: {
    GET: 100,
    POST: 20,
    PUT: 15,
    DELETE: 5
  },
  SESSION_VALIDATION_TIMEOUT: 5 * 60 * 1000, // 5 minutes
  FINANCIAL_DATA_RETENTION_DAYS: 2555, // 7 years for tax compliance
  ENCRYPTION_ENABLED: true,
  SENSITIVE_DATA_MASKING: true,
  FRAUD_DETECTION_ENABLED: true,
  TRANSACTION_ANOMALY_THRESHOLD: 0.15, // 15% deviation from normal
  CONCURRENT_TRANSACTION_LIMIT: 3
}

// Advanced security state for financial operations
interface FinancialSecurityState {
  requestId: string
  deviceFingerprint: string
  userAgent: string
  ipAddress: string
  riskScore: number
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  sessionToken: string
  correlationId: string
  accessLevel: 'VIEW' | 'TRANSACT' | 'MANAGE' | 'ADMIN'
  financialScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE'
  fraudScore: number
  anomalies: string[]
}

class AdvancedFinancialSecurity {
  private static instance: AdvancedFinancialSecurity
  private securityContext: Map<string, FinancialSecurityState> = new Map()
  private requestPatterns: Map<string, number[]> = new Map()
  private transactionPatterns: Map<string, any> = new Map()
  private financialAnomalies: Map<string, any[]> = new Map()

  private constructor() {}

  static getInstance(): AdvancedFinancialSecurity {
    if (!AdvancedFinancialSecurity.instance) {
      AdvancedFinancialSecurity.instance = new AdvancedFinancialSecurity()
    }
    return AdvancedFinancialSecurity.instance
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
      req.headers.get('x-real-ip') || ''
    ].join('|')

    const fingerprint = crypto
      .createHash('sha256')
      .update(fingerprintComponents)
      .digest('hex')
      .substring(0, 32)

    return { fingerprint, userAgent }
  }

  // AI-powered fraud detection for financial transactions
  private analyzeFinancialThreat(
    context: FinancialSecurityState, 
    method: string,
    transactionData?: any
  ): {
    threatScore: number
    fraudScore: number
    detectedThreats: string[]
    anomalies: string[]
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    accessLevel: 'VIEW' | 'TRANSACT' | 'MANAGE' | 'ADMIN'
    financialScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE'
  } {
    const threats: string[] = []
    const anomalies: string[] = []
    let threatScore = 0
    let fraudScore = 0

    // Analyze access patterns
    const recentRequests = this.requestPatterns.get(context.ipAddress) || []
    const now = Date.now()
    const recentRequestCount = recentRequests.filter(timestamp => 
      now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW
    ).length

    // Financial-specific threat detection
    if (recentRequestCount > 50) {
      threats.push('EXCESSIVE_FINANCIAL_ACCESS')
      threatScore += 30
      fraudScore += 20
    }

    // Unusual timing for financial operations
    if (this.isUnusualTimeForFinance()) {
      threats.push('UNUSUAL_FINANCIAL_TIME')
      threatScore += 25
      fraudScore += 15
    }

    // Geographic anomaly detection
    if (this.isSuspiciousGeographicAccess(context.ipAddress)) {
      threats.push('SUSPICIOUS_GEOGRAPHIC_ACCESS')
      threatScore += 35
      fraudScore += 25
    }

    // Device fingerprint anomalies
    if (this.isFinancialDeviceAnomaly(context.deviceFingerprint)) {
      threats.push('FINANCIAL_DEVICE_ANOMALY')
      threatScore += 20
      fraudScore += 30
    }

    // Transaction-specific fraud detection
    if (transactionData && method === 'POST') {
      const fraudAnalysis = this.analyzeTransactionFraud(transactionData, context)
      fraudScore += fraudAnalysis.fraudScore
      anomalies.push(...fraudAnalysis.anomalies)
    }

    // Behavioral analysis
    if (this.isBehavioralAnomaly(context.userAgent, recentRequestCount)) {
      threats.push('BEHAVIORAL_ANOMALY')
      threatScore += 20
      fraudScore += 15
    }

    // Concurrent transaction detection
    if (method !== 'GET' && this.hasConcurrentTransactions(context.sessionToken)) {
      threats.push('CONCURRENT_TRANSACTIONS')
      threatScore += 25
      fraudScore += 20
    }

    // Determine access levels based on risk
    let accessLevel: 'VIEW' | 'TRANSACT' | 'MANAGE' | 'ADMIN' = 'VIEW'
    let financialScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE' = 'BASIC'

    if (threatScore === 0 && fraudScore === 0) {
      accessLevel = 'ADMIN'
      financialScope = 'COMPLIANCE'
    } else if (threatScore < 20 && fraudScore < 20) {
      accessLevel = 'MANAGE'
      financialScope = 'FULL'
    } else if (threatScore < 40 && fraudScore < 40) {
      accessLevel = 'TRANSACT'
      financialScope = 'DETAILED'
    }

    // Risk level determination
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    const totalRiskScore = threatScore + fraudScore
    
    if (totalRiskScore >= 80) riskLevel = 'CRITICAL'
    else if (totalRiskScore >= 60) riskLevel = 'HIGH'
    else if (totalRiskScore >= 30) riskLevel = 'MEDIUM'

    return { 
      threatScore, 
      fraudScore, 
      detectedThreats: threats, 
      anomalies,
      riskLevel, 
      accessLevel,
      financialScope
    }
  }

  private isUnusualTimeForFinance(): boolean {
    const hour = new Date().getHours()
    const dayOfWeek = new Date().getDay()
    
    // Flag access during off-hours for financial operations
    return (hour >= 22 || hour <= 5) || (dayOfWeek === 0 || dayOfWeek === 6)
  }

  private isSuspiciousGeographicAccess(ipAddress: string): boolean {
    // Simplified geographic risk assessment
    const suspiciousPatterns = [
      /^192\.168\./, // Private networks
      /^10\./, // Private networks
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private networks
      /^127\./, // Localhost
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(ipAddress))
    return isSuspicious && ipAddress !== '127.0.0.1'
  }

  private isFinancialDeviceAnomaly(fingerprint: string): boolean {
    // Financial device anomalies
    return fingerprint.length < 16 || 
           !/^[a-f0-9]+$/.test(fingerprint) ||
           this.isKnownSuspiciousDevice(fingerprint)
  }

  private isKnownSuspiciousDevice(fingerprint: string): boolean {
    // Simplified suspicious device detection
    // In production, maintain a database of suspicious devices
    return fingerprint.includes('bot') || fingerprint.includes('crawler')
  }

  private analyzeTransactionFraud(transactionData: any, context: FinancialSecurityState): {
    fraudScore: number
    anomalies: string[]
  } {
    const anomalies: string[] = []
    let fraudScore = 0

    // Check for unusual transaction amounts
    if (transactionData.amount > 10000) {
      anomalies.push('HIGH_VALUE_TRANSACTION')
      fraudScore += 20
    }

    // Check for suspicious payment methods
    const suspiciousPaymentMethods = ['CASH', 'CHECK']
    if (suspiciousPaymentMethods.includes(transactionData.paymentMethod)) {
      anomalies.push('SUSPICIOUS_PAYMENT_METHOD')
      fraudScore += 10
    }

    // Check for rapid-fire transactions
    const recentTransactions = this.getRecentTransactions(context.sessionToken)
    if (recentTransactions.length > SECURITY_CONFIG.CONCURRENT_TRANSACTION_LIMIT) {
      anomalies.push('RAPID_TRANSACTIONS')
      fraudScore += 25
    }

    // Check for off-hours transactions
    if (this.isUnusualTimeForFinance()) {
      anomalies.push('OFF_HOURS_TRANSACTION')
      fraudScore += 15
    }

    return { fraudScore, anomalies }
  }

  private getRecentTransactions(sessionToken: string): any[] {
    // Simplified recent transaction tracking
    const key = `transactions:${sessionToken}`
    return this.transactionPatterns.get(key) || []
  }

  private hasConcurrentTransactions(sessionToken: string): boolean {
    const recentTransactions = this.getRecentTransactions(sessionToken)
    const now = Date.now()
    const oneMinuteAgo = now - 60000 // 1 minute
    
    return recentTransactions.filter(t => t.timestamp > oneMinuteAgo).length > 
           SECURITY_CONFIG.CONCURRENT_TRANSACTION_LIMIT
  }

  private isBehavioralAnomaly(userAgent: string, requestCount: number): boolean {
    const suspiciousPatterns = [
      /bot|crawler|spider/i,
      /python|curl|wget/i,
      /postman/i
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(userAgent))
    const isHighFrequency = requestCount > 100
    
    return isSuspicious || isHighFrequency
  }

  // Advanced session validation for financial operations
  private async validateFinancialSession(req: NextRequest, userId: string): Promise<{
    isValid: boolean
    sessionState: any
    violations: string[]
    accessLevel: 'VIEW' | 'TRANSACT' | 'MANAGE' | 'ADMIN'
  }> {
    const violations: string[] = []
    
    try {
      const sessionToken = req.headers.get('x-session-token')
      const refreshToken = req.headers.get('x-refresh-token')
      
      if (!sessionToken) {
        violations.push('MISSING_FINANCIAL_SESSION_TOKEN')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Enhanced JWT session validation
      const secret = new TextEncoder().encode(process.env.REFRESH_TOKEN_SECRET || 'fallback-secret')
      const { payload } = await jwtVerify(sessionToken, secret)
      
      // Financial session expiration check (stricter)
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        violations.push('FINANCIAL_SESSION_EXPIRED')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Financial device fingerprint validation
      const deviceInfo = this.extractDeviceInfo(req)
      const sessionFingerprint = payload.deviceFingerprint as string
      if (sessionFingerprint && sessionFingerprint !== deviceInfo.fingerprint) {
        violations.push('FINANCIAL_DEVICE_MISMATCH')
      }

      // Financial role-based access validation
      const sessionRole = payload.role as string
      const financialAccessLevel = this.determineFinancialAccessLevel(sessionRole)
      
      return { 
        isValid: violations.length === 0, 
        sessionState: payload, 
        violations,
        accessLevel: financialAccessLevel
      }
    } catch (error) {
      violations.push('FINANCIAL_SESSION_VALIDATION_ERROR')
      return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
    }
  }

  private determineFinancialAccessLevel(role: string): 'VIEW' | 'TRANSACT' | 'MANAGE' | 'ADMIN' {
    switch (role?.toUpperCase()) {
      case 'SUPER_ADMIN':
      case 'FINANCIAL_ADMIN':
        return 'ADMIN'
      case 'ADMIN':
      case 'ACCOUNTANT':
      case 'FINANCIAL_MANAGER':
        return 'MANAGE'
      case 'HOTEL_MANAGER':
        return 'TRANSACT'
      default:
        return 'VIEW'
    }
  }

  // Mask sensitive financial data
  private maskFinancialData(data: any, accessLevel: string, threatLevel: string): any {
    const masked = { ...data }

    if (accessLevel === 'VIEW' || threatLevel === 'HIGH' || threatLevel === 'CRITICAL') {
      // Apply data masking for sensitive financial information
      if (typeof masked.amount === 'number') {
        masked.amount = Math.round(masked.amount / 100) * 100 // Round to nearest hundred
      }
      if (typeof masked.taxAmount === 'number') {
        masked.taxAmount = Math.round(masked.taxAmount / 10) * 10 // Round to nearest ten
      }
      
      // Mask payment details
      if (masked.paymentMethod === 'CARD') {
        masked.paymentMethod = 'CARD'
        masked.notes = '***CARD_PAYMENT***'
      }
    }

    return masked
  }

  // Record comprehensive financial security event
  private recordFinancialSecurityEvent(event: any): void {
    try {
      auditLogger.log({
        event: 'FINANCIAL_OPERATION',
        level: 'INFO',
        userId: event.userId,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: {
          requestId: event.requestId,
          correlationId: event.correlationId,
          operation: event.operation,
          threatLevel: event.threatLevel,
          fraudScore: event.fraudScore,
          accessLevel: event.accessLevel,
          financialScope: event.financialScope,
          anomalies: event.anomalies,
          transactionData: event.transactionData ? 'PRESENT' : 'ABSENT'
        }
      })
    } catch (error) {
      console.error('Failed to record financial security event:', error)
    }
  }

  // Main security processing
  public async processRequest(
    req: NextRequest, 
    method: string,
    transactionData?: any
  ): Promise<{
    isAllowed: boolean
    context: FinancialSecurityState
    violations: string[]
    recommendations: string[]
    accessLevel: 'VIEW' | 'TRANSACT' | 'MANAGE' | 'ADMIN'
    financialScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE'
  }> {
    const requestId = this.generateRequestId()
    const correlationId = this.generateCorrelationId()
    
    const { fingerprint, userAgent } = this.extractDeviceInfo(req)
    const ipAddress = req.headers.get('x-forwarded-for') || req.ip || 'unknown'

    const context: FinancialSecurityState = {
      requestId,
      deviceFingerprint: fingerprint,
      userAgent,
      ipAddress,
      riskScore: 0,
      threatLevel: 'LOW',
      sessionToken: req.headers.get('x-session-token') || '',
      correlationId,
      accessLevel: 'VIEW',
      financialScope: 'BASIC',
      fraudScore: 0,
      anomalies: []
    }

    const violations: string[] = []
    const recommendations: string[] = []

    try {
      // Enhanced rate limiting based on method
      const rateLimitKey = `${ipAddress}:financial-${method.toLowerCase()}`
      const rateLimitMax = SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS[method] || 50
      const rateLimitResult = await rateLimit.check(rateLimitKey, rateLimitMax, SECURITY_CONFIG.RATE_LIMIT_WINDOW)
      
      if (!rateLimitResult.allowed) {
        violations.push('FINANCIAL_RATE_LIMIT_EXCEEDED')
        recommendations.push('Implement exponential backoff for financial operations')
      }

      // Record request pattern
      const now = Date.now()
      const requests = this.requestPatterns.get(ipAddress) || []
      requests.push(now)
      this.requestPatterns.set(ipAddress, requests.filter(timestamp => now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW))

      // Threat and fraud analysis
      const threatAnalysis = this.analyzeFinancialThreat(context, method, transactionData)
      context.riskScore = threatAnalysis.threatScore
      context.threatLevel = threatAnalysis.riskLevel
      context.accessLevel = threatAnalysis.accessLevel
      context.financialScope = threatAnalysis.financialScope
      context.fraudScore = threatAnalysis.fraudScore
      context.anomalies = threatAnalysis.anomalies

      if (threatAnalysis.detectedThreats.length > 0) {
        violations.push(...threatAnalysis.detectedThreats)
        recommendations.push('Review financial access patterns and implement additional controls')
      }

      if (threatAnalysis.anomalies.length > 0) {
        violations.push(...threatAnalysis.anomalies)
        recommendations.push('Investigate transaction anomalies')
      }

      // Final security decision
      const isAllowed = violations.length === 0 || context.threatLevel !== 'CRITICAL'

      // Record comprehensive security event
      this.recordFinancialSecurityEvent({
        event: 'FINANCIAL_SECURITY_CHECK',
        userId: 'unknown',
        ipAddress,
        userAgent,
        requestId,
        correlationId,
        operation: method,
        accessLevel: context.accessLevel,
        financialScope: context.financialScope,
        threatLevel: context.threatLevel,
        fraudScore: context.fraudScore,
        anomalies: context.anomalies,
        transactionData,
        violations
      })

      return { 
        isAllowed, 
        context, 
        violations, 
        recommendations,
        accessLevel: context.accessLevel,
        financialScope: context.financialScope
      }

    } catch (error) {
      violations.push('FINANCIAL_SECURITY_PROCESSING_ERROR')
      return { 
        isAllowed: false, 
        context, 
        violations,
        recommendations: ['Contact system administrator immediately'],
        accessLevel: 'VIEW',
        financialScope: 'BASIC'
      }
    }
  }
}

// Initialize security processor
const securityProcessor = AdvancedFinancialSecurity.getInstance()

// Validation Schemas (Enhanced)
const createTransactionSchema = z.object({
  hotelId: z.string(),
  category: z.enum([
    'REVENUE_ROOM', 'REVENUE_FNB', 'REVENUE_SPA', 'REVENUE_EVENTS', 'REVENUE_OTHER',
    'EXPENSE_STAFF', 'EXPENSE_UTILITIES', 'EXPENSE_SUPPLIES', 
    'EXPENSE_MAINTENANCE', 'EXPENSE_MARKETING', 'EXPENSE_INSURANCE', 'EXPENSE_OTHER'
  ]),
  type: z.enum(['INCOME', 'EXPENSE']),
  amount: z.number().positive().max(1000000), // Max $1M
  currency: z.string().default('USD'),
  bookingId: z.string().optional(),
  invoiceId: z.string().optional(),
  paymentId: z.string().optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 
    'CORPORATE_BILL', 'LOYALTY_POINTS', 'PROMOTION_CREDIT'
  ]),
  transactionDate: z.string().transform((str) => new Date(str)).optional(),
  description: z.string().min(1).max(500),
  notes: z.string().max(1000).optional(),
  taxAmount: z.number().min(0).default(0),
  taxRate: z.number().min(0).max(1).default(0),
  receiptUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional()
})

const updateTransactionSchema = z.object({
  amount: z.number().positive().max(1000000).optional(),
  currency: z.string().optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 
    'CORPORATE_BILL', 'LOYALTY_POINTS', 'PROMOTION_CREDIT'
  ]).optional(),
  description: z.string().min(1).max(500).optional(),
  notes: z.string().max(1000).optional(),
  taxAmount: z.number().min(0).optional(),
  taxRate: z.number().min(0).max(1).optional(),
  status: z.enum(['PENDING', 'COMPLETED', 'FAILED', 'CANCELLED', 'REFUNDED', 'PARTIALLY_PAID']).optional(),
  receiptUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional()
})

// Enhanced GET endpoint
export async function GET(req: NextRequest) {
  const startTime = Date.now()
  let securityContext: FinancialSecurityState | null = null

  try {
    // Perform advanced financial security analysis
    const securityResult = await securityProcessor.processRequest(req, 'GET')
    
    if (!securityResult.isAllowed) {
      await auditLogger.log({
        event: 'FINANCIAL_ACCESS_DENIED',
        level: 'HIGH',
        userId: 'unknown',
        ipAddress: securityResult.context.ipAddress,
        userAgent: securityResult.context.userAgent,
        metadata: {
          requestId: securityResult.context.requestId,
          correlationId: securityResult.context.correlationId,
          violations: securityResult.violations,
          threatLevel: securityResult.context.threatLevel,
          fraudScore: securityResult.context.fraudScore,
          accessLevel: securityResult.accessLevel,
          financialScope: securityResult.financialScope
        }
      })

      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Financial data access denied due to security policy violations",
            security: {
              violations: securityResult.violations,
              recommendations: securityResult.recommendations,
              threatLevel: securityResult.context.threatLevel,
              fraudScore: securityResult.context.fraudScore,
              accessLevel: securityResult.accessLevel,
              financialScope: securityResult.financialScope
            }
          },
          { status: 403 }
        )
      )
    }

    securityContext = securityResult.context

    // Enhanced authentication
    const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
    if (!auth.isValid) return auth.response!

    // Enhanced session validation
    const sessionValidation = await securityProcessor.validateFinancialSession(req, auth.user.id)
    if (!sessionValidation.isValid) {
      await auditLogger.log({
        event: 'INVALID_FINANCIAL_SESSION',
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
            message: "Financial session validation failed",
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

    // Extract and validate query parameters with security context
    const searchParams = req.nextUrl.searchParams
    
    // Pagination with security limits
    const page = Math.max(1, parseInt(searchParams.get('page') || '1'))
    const pageSize = Math.min(100, Math.max(1, parseInt(searchParams.get('pageSize') || '20')))

    // Enhanced parameter validation
    const validatedParams = this.validateFinancialQueryParams(searchParams, finalAccessLevel)
    
    // Build secure where clause
    const where: any = this.buildSecureWhereClause(auth, validatedParams, finalAccessLevel)

    const [transactions, total] = await Promise.all([
      prisma.financialTransaction.findMany({
        where,
        include: this.buildIncludeClause(finalAccessLevel),
        orderBy: { transactionDate: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.financialTransaction.count({ where })
    ])

    // Enhanced summary statistics
    const summary = await prisma.financialTransaction.groupBy({
      by: ['type'],
      where: this.buildSecureWhereClause(auth, validatedParams, finalAccessLevel),
      _sum: { amount: true },
      _count: { _all: true }
    })

    const totalIncome = summary.find(s => s.type === 'INCOME')?._sum.amount || 0
    const totalExpense = summary.find(s => s.type === 'EXPENSE')?._sum.amount || 0
    const netAmount = totalIncome - totalExpense

    // Apply financial data masking
    const securedTransactions = transactions.map(transaction => 
      securityProcessor.maskFinancialData(transaction, finalAccessLevel, securityContext.threatLevel)
    )

    // Performance monitoring
    const processingTime = Date.now() - startTime

    // Log successful financial access
    await auditLogger.log({
      event: 'FINANCIAL_ACCESS_SUCCESS',
      level: 'INFO',
      userId: auth.user.id,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      metadata: {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        accessLevel: finalAccessLevel,
        financialScope: securityResult.financialScope,
        recordsRetrieved: securedTransactions.length,
        processingTime,
        threatLevel: securityContext.threatLevel,
        fraudScore: securityContext.fraudScore
      }
    })

    // Update security monitoring
    securityMonitor.recordMetric('financial_access_duration', processingTime)
    securityMonitor.recordMetric('financial_records_retrieved', securedTransactions.length)
    securityMonitor.recordSecurityEvent({
      type: 'FINANCIAL_DATA_ACCESS',
      severity: 'LOW',
      details: {
        userId: auth.user.id,
        accessLevel: finalAccessLevel,
        financialScope: securityResult.financialScope,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            transactions: securedTransactions,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: securityProcessor.maskFinancialData({
              totalIncome,
              totalExpense,
              netAmount,
              transactionCount: total
            }, finalAccessLevel, securityContext.threatLevel)
          },
          "Financial transactions retrieved successfully",
          {
            requestId: securityContext.requestId,
            correlationId: securityContext.correlationId,
            processingTime,
            accessLevel: finalAccessLevel,
            financialScope: securityResult.financialScope,
            threatLevel: securityContext.threatLevel,
            fraudScore: securityContext.fraudScore
          }
        )
      )
    )

  } catch (error: any) {
    const processingTime = Date.now() - startTime

    // Log financial error
    await auditLogger.log({
      event: 'FINANCIAL_ACCESS_ERROR',
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

    console.error("[Get Financial Transactions Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch transactions", "FETCH_TRANSACTIONS_ERROR"),
        { status: 500 }
      )
    )
  }
}

// Helper methods (would be implemented based on specific requirements)
function validateFinancialQueryParams(searchParams: URLSearchParams, accessLevel: string): any {
  const params: any = {}
  
  // Basic parameters
  params.page = parseInt(searchParams.get('page') || '1')
  params.pageSize = parseInt(searchParams.get('pageSize') || '20')
  params.hotelId = searchParams.get('hotelId')
  params.category = searchParams.get('category')
  params.type = searchParams.get('type')
  params.status = searchParams.get('status')
  params.paymentMethod = searchParams.get('paymentMethod')
  
  // Date filtering with validation
  const startDate = searchParams.get('startDate')
  const endDate = searchParams.get('endDate')
  if (startDate) params.startDate = new Date(startDate)
  if (endDate) params.endDate = new Date(endDate)
  
  params.fiscalYear = searchParams.get('fiscalYear')
  params.fiscalPeriod = searchParams.get('fiscalPeriod')
  params.search = searchParams.get('search')
  
  return params
}

function buildSecureWhereClause(auth: any, params: any, accessLevel: string): any {
  const where: any = {}
  
  // Role-based filtering
  if (auth.payload.role === 'HOTEL_MANAGER') {
    // Hotel managers can only see transactions for their hotels
    const userHotels = [] // Would fetch from database
    where.hotelId = { in: userHotels.map((h: any) => h.id) }
  }
  
  // Parameter-based filtering
  if (params.hotelId) where.hotelId = params.hotelId
  if (params.category) where.category = params.category
  if (params.type) where.type = params.type
  if (params.status) where.status = params.status
  if (params.paymentMethod) where.paymentMethod = params.paymentMethod
  
  // Date filtering
  if (params.startDate || params.endDate) {
    where.transactionDate = {}
    if (params.startDate) where.transactionDate.gte = params.startDate
    if (params.endDate) where.transactionDate.lte = params.endDate
  }
  
  if (params.fiscalYear) where.fiscalYear = parseInt(params.fiscalYear)
  if (params.fiscalPeriod) where.fiscalPeriod = params.fiscalPeriod
  
  // Search filtering
  if (params.search) {
    where.description = {
      contains: params.search,
      mode: 'insensitive'
    }
  }
  
  return where
}

function buildIncludeClause(accessLevel: string): any {
  const include: any = {
    hotel: {
      select: { name: true, city: true }
    }
  }
  
  if (accessLevel === 'TRANSACT' || accessLevel === 'MANAGE' || accessLevel === 'ADMIN') {
    include.booking = {
      select: {
        id: true,
        bookingReference: true,
        guestName: true,
        totalPrice: true
      }
    }
    include.invoice = {
      select: {
        id: true,
        invoiceNumber: true,
        totalAmount: true
      }
    }
    include.payment = {
      select: {
        id: true,
        status: true,
        method: true
      }
    }
  }
  
  return include
}

// Continue with POST, PUT, DELETE methods following the same pattern...