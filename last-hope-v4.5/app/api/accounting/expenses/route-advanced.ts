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

// Enhanced security constants for expense management
const SECURITY_CONFIG = {
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: {
    GET: 80,
    POST: 15,
    PUT: 10,
    DELETE: 3
  },
  SESSION_VALIDATION_TIMEOUT: 5 * 60 * 1000, // 5 minutes
  EXPENSE_DATA_RETENTION_DAYS: 2555, // 7 years for tax compliance
  ENCRYPTION_ENABLED: true,
  SENSITIVE_DATA_MASKING: true,
  EXPENSE_FRAUD_DETECTION_ENABLED: true,
  EXPENSE_ANOMALY_THRESHOLD: 0.20, // 20% deviation from normal
  APPROVAL_REQUIRED_THRESHOLD: 1000, // $1000+ requires approval
  CONCURRENT_EXPENSE_LIMIT: 2
}

// Advanced security state for expense operations
interface ExpenseSecurityState {
  requestId: string
  deviceFingerprint: string
  userAgent: string
  ipAddress: string
  riskScore: number
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  sessionToken: string
  correlationId: string
  accessLevel: 'VIEW' | 'CREATE' | 'APPROVE' | 'MANAGE' | 'ADMIN'
  expenseScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE'
  fraudScore: number
  anomalies: string[]
  approvalRequired: boolean
}

class AdvancedExpenseSecurity {
  private static instance: AdvancedExpenseSecurity
  private securityContext: Map<string, ExpenseSecurityState> = new Map()
  private requestPatterns: Map<string, number[]> = new Map()
  private expensePatterns: Map<string, any> = new Map()
  private approvalPatterns: Map<string, any> = new Map()

  private constructor() {}

  static getInstance(): AdvancedExpenseSecurity {
    if (!AdvancedExpenseSecurity.instance) {
      AdvancedExpenseSecurity.instance = new AdvancedExpenseSecurity()
    }
    return AdvancedExpenseSecurity.instance
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

  // AI-powered fraud detection for expense management
  private analyzeExpenseThreat(
    context: ExpenseSecurityState, 
    method: string,
    expenseData?: any
  ): {
    threatScore: number
    fraudScore: number
    detectedThreats: string[]
    anomalies: string[]
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    accessLevel: 'VIEW' | 'CREATE' | 'APPROVE' | 'MANAGE' | 'ADMIN'
    expenseScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE'
    approvalRequired: boolean
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

    // Expense-specific threat detection
    if (recentRequestCount > 40) {
      threats.push('EXCESSIVE_EXPENSE_ACCESS')
      threatScore += 25
      fraudScore += 15
    }

    // Unusual timing for expense operations
    if (this.isUnusualTimeForExpenses()) {
      threats.push('UNUSUAL_EXPENSE_TIME')
      threatScore += 20
      fraudScore += 10
    }

    // Geographic anomaly for expense operations
    if (this.isSuspiciousExpenseGeographic(context.ipAddress)) {
      threats.push('SUSPICIOUS_EXPENSE_GEOGRAPHIC')
      threatScore += 30
      fraudScore += 20
    }

    // Device fingerprint anomalies for expenses
    if (this.isExpenseDeviceAnomaly(context.deviceFingerprint)) {
      threats.push('EXPENSE_DEVICE_ANOMALY')
      threatScore += 20
      fraudScore += 25
    }

    // Expense-specific fraud detection
    if (expenseData && method === 'POST') {
      const fraudAnalysis = this.analyzeExpenseFraud(expenseData, context)
      fraudScore += fraudAnalysis.fraudScore
      anomalies.push(...fraudAnalysis.anomalies)
    }

    // Approval workflow anomalies
    if (method === 'PUT' && expenseData?.isApproved) {
      const approvalAnalysis = this.analyzeApprovalAnomaly(expenseData, context)
      threatScore += approvalAnalysis.threatScore
      anomalies.push(...approvalAnalysis.anomalies)
    }

    // Behavioral analysis for expense operations
    if (this.isExpenseBehavioralAnomaly(context.userAgent, recentRequestCount)) {
      threats.push('EXPENSE_BEHAVIORAL_ANOMALY')
      threatScore += 15
      fraudScore += 10
    }

    // Concurrent expense operations
    if (method !== 'GET' && this.hasConcurrentExpenses(context.sessionToken)) {
      threats.push('CONCURRENT_EXPENSE_OPERATIONS')
      threatScore += 20
      fraudScore += 15
    }

    // Determine access levels based on risk and role
    let accessLevel: 'VIEW' | 'CREATE' | 'APPROVE' | 'MANAGE' | 'ADMIN' = 'VIEW'
    let expenseScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE' = 'BASIC'
    let approvalRequired = false

    if (threatScore === 0 && fraudScore === 0) {
      accessLevel = 'ADMIN'
      expenseScope = 'COMPLIANCE'
    } else if (threatScore < 15 && fraudScore < 15) {
      accessLevel = 'MANAGE'
      expenseScope = 'FULL'
    } else if (threatScore < 30 && fraudScore < 30) {
      accessLevel = 'APPROVE'
      expenseScope = 'DETAILED'
      approvalRequired = expenseData?.amount > SECURITY_CONFIG.APPROVAL_REQUIRED_THRESHOLD
    } else if (threatScore < 45) {
      accessLevel = 'CREATE'
      expenseScope = 'DETAILED'
      approvalRequired = true
    }

    // Risk level determination
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    const totalRiskScore = threatScore + fraudScore
    
    if (totalRiskScore >= 70) riskLevel = 'CRITICAL'
    else if (totalRiskScore >= 50) riskLevel = 'HIGH'
    else if (totalRiskScore >= 25) riskLevel = 'MEDIUM'

    return { 
      threatScore, 
      fraudScore, 
      detectedThreats: threats, 
      anomalies,
      riskLevel, 
      accessLevel,
      expenseScope,
      approvalRequired
    }
  }

  private isUnusualTimeForExpenses(): boolean {
    const hour = new Date().getHours()
    const dayOfWeek = new Date().getDay()
    
    // Flag access during off-hours for expense operations
    return (hour >= 20 || hour <= 6) || (dayOfWeek === 0 || dayOfWeek === 6)
  }

  private isSuspiciousExpenseGeographic(ipAddress: string): boolean {
    // Geographic risk assessment for expense operations
    const suspiciousPatterns = [
      /^192\.168\./, // Private networks
      /^10\./, // Private networks
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private networks
      /^127\./, // Localhost
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(ipAddress))
    return isSuspicious && ipAddress !== '127.0.0.1'
  }

  private isExpenseDeviceAnomaly(fingerprint: string): boolean {
    return fingerprint.length < 16 || 
           !/^[a-f0-9]+$/.test(fingerprint) ||
           this.isKnownExpenseDevice(fingerprint)
  }

  private isKnownExpenseDevice(fingerprint: string): boolean {
    return fingerprint.includes('bot') || fingerprint.includes('crawler')
  }

  private analyzeExpenseFraud(expenseData: any, context: ExpenseSecurityState): {
    fraudScore: number
    anomalies: string[]
  } {
    const anomalies: string[] = []
    let fraudScore = 0

    // Check for high-value expenses
    if (expenseData.amount > 5000) {
      anomalies.push('HIGH_VALUE_EXPENSE')
      fraudScore += 25
    } else if (expenseData.amount > 1000) {
      anomalies.push('MEDIUM_VALUE_EXPENSE')
      fraudScore += 15
    }

    // Check for suspicious payment methods
    const suspiciousPaymentMethods = ['CASH', 'CHECK']
    if (suspiciousPaymentMethods.includes(expenseData.paymentMethod)) {
      anomalies.push('SUSPICIOUS_PAYMENT_METHOD')
      fraudScore += 15
    }

    // Check for round number amounts (potential fraud indicator)
    if (expenseData.amount % 100 === 0 && expenseData.amount >= 500) {
      anomalies.push('ROUND_NUMBER_EXPENSE')
      fraudScore += 10
    }

    // Check for missing vendor (potential personal expense)
    if (!expenseData.vendorId) {
      anomalies.push('NO_VENDOR_SPECIFIED')
      fraudScore += 20
    }

    // Check for off-hours creation
    if (this.isUnusualTimeForExpenses()) {
      anomalies.push('OFF_HOURS_EXPENSE_CREATION')
      fraudScore += 10
    }

    // Check for rapid expense submissions
    const recentExpenses = this.getRecentExpenses(context.sessionToken)
    if (recentExpenses.length > SECURITY_CONFIG.CONCURRENT_EXPENSE_LIMIT) {
      anomalies.push('RAPID_EXPENSE_SUBMISSIONS')
      fraudScore += 20
    }

    return { fraudScore, anomalies }
  }

  private analyzeApprovalAnomaly(approvalData: any, context: ExpenseSecurityState): {
    threatScore: number
    anomalies: string[]
  } {
    const anomalies: string[] = []
    let threatScore = 0

    // Check for approval without proper authorization
    if (approvalData.amount > SECURITY_CONFIG.APPROVAL_REQUIRED_THRESHOLD) {
      const approvalHistory = this.getApprovalHistory(context.sessionToken)
      if (approvalHistory.length === 0) {
        anomalies.push('FIRST_TIME_HIGH_VALUE_APPROVAL')
        threatScore += 15
      }
    }

    // Check for rapid approvals
    const recentApprovals = this.getRecentApprovals(context.sessionToken)
    if (recentApprovals.length > 5) {
      anomalies.push('RAPID_APPROVAL_SEQUENCE')
      threatScore += 20
    }

    return { threatScore, anomalies }
  }

  private getRecentExpenses(sessionToken: string): any[] {
    const key = `expenses:${sessionToken}`
    return this.expensePatterns.get(key) || []
  }

  private getRecentApprovals(sessionToken: string): any[] {
    const key = `approvals:${sessionToken}`
    return this.approvalPatterns.get(key) || []
  }

  private getApprovalHistory(sessionToken: string): any[] {
    const key = `approval_history:${sessionToken}`
    return this.approvalPatterns.get(key) || []
  }

  private hasConcurrentExpenses(sessionToken: string): boolean {
    const recentExpenses = this.getRecentExpenses(sessionToken)
    const now = Date.now()
    const oneMinuteAgo = now - 60000 // 1 minute
    
    return recentExpenses.filter(t => t.timestamp > oneMinuteAgo).length > 
           SECURITY_CONFIG.CONCURRENT_EXPENSE_LIMIT
  }

  private isExpenseBehavioralAnomaly(userAgent: string, requestCount: number): boolean {
    const suspiciousPatterns = [
      /bot|crawler|spider/i,
      /python|curl|wget/i,
      /postman/i
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(userAgent))
    const isHighFrequency = requestCount > 60
    
    return isSuspicious || isHighFrequency
  }

  // Advanced session validation for expense operations
  private async validateExpenseSession(req: NextRequest, userId: string): Promise<{
    isValid: boolean
    sessionState: any
    violations: string[]
    accessLevel: 'VIEW' | 'CREATE' | 'APPROVE' | 'MANAGE' | 'ADMIN'
  }> {
    const violations: string[] = []
    
    try {
      const sessionToken = req.headers.get('x-session-token')
      const refreshToken = req.headers.get('x-refresh-token')
      
      if (!sessionToken) {
        violations.push('MISSING_EXPENSE_SESSION_TOKEN')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Enhanced JWT session validation
      const secret = new TextEncoder().encode(process.env.REFRESH_TOKEN_SECRET || 'fallback-secret')
      const { payload } = await jwtVerify(sessionToken, secret)
      
      // Session expiration check
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        violations.push('EXPENSE_SESSION_EXPIRED')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Device fingerprint validation
      const deviceInfo = this.extractDeviceInfo(req)
      const sessionFingerprint = payload.deviceFingerprint as string
      if (sessionFingerprint && sessionFingerprint !== deviceInfo.fingerprint) {
        violations.push('EXPENSE_DEVICE_MISMATCH')
      }

      // Expense role-based access validation
      const sessionRole = payload.role as string
      const expenseAccessLevel = this.determineExpenseAccessLevel(sessionRole)
      
      return { 
        isValid: violations.length === 0, 
        sessionState: payload, 
        violations,
        accessLevel: expenseAccessLevel
      }
    } catch (error) {
      violations.push('EXPENSE_SESSION_VALIDATION_ERROR')
      return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
    }
  }

  private determineExpenseAccessLevel(role: string): 'VIEW' | 'CREATE' | 'APPROVE' | 'MANAGE' | 'ADMIN' {
    switch (role?.toUpperCase()) {
      case 'SUPER_ADMIN':
      case 'FINANCIAL_ADMIN':
        return 'ADMIN'
      case 'ADMIN':
      case 'ACCOUNTANT':
      case 'FINANCIAL_MANAGER':
        return 'MANAGE'
      case 'HOTEL_MANAGER':
        return 'APPROVE'
      case 'STAFF':
        return 'CREATE'
      default:
        return 'VIEW'
    }
  }

  // Mask sensitive expense data
  private maskExpenseData(data: any, accessLevel: string, threatLevel: string): any {
    const masked = { ...data }

    if (accessLevel === 'VIEW' || threatLevel === 'HIGH' || threatLevel === 'CRITICAL') {
      // Apply data masking for sensitive expense information
      if (typeof masked.amount === 'number') {
        masked.amount = Math.round(masked.amount / 50) * 50 // Round to nearest fifty
      }
      if (typeof masked.totalAmount === 'number') {
        masked.totalAmount = Math.round(masked.totalAmount / 50) * 50
      }
      
      // Mask vendor details for basic access
      if (masked.vendor && accessLevel === 'VIEW') {
        masked.vendor = {
          ...masked.vendor,
          name: '***MASKED***',
          companyName: '***MASKED***'
        }
      }
    }

    return masked
  }

  // Record comprehensive expense security event
  private recordExpenseSecurityEvent(event: any): void {
    try {
      auditLogger.log({
        event: 'EXPENSE_OPERATION',
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
          expenseScope: event.expenseScope,
          anomalies: event.anomalies,
          approvalRequired: event.approvalRequired,
          expenseData: event.expenseData ? 'PRESENT' : 'ABSENT'
        }
      })
    } catch (error) {
      console.error('Failed to record expense security event:', error)
    }
  }

  // Main security processing
  public async processRequest(
    req: NextRequest, 
    method: string,
    expenseData?: any
  ): Promise<{
    isAllowed: boolean
    context: ExpenseSecurityState
    violations: string[]
    recommendations: string[]
    accessLevel: 'VIEW' | 'CREATE' | 'APPROVE' | 'MANAGE' | 'ADMIN'
    expenseScope: 'BASIC' | 'DETAILED' | 'FULL' | 'COMPLIANCE'
  }> {
    const requestId = this.generateRequestId()
    const correlationId = this.generateCorrelationId()
    
    const { fingerprint, userAgent } = this.extractDeviceInfo(req)
    const ipAddress = req.headers.get('x-forwarded-for') || req.ip || 'unknown'

    const context: ExpenseSecurityState = {
      requestId,
      deviceFingerprint: fingerprint,
      userAgent,
      ipAddress,
      riskScore: 0,
      threatLevel: 'LOW',
      sessionToken: req.headers.get('x-session-token') || '',
      correlationId,
      accessLevel: 'VIEW',
      expenseScope: 'BASIC',
      fraudScore: 0,
      anomalies: [],
      approvalRequired: false
    }

    const violations: string[] = []
    const recommendations: string[] = []

    try {
      // Enhanced rate limiting based on method
      const rateLimitKey = `${ipAddress}:expense-${method.toLowerCase()}`
      const rateLimitMax = SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS[method] || 40
      const rateLimitResult = await rateLimit.check(rateLimitKey, rateLimitMax, SECURITY_CONFIG.RATE_LIMIT_WINDOW)
      
      if (!rateLimitResult.allowed) {
        violations.push('EXPENSE_RATE_LIMIT_EXCEEDED')
        recommendations.push('Implement exponential backoff for expense operations')
      }

      // Record request pattern
      const now = Date.now()
      const requests = this.requestPatterns.get(ipAddress) || []
      requests.push(now)
      this.requestPatterns.set(ipAddress, requests.filter(timestamp => now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW))

      // Threat and fraud analysis
      const threatAnalysis = this.analyzeExpenseThreat(context, method, expenseData)
      context.riskScore = threatAnalysis.threatScore
      context.threatLevel = threatAnalysis.riskLevel
      context.accessLevel = threatAnalysis.accessLevel
      context.expenseScope = threatAnalysis.expenseScope
      context.fraudScore = threatAnalysis.fraudScore
      context.anomalies = threatAnalysis.anomalies
      context.approvalRequired = threatAnalysis.approvalRequired

      if (threatAnalysis.detectedThreats.length > 0) {
        violations.push(...threatAnalysis.detectedThreats)
        recommendations.push('Review expense access patterns and implement additional controls')
      }

      if (threatAnalysis.anomalies.length > 0) {
        violations.push(...threatAnalysis.anomalies)
        recommendations.push('Investigate expense anomalies')
      }

      // Final security decision
      const isAllowed = violations.length === 0 || context.threatLevel !== 'CRITICAL'

      // Record comprehensive security event
      this.recordExpenseSecurityEvent({
        event: 'EXPENSE_SECURITY_CHECK',
        userId: 'unknown',
        ipAddress,
        userAgent,
        requestId,
        correlationId,
        operation: method,
        accessLevel: context.accessLevel,
        expenseScope: context.expenseScope,
        threatLevel: context.threatLevel,
        fraudScore: context.fraudScore,
        anomalies: context.anomalies,
        approvalRequired: context.approvalRequired,
        expenseData,
        violations
      })

      return { 
        isAllowed, 
        context, 
        violations, 
        recommendations,
        accessLevel: context.accessLevel,
        expenseScope: context.expenseScope
      }

    } catch (error) {
      violations.push('EXPENSE_SECURITY_PROCESSING_ERROR')
      return { 
        isAllowed: false, 
        context, 
        violations,
        recommendations: ['Contact system administrator immediately'],
        accessLevel: 'VIEW',
        expenseScope: 'BASIC'
      }
    }
  }
}

// Initialize security processor
const securityProcessor = AdvancedExpenseSecurity.getInstance()

// Validation Schemas (Enhanced)
const createExpenseSchema = z.object({
  hotelId: z.string(),
  categoryId: z.string(),
  vendorId: z.string().optional(),
  amount: z.number().positive().max(100000), // Max $100K
  currency: z.string().default('USD'),
  description: z.string().min(1).max(500),
  notes: z.string().max(1000).optional(),
  expenseDate: z.string().transform((str) => new Date(str)).optional(),
  dueDate: z.string().transform((str) => new Date(str)).optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 'CORPORATE_BILL'
  ]),
  invoiceNumber: z.string().optional(),
  receiptNumber: z.string().optional(),
  receiptUrl: z.string().url().optional(),
  invoiceUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional(),
  bookingId: z.string().optional()
})

const updateExpenseSchema = z.object({
  amount: z.number().positive().max(100000).optional(),
  currency: z.string().optional(),
  description: z.string().min(1).max(500).optional(),
  notes: z.string().max(1000).optional(),
  expenseDate: z.string().transform((str) => new Date(str)).optional(),
  dueDate: z.string().transform((str) => new Date(str)).optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 'CORPORATE_BILL'
  ]).optional(),
  invoiceNumber: z.string().optional(),
  receiptNumber: z.string().optional(),
  receiptUrl: z.string().url().optional(),
  invoiceUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional(),
  isApproved: z.boolean().optional(),
  approvalNotes: z.string().optional()
})

// Enhanced GET endpoint
export async function GET(req: NextRequest) {
  const startTime = Date.now()
  let securityContext: ExpenseSecurityState | null = null

  try {
    // Perform advanced expense security analysis
    const securityResult = await securityProcessor.processRequest(req, 'GET')
    
    if (!securityResult.isAllowed) {
      await auditLogger.log({
        event: 'EXPENSE_ACCESS_DENIED',
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
          expenseScope: securityResult.expenseScope
        }
      })

      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Expense data access denied due to security policy violations",
            security: {
              violations: securityResult.violations,
              recommendations: securityResult.recommendations,
              threatLevel: securityResult.context.threatLevel,
              fraudScore: securityResult.context.fraudScore,
              accessLevel: securityResult.accessLevel,
              expenseScope: securityResult.expenseScope
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
    const sessionValidation = await securityProcessor.validateExpenseSession(req, auth.user.id)
    if (!sessionValidation.isValid) {
      await auditLogger.log({
        event: 'INVALID_EXPENSE_SESSION',
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
            message: "Expense session validation failed",
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
    const pageSize = Math.min(50, Math.max(1, parseInt(searchParams.get('pageSize') || '20')))

    // Enhanced parameter validation
    const validatedParams = this.validateExpenseQueryParams(searchParams, finalAccessLevel)
    
    // Build secure where clause
    const where: any = this.buildSecureExpenseWhereClause(auth, validatedParams, finalAccessLevel)

    const [expenses, total] = await Promise.all([
      prisma.expenseRecord.findMany({
        where,
        include: this.buildExpenseIncludeClause(finalAccessLevel),
        orderBy: { expenseDate: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.expenseRecord.count({ where })
    ])

    // Enhanced summary statistics
    const summary = await prisma.expenseRecord.groupBy({
      by: ['status'],
      where: this.buildSecureExpenseWhereClause(auth, validatedParams, finalAccessLevel),
      _sum: { totalAmount: true },
      _count: true
    })

    const totalExpenses = summary.reduce((sum, item) => sum + (item._sum.totalAmount || 0), 0)
    const approvedExpenses = summary.find(s => s.status === 'COMPLETED')?._sum.totalAmount || 0
    const pendingExpenses = summary.find(s => s.status === 'PENDING')?._sum.totalAmount || 0

    // Apply expense data masking
    const securedExpenses = expenses.map(expense => 
      securityProcessor.maskExpenseData(expense, finalAccessLevel, securityContext.threatLevel)
    )

    // Performance monitoring
    const processingTime = Date.now() - startTime

    // Log successful expense access
    await auditLogger.log({
      event: 'EXPENSE_ACCESS_SUCCESS',
      level: 'INFO',
      userId: auth.user.id,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      metadata: {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        accessLevel: finalAccessLevel,
        expenseScope: securityResult.expenseScope,
        recordsRetrieved: securedExpenses.length,
        processingTime,
        threatLevel: securityContext.threatLevel,
        fraudScore: securityContext.fraudScore
      }
    })

    // Update security monitoring
    securityMonitor.recordMetric('expense_access_duration', processingTime)
    securityMonitor.recordMetric('expense_records_retrieved', securedExpenses.length)
    securityMonitor.recordSecurityEvent({
      type: 'EXPENSE_DATA_ACCESS',
      severity: 'LOW',
      details: {
        userId: auth.user.id,
        accessLevel: finalAccessLevel,
        expenseScope: securityResult.expenseScope,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            expenses: securedExpenses,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: securityProcessor.maskExpenseData({
              totalExpenses,
              approvedExpenses,
              pendingExpenses,
              expenseCount: total
            }, finalAccessLevel, securityContext.threatLevel)
          },
          "Expenses retrieved successfully",
          {
            requestId: securityContext.requestId,
            correlationId: securityContext.correlationId,
            processingTime,
            accessLevel: finalAccessLevel,
            expenseScope: securityResult.expenseScope,
            threatLevel: securityContext.threatLevel,
            fraudScore: securityContext.fraudScore
          }
        )
      )
    )

  } catch (error: any) {
    const processingTime = Date.now() - startTime

    // Log expense error
    await auditLogger.log({
      event: 'EXPENSE_ACCESS_ERROR',
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

    console.error("[Get Expenses Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch expenses", "FETCH_EXPENSES_ERROR"),
        { status: 500 }
      )
    )
  }
}

// Helper methods for expense operations
function validateExpenseQueryParams(searchParams: URLSearchParams, accessLevel: string): any {
  const params: any = {}
  
  // Basic parameters
  params.page = parseInt(searchParams.get('page') || '1')
  params.pageSize = parseInt(searchParams.get('pageSize') || '20')
  params.hotelId = searchParams.get('hotelId')
  params.categoryId = searchParams.get('categoryId')
  params.vendorId = searchParams.get('vendorId')
  params.status = searchParams.get('status')
  params.paymentMethod = searchParams.get('paymentMethod')
  params.isApproved = searchParams.get('isApproved')
  
  // Date filtering with validation
  const startDate = searchParams.get('startDate')
  const endDate = searchParams.get('endDate')
  if (startDate) params.startDate = new Date(startDate)
  if (endDate) params.endDate = new Date(endDate)
  
  params.search = searchParams.get('search')
  
  return params
}

function buildSecureExpenseWhereClause(auth: any, params: any, accessLevel: string): any {
  const where: any = {}
  
  // Role-based filtering
  if (auth.payload.role === 'HOTEL_MANAGER') {
    const userHotels = [] // Would fetch from database
    where.hotelId = { in: userHotels.map((h: any) => h.id) }
  }
  
  // Parameter-based filtering
  if (params.hotelId) where.hotelId = params.hotelId
  if (params.categoryId) where.categoryId = params.categoryId
  if (params.vendorId) where.vendorId = params.vendorId
  if (params.status) where.status = params.status
  if (params.paymentMethod) where.paymentMethod = params.paymentMethod
  if (params.isApproved !== null && params.isApproved !== undefined) {
    where.isApproved = params.isApproved === 'true'
  }
  
  // Date filtering
  if (params.startDate || params.endDate) {
    where.expenseDate = {}
    if (params.startDate) where.expenseDate.gte = params.startDate
    if (params.endDate) where.expenseDate.lte = params.endDate
  }
  
  // Search filtering
  if (params.search) {
    where.description = {
      contains: params.search,
      mode: 'insensitive'
    }
  }
  
  return where
}

function buildExpenseIncludeClause(accessLevel: string): any {
  const include: any = {
    hotel: {
      select: { name: true, city: true }
    },
    category: {
      select: { name: true, categoryType: true }
    }
  }
  
  if (accessLevel === 'CREATE' || accessLevel === 'APPROVE' || accessLevel === 'MANAGE' || accessLevel === 'ADMIN') {
    include.vendor = {
      select: {
        name: true,
        companyName: true,
        rating: true,
        reliabilityScore: true
      }
    }
    include.booking = {
      select: {
        id: true,
        bookingReference: true,
        guestName: true
      }
    }
  }
  
  return include
}

// Continue with POST, PUT, DELETE methods following the same security patterns...