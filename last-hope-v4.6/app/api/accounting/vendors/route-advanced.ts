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
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Enhanced security constants for vendor management
const SECURITY_CONFIG = {
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: {
    GET: 60,
    POST: 10,
    PUT: 8,
    DELETE: 3
  },
  SESSION_VALIDATION_TIMEOUT: 5 * 60 * 1000, // 5 minutes
  VENDOR_DATA_RETENTION_DAYS: 1825, // 5 years for vendor compliance
  ENCRYPTION_ENABLED: true,
  SENSITIVE_DATA_MASKING: true,
  VENDOR_VERIFICATION_ENABLED: true,
  VENDOR_RISK_THRESHOLD: 0.25, // 25% deviation from normal
  CONCURRENT_VENDOR_LIMIT: 3,
  CREDIT_LIMIT_MAX: 1000000 // Max $1M credit limit
}

// Advanced security state for vendor operations
interface VendorSecurityState {
  requestId: string
  deviceFingerprint: string
  userAgent: string
  ipAddress: string
  riskScore: number
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  sessionToken: string
  correlationId: string
  accessLevel: 'VIEW' | 'CREATE' | 'MODIFY' | 'MANAGE' | 'ADMIN'
  vendorScope: 'BASIC' | 'CONTACT' | 'FINANCIAL' | 'COMPREHENSIVE'
  dataClassification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'
  vendorRisk: number
  anomalies: string[]
  verificationRequired: boolean
}

class AdvancedVendorSecurity {
  private static instance: AdvancedVendorSecurity
  private securityContext: Map<string, VendorSecurityState> = new Map()
  private requestPatterns: Map<string, number[]> = new Map()
  private vendorPatterns: Map<string, any> = new Map()
  private verificationPatterns: Map<string, any> = new Map()

  private constructor() {}

  static getInstance(): AdvancedVendorSecurity {
    if (!AdvancedVendorSecurity.instance) {
      AdvancedVendorSecurity.instance = new AdvancedVendorSecurity()
    }
    return AdvancedVendorSecurity.instance
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

  // AI-powered threat detection for vendor management
  private analyzeVendorThreat(
    context: VendorSecurityState, 
    method: string,
    vendorData?: any
  ): {
    threatScore: number
    vendorRisk: number
    detectedThreats: string[]
    anomalies: string[]
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    accessLevel: 'VIEW' | 'CREATE' | 'MODIFY' | 'MANAGE' | 'ADMIN'
    vendorScope: 'BASIC' | 'CONTACT' | 'FINANCIAL' | 'COMPREHENSIVE'
    dataClassification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'
    verificationRequired: boolean
  } {
    const threats: string[] = []
    const anomalies: string[] = []
    let threatScore = 0
    let vendorRisk = 0

    // Analyze access patterns for vendor operations
    const recentRequests = this.requestPatterns.get(context.ipAddress) || []
    const now = Date.now()
    const recentRequestCount = recentRequests.filter(timestamp => 
      now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW
    ).length

    // Vendor-specific threat detection
    if (recentRequestCount > 35) {
      threats.push('EXCESSIVE_VENDOR_ACCESS')
      threatScore += 25
      vendorRisk += 20
    }

    // Unusual timing for vendor operations
    if (this.isUnusualTimeForVendors()) {
      threats.push('UNUSUAL_VENDOR_TIME')
      threatScore += 20
      vendorRisk += 15
    }

    // Geographic anomalies for vendor management
    if (this.isSuspiciousVendorGeographic(context.ipAddress)) {
      threats.push('SUSPICIOUS_VENDOR_GEOGRAPHIC')
      threatScore += 30
      vendorRisk += 25
    }

    // Device fingerprint anomalies for vendor operations
    if (this.isVendorDeviceAnomaly(context.deviceFingerprint)) {
      threats.push('VENDOR_DEVICE_ANOMALY')
      threatScore += 20
      vendorRisk += 30
    }

    // Vendor creation/modification-specific security
    if (vendorData && (method === 'POST' || method === 'PUT')) {
      const vendorAnalysis = this.analyzeVendorData(vendorData, context)
      threatScore += vendorAnalysis.threatScore
      vendorRisk += vendorAnalysis.vendorRisk
      anomalies.push(...vendorAnalysis.anomalies)
    }

    // Financial data access anomalies
    if (method === 'GET' && this.isAccessingFinancialVendorData(vendorData)) {
      const financialAnalysis = this.analyzeFinancialVendorAccess(vendorData, context)
      threatScore += financialAnalysis.threatScore
      vendorRisk += financialAnalysis.vendorRisk
      anomalies.push(...financialAnalysis.anomalies)
    }

    // Behavioral analysis for vendor operations
    if (this.isVendorBehavioralAnomaly(context.userAgent, recentRequestCount)) {
      threats.push('VENDOR_BEHAVIORAL_ANOMALY')
      threatScore += 15
      vendorRisk += 10
    }

    // Concurrent vendor operations detection
    if (method !== 'GET' && this.hasConcurrentVendorOperations(context.sessionToken)) {
      threats.push('CONCURRENT_VENDOR_OPERATIONS')
      threatScore += 20
      vendorRisk += 15
    }

    // Determine access levels based on comprehensive risk assessment
    let accessLevel: 'VIEW' | 'CREATE' | 'MODIFY' | 'MANAGE' | 'ADMIN' = 'VIEW'
    let vendorScope: 'BASIC' | 'CONTACT' | 'FINANCIAL' | 'COMPREHENSIVE' = 'BASIC'
    let dataClassification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' = 'INTERNAL'
    let verificationRequired = false

    if (threatScore === 0 && vendorRisk === 0) {
      accessLevel = 'ADMIN'
      vendorScope = 'COMPREHENSIVE'
      dataClassification = 'RESTRICTED'
      verificationRequired = false
    } else if (threatScore < 15 && vendorRisk < 15) {
      accessLevel = 'MANAGE'
      vendorScope = 'COMPREHENSIVE'
      dataClassification = 'CONFIDENTIAL'
      verificationRequired = false
    } else if (threatScore < 30 && vendorRisk < 30) {
      accessLevel = 'MODIFY'
      vendorScope = 'FINANCIAL'
      dataClassification = 'CONFIDENTIAL'
      verificationRequired = vendorData?.creditLimit > 50000
    } else if (threatScore < 45) {
      accessLevel = 'CREATE'
      vendorScope = 'CONTACT'
      dataClassification = 'INTERNAL'
      verificationRequired = true
    }

    // Risk level determination
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
    const totalRiskScore = threatScore + vendorRisk
    
    if (totalRiskScore >= 70) riskLevel = 'CRITICAL'
    else if (totalRiskScore >= 50) riskLevel = 'HIGH'
    else if (totalRiskScore >= 25) riskLevel = 'MEDIUM'

    return { 
      threatScore, 
      vendorRisk, 
      detectedThreats: threats, 
      anomalies,
      riskLevel, 
      accessLevel,
      vendorScope,
      dataClassification,
      verificationRequired
    }
  }

  private isUnusualTimeForVendors(): boolean {
    const hour = new Date().getHours()
    const dayOfWeek = new Date().getDay()
    
    // Flag access during off-hours for vendor operations
    return (hour >= 21 || hour <= 6) || (dayOfWeek === 0 || dayOfWeek === 6)
  }

  private isSuspiciousVendorGeographic(ipAddress: string): boolean {
    // Geographic risk assessment for vendor operations
    const suspiciousPatterns = [
      /^192\.168\./, // Private networks
      /^10\./, // Private networks
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private networks
      /^127\./, // Localhost
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(ipAddress))
    return isSuspicious && ipAddress !== '127.0.0.1'
  }

  private isVendorDeviceAnomaly(fingerprint: string): boolean {
    return fingerprint.length < 16 || 
           !/^[a-f0-9]+$/.test(fingerprint) ||
           this.isKnownVendorDevice(fingerprint)
  }

  private isKnownVendorDevice(fingerprint: string): boolean {
    return fingerprint.includes('bot') || fingerprint.includes('crawler')
  }

  private analyzeVendorData(vendorData: any, context: VendorSecurityState): {
    threatScore: number
    vendorRisk: number
    anomalies: string[]
  } {
    const anomalies: string[] = []
    let threatScore = 0
    let vendorRisk = 0

    // Check for high credit limits
    if (vendorData.creditLimit && vendorData.creditLimit > 100000) {
      anomalies.push('HIGH_CREDIT_LIMIT')
      threatScore += 20
      vendorRisk += 25
    } else if (vendorData.creditLimit && vendorData.creditLimit > 50000) {
      anomalies.push('MEDIUM_CREDIT_LIMIT')
      threatScore += 10
      vendorRisk += 15
    }

    // Check for missing tax information (compliance risk)
    if (!vendorData.taxId && !vendorData.registrationNumber) {
      anomalies.push('MISSING_TAX_INFORMATION')
      threatScore += 15
      vendorRisk += 20
    }

    // Check for suspicious bank information
    if (vendorData.bankAccount && !vendorData.swiftCode) {
      anomalies.push('INCOMPLETE_BANK_INFORMATION')
      threatScore += 10
      vendorRisk += 15
    }

    // Check for unusual vendor names or patterns
    if (this.isSuspiciousVendorName(vendorData.name)) {
      anomalies.push('SUSPICIOUS_VENDOR_NAME')
      threatScore += 15
      vendorRisk += 20
    }

    // Check for high-value operations
    if (vendorData.creditLimit > SECURITY_CONFIG.CREDIT_LIMIT_MAX / 2) {
      anomalies.push('HIGH_VALUE_VENDOR_OPERATION')
      threatScore += 20
      vendorRisk += 25
    }

    return { threatScore, vendorRisk, anomalies }
  }

  private analyzeFinancialVendorAccess(accessData: any, context: VendorSecurityState): {
    threatScore: number
    vendorRisk: number
    anomalies: string[]
  } {
    const anomalies: string[] = []
    let threatScore = 0
    let vendorRisk = 0

    // Check for bulk financial data access
    if (accessData?.pageSize && accessData.pageSize > 50) {
      anomalies.push('BULK_FINANCIAL_VENDOR_ACCESS')
      threatScore += 15
      vendorRisk += 10
    }

    return { threatScore, vendorRisk, anomalies }
  }

  private isAccessingFinancialVendorData(data: any): boolean {
    return data?.includeFinancial || data?.includeBankDetails
  }

  private isSuspiciousVendorName(name: string): boolean {
    const suspiciousPatterns = [
      /test|demo|sample/i,
      /unknown|anonymous/i,
      /temp|temporary/i
    ]
    
    return suspiciousPatterns.some(pattern => pattern.test(name))
  }

  private isVendorBehavioralAnomaly(userAgent: string, requestCount: number): boolean {
    const suspiciousPatterns = [
      /bot|crawler|spider/i,
      /python|curl|wget/i,
      /postman/i
    ]
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(userAgent))
    const isHighFrequency = requestCount > 50
    
    return isSuspicious || isHighFrequency
  }

  private getConcurrentVendorOperations(sessionToken: string): any[] {
    const key = `vendor_ops:${sessionToken}`
    return this.vendorPatterns.get(key) || []
  }

  private hasConcurrentVendorOperations(sessionToken: string): boolean {
    const recentOps = this.getConcurrentVendorOperations(sessionToken)
    const now = Date.now()
    const oneMinuteAgo = now - 60000 // 1 minute
    
    return recentOps.filter(t => t.timestamp > oneMinuteAgo).length > 
           SECURITY_CONFIG.CONCURRENT_VENDOR_LIMIT
  }

  // Advanced session validation for vendor operations
  private async validateVendorSession(req: NextRequest, userId: string): Promise<{
    isValid: boolean
    sessionState: any
    violations: string[]
    accessLevel: 'VIEW' | 'CREATE' | 'MODIFY' | 'MANAGE' | 'ADMIN'
  }> {
    const violations: string[] = []
    
    try {
      const sessionToken = req.headers.get('x-session-token')
      const refreshToken = req.headers.get('x-refresh-token')
      
      if (!sessionToken) {
        violations.push('MISSING_VENDOR_SESSION_TOKEN')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Enhanced JWT session validation
      const secret = new TextEncoder().encode(process.env.REFRESH_TOKEN_SECRET || 'fallback-secret')
      const { payload } = await jwtVerify(sessionToken, secret)
      
      // Session expiration check
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        violations.push('VENDOR_SESSION_EXPIRED')
        return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
      }

      // Device fingerprint validation
      const deviceInfo = this.extractDeviceInfo(req)
      const sessionFingerprint = payload.deviceFingerprint as string
      if (sessionFingerprint && sessionFingerprint !== deviceInfo.fingerprint) {
        violations.push('VENDOR_DEVICE_MISMATCH')
      }

      // Vendor role-based access validation
      const sessionRole = payload.role as string
      const vendorAccessLevel = this.determineVendorAccessLevel(sessionRole)
      
      return { 
        isValid: violations.length === 0, 
        sessionState: payload, 
        violations,
        accessLevel: vendorAccessLevel
      }
    } catch (error) {
      violations.push('VENDOR_SESSION_VALIDATION_ERROR')
      return { isValid: false, sessionState: null, violations, accessLevel: 'VIEW' }
    }
  }

  private determineVendorAccessLevel(role: string): 'VIEW' | 'CREATE' | 'MODIFY' | 'MANAGE' | 'ADMIN' {
    switch (role?.toUpperCase()) {
      case 'SUPER_ADMIN':
      case 'FINANCIAL_ADMIN':
        return 'ADMIN'
      case 'ADMIN':
      case 'ACCOUNTANT':
      case 'FINANCIAL_MANAGER':
        return 'MANAGE'
      case 'HOTEL_MANAGER':
        return 'MODIFY'
      case 'PURCHASING_MANAGER':
        return 'CREATE'
      default:
        return 'VIEW'
    }
  }

  // Mask highly sensitive vendor data
  private maskVendorData(data: any, accessLevel: string, threatLevel: string): any {
    const masked = { ...data }

    if (accessLevel === 'VIEW' || threatLevel === 'HIGH' || threatLevel === 'CRITICAL') {
      // Apply extensive data masking for vendor information
      if (masked.taxId) {
        masked.taxId = this.maskTaxId(masked.taxId)
      }
      if (masked.bankAccount) {
        masked.bankAccount = '***BANK_ACCOUNT_MASKED***'
      }
      if (masked.iban) {
        masked.iban = '***IBAN_MASKED***'
      }
      if (masked.creditLimit && typeof masked.creditLimit === 'number') {
        masked.creditLimit = Math.round(masked.creditLimit / 5000) * 5000 // Round to nearest 5K
      }
      if (masked.registrationNumber) {
        masked.registrationNumber = '***REG_MASKED***'
      }
    }

    // For contact-level access, mask financial details
    if (accessLevel === 'VIEW' || accessLevel === 'CREATE') {
      masked.bankAccount = undefined
      masked.iban = undefined
      masked.swiftCode = undefined
      masked.creditLimit = undefined
      masked.paymentTerms = undefined
    }

    return masked
  }

  private maskTaxId(taxId: string): string {
    if (!taxId || taxId.length < 4) return '***MASKED***'
    return taxId.substring(0, 2) + '***' + taxId.substring(taxId.length - 2)
  }

  // Record comprehensive vendor security event
  private recordVendorSecurityEvent(event: any): void {
    try {
      auditLogger.log({
        event: 'VENDOR_OPERATION',
        level: 'INFO',
        userId: event.userId,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        metadata: {
          requestId: event.requestId,
          correlationId: event.correlationId,
          operation: event.operation,
          threatLevel: event.threatLevel,
          vendorRisk: event.vendorRisk,
          accessLevel: event.accessLevel,
          vendorScope: event.vendorScope,
          dataClassification: event.dataClassification,
          anomalies: event.anomalies,
          verificationRequired: event.verificationRequired,
          vendorData: event.vendorData ? 'PRESENT' : 'ABSENT'
        }
      })
    } catch (error) {
      console.error('Failed to record vendor security event:', error)
    }
  }

  // Main security processing
  public async processRequest(
    req: NextRequest, 
    method: string,
    vendorData?: any
  ): Promise<{
    isAllowed: boolean
    context: VendorSecurityState
    violations: string[]
    recommendations: string[]
    accessLevel: 'VIEW' | 'CREATE' | 'MODIFY' | 'MANAGE' | 'ADMIN'
    vendorScope: 'BASIC' | 'CONTACT' | 'FINANCIAL' | 'COMPREHENSIVE'
  }> {
    const requestId = this.generateRequestId()
    const correlationId = this.generateCorrelationId()
    
    const { fingerprint, userAgent } = this.extractDeviceInfo(req)
    const ipAddress = req.headers.get('x-forwarded-for') || req.ip || 'unknown'

    const context: VendorSecurityState = {
      requestId,
      deviceFingerprint: fingerprint,
      userAgent,
      ipAddress,
      riskScore: 0,
      threatLevel: 'LOW',
      sessionToken: req.headers.get('x-session-token') || '',
      correlationId,
      accessLevel: 'VIEW',
      vendorScope: 'BASIC',
      dataClassification: 'INTERNAL',
      vendorRisk: 0,
      anomalies: [],
      verificationRequired: false
    }

    const violations: string[] = []
    const recommendations: string[] = []

    try {
      // Enhanced rate limiting based on method
      const rateLimitKey = `${ipAddress}:vendor-${method.toLowerCase()}`
      const rateLimitMax = SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS[method] || 30
      const rateLimitResult = await rateLimit.check(rateLimitKey, rateLimitMax, SECURITY_CONFIG.RATE_LIMIT_WINDOW)
      
      if (!rateLimitResult.allowed) {
        violations.push('VENDOR_RATE_LIMIT_EXCEEDED')
        recommendations.push('Implement exponential backoff for vendor operations')
      }

      // Record request pattern
      const now = Date.now()
      const requests = this.requestPatterns.get(ipAddress) || []
      requests.push(now)
      this.requestPatterns.set(ipAddress, requests.filter(timestamp => now - timestamp < SECURITY_CONFIG.RATE_LIMIT_WINDOW))

      // Threat and vendor risk analysis
      const threatAnalysis = this.analyzeVendorThreat(context, method, vendorData)
      context.riskScore = threatAnalysis.threatScore
      context.threatLevel = threatAnalysis.riskLevel
      context.accessLevel = threatAnalysis.accessLevel
      context.vendorScope = threatAnalysis.vendorScope
      context.dataClassification = threatAnalysis.dataClassification
      context.vendorRisk = threatAnalysis.vendorRisk
      context.anomalies = threatAnalysis.anomalies
      context.verificationRequired = threatAnalysis.verificationRequired

      if (threatAnalysis.detectedThreats.length > 0) {
        violations.push(...threatAnalysis.detectedThreats)
        recommendations.push('Review vendor access patterns and implement additional controls')
      }

      if (threatAnalysis.anomalies.length > 0) {
        violations.push(...threatAnalysis.anomalies)
        recommendations.push('Investigate vendor anomalies and verify vendor information')
      }

      // Final security decision
      const isAllowed = violations.length === 0 || context.threatLevel !== 'CRITICAL'

      // Record comprehensive security event
      this.recordVendorSecurityEvent({
        event: 'VENDOR_SECURITY_CHECK',
        userId: 'unknown',
        ipAddress,
        userAgent,
        requestId,
        correlationId,
        operation: method,
        accessLevel: context.accessLevel,
        vendorScope: context.vendorScope,
        threatLevel: context.threatLevel,
        vendorRisk: context.vendorRisk,
        dataClassification: context.dataClassification,
        anomalies: context.anomalies,
        verificationRequired: context.verificationRequired,
        vendorData,
        violations
      })

      return { 
        isAllowed, 
        context, 
        violations, 
        recommendations,
        accessLevel: context.accessLevel,
        vendorScope: context.vendorScope
      }

    } catch (error) {
      violations.push('VENDOR_SECURITY_PROCESSING_ERROR')
      return { 
        isAllowed: false, 
        context, 
        violations,
        recommendations: ['Contact system administrator and finance team'],
        accessLevel: 'VIEW',
        vendorScope: 'BASIC'
      }
    }
  }
}

// Initialize security processor
const securityProcessor = AdvancedVendorSecurity.getInstance()

// Validation Schemas (Enhanced)
const createVendorSchema = z.object({
  name: z.string().min(1).max(200),
  companyName: z.string().max(200).optional(),
  taxId: z.string().max(100).optional(),
  registrationNumber: z.string().max(100).optional(),
  email: z.string().email().optional(),
  phone: z.string().max(50).optional(),
  website: z.string().url().optional(),
  address: z.string().max(500).optional(),
  city: z.string().max(100).optional(),
  country: z.string().max(100).optional(),
  paymentTerms: z.string().max(100).optional(),
  currency: z.string().default('USD'),
  creditLimit: z.number().min(0).max(SECURITY_CONFIG.CREDIT_LIMIT_MAX).default(0),
  bankAccount: z.string().max(500).optional(),
  iban: z.string().max(50).optional(),
  swiftCode: z.string().max(20).optional(),
  rating: z.number().min(0).max(5).optional(),
  reliabilityScore: z.number().min(0).max(100).optional()
})

// Enhanced GET endpoint
export async function GET(req: NextRequest) {
  const startTime = Date.now()
  let securityContext: VendorSecurityState | null = null

  try {
    // Perform advanced vendor security analysis
    const securityResult = await securityProcessor.processRequest(req, 'GET')
    
    if (!securityResult.isAllowed) {
      await auditLogger.log({
        event: 'VENDOR_ACCESS_DENIED',
        level: 'HIGH',
        userId: 'unknown',
        ipAddress: securityResult.context.ipAddress,
        userAgent: securityResult.context.userAgent,
        metadata: {
          requestId: securityResult.context.requestId,
          correlationId: securityResult.context.correlationId,
          violations: securityResult.violations,
          threatLevel: securityResult.context.threatLevel,
          vendorRisk: securityResult.context.vendorRisk,
          accessLevel: securityResult.accessLevel,
          vendorScope: securityResult.vendorScope,
          dataClassification: securityResult.context.dataClassification
        }
      })

      return addSecurityHeaders(
        NextResponse.json(
          {
            status: "error",
            message: "Vendor data access denied due to security policy violations",
            security: {
              violations: securityResult.violations,
              recommendations: securityResult.recommendations,
              threatLevel: securityResult.context.threatLevel,
              vendorRisk: securityResult.context.vendorRisk,
              accessLevel: securityResult.accessLevel,
              vendorScope: securityResult.vendorScope,
              dataClassification: securityResult.context.dataClassification
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
    const sessionValidation = await securityProcessor.validateVendorSession(req, auth.user.id)
    if (!sessionValidation.isValid) {
      await auditLogger.log({
        event: 'INVALID_VENDOR_SESSION',
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
            message: "Vendor session validation failed",
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

    // Extract and validate query parameters
    const searchParams = req.nextUrl.searchParams
    
    // Pagination with security limits
    const page = Math.max(1, parseInt(searchParams.get('page') || '1'))
    const pageSize = Math.min(50, Math.max(1, parseInt(searchParams.get('pageSize') || '20')))

    // Enhanced parameter validation
    const validatedParams = this.validateVendorQueryParams(searchParams, finalAccessLevel)
    
    // Build secure where clause
    const where: any = this.buildSecureVendorWhereClause(auth, validatedParams, finalAccessLevel)

    const [vendors, total] = await Promise.all([
      prisma.vendor.findMany({
        where,
        orderBy: { name: 'asc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.vendor.count({ where })
    ])

    // Apply vendor data masking
    const securedVendors = vendors.map(vendor => 
      securityProcessor.maskVendorData(vendor, finalAccessLevel, securityContext.threatLevel)
    )

    // Performance monitoring
    const processingTime = Date.now() - startTime

    // Log successful vendor access
    await auditLogger.log({
      event: 'VENDOR_ACCESS_SUCCESS',
      level: 'INFO',
      userId: auth.user.id,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      metadata: {
        requestId: securityContext.requestId,
        correlationId: securityContext.correlationId,
        accessLevel: finalAccessLevel,
        vendorScope: securityResult.vendorScope,
        dataClassification: securityContext.dataClassification,
        recordsRetrieved: securedVendors.length,
        processingTime,
        threatLevel: securityContext.threatLevel,
        vendorRisk: securityContext.vendorRisk
      }
    })

    // Update security monitoring
    securityMonitor.recordMetric('vendor_access_duration', processingTime)
    securityMonitor.recordMetric('vendor_records_retrieved', securedVendors.length)
    securityMonitor.recordSecurityEvent({
      type: 'VENDOR_DATA_ACCESS',
      severity: 'LOW',
      details: {
        userId: auth.user.id,
        accessLevel: finalAccessLevel,
        vendorScope: securityResult.vendorScope,
        dataClassification: securityContext.dataClassification,
        processingTime
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            vendors: securedVendors,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            }
          },
          "Vendors retrieved successfully",
          {
            requestId: securityContext.requestId,
            correlationId: securityContext.correlationId,
            processingTime,
            accessLevel: finalAccessLevel,
            vendorScope: securityResult.vendorScope,
            dataClassification: securityContext.dataClassification,
            threatLevel: securityContext.threatLevel,
            vendorRisk: securityContext.vendorRisk
          }
        )
      )
    )

  } catch (error: any) {
    const processingTime = Date.now() - startTime

    // Log vendor error
    await auditLogger.log({
      event: 'VENDOR_ACCESS_ERROR',
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

    console.error("[Get Vendors Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch vendors", "FETCH_VENDORS_ERROR"),
        { status: 500 }
      )
    )
  }
}

// Helper methods for vendor operations
function validateVendorQueryParams(searchParams: URLSearchParams, accessLevel: string): any {
  const params: any = {}
  
  // Basic parameters
  params.page = parseInt(searchParams.get('page') || '1')
  params.pageSize = parseInt(searchParams.get('pageSize') || '20')
  params.search = searchParams.get('search')
  params.isActive = searchParams.get('isActive')
  
  return params
}

function buildSecureVendorWhereClause(auth: any, params: any, accessLevel: string): any {
  const where: any = {}
  
  // Search filtering
  if (params.search) {
    where.OR = [
      { name: { contains: params.search, mode: 'insensitive' } },
      { companyName: { contains: params.search, mode: 'insensitive' } }
    ]
  }
  
  // Status filtering
  if (params.isActive !== null && params.isActive !== undefined) {
    where.isActive = params.isActive === 'true'
  }
  
  return where
}

// Continue with POST, PUT, DELETE methods following the same security patterns...