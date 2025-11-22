import { NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import { payrollService } from "@/lib/services/payroll.service"
import { createHash, randomBytes, timingSafeEqual } from "crypto"
import jwt from "jsonwebtoken"
import { z } from "zod"

// ===========================================
// ADVANCED PAYROLL MANAGEMENT APIs
// إدارة الرواتب المتقدمة - نظام أمان شامل
// ===========================================

export const dynamic = 'force-dynamic'

// Enhanced Security Headers
const SECURITY_HEADERS = {
  'X-DNS-Prefetch-Control': 'off',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Payroll-Access': 'restricted'
}

// Request Correlation & Tracing
let requestCounter = 0
const generateRequestId = () => {
  requestCounter++
  const timestamp = Date.now()
  const random = randomBytes(8).toString('hex')
  return `payroll-${timestamp}-${requestCounter}-${random}`
}

// Advanced Financial Threat Detection
interface FinancialThreatAnalysis {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  threats: string[]
  confidence: number
  recommendedAction: string
  suspiciousIndicators: string[]
  financialRiskScore: number
}

class FinancialThreatDetector {
  private financialThreatPatterns = [
    { pattern: /salary|wage|payment|transfer|bank|account|ssn|tax|financial/i, weight: 40, type: 'FINANCIAL_DATA_ACCESS' },
    { pattern: /admin|root|system|privilege|elevate/i, weight: 50, type: 'PRIVILEGE_ESCALATION' },
    { pattern: /union\s+select|drop\s+table|delete\s+from|insert\s+into/i, weight: 60, type: 'SQL_INJECTION' },
    { pattern: /<script|javascript:|vbscript:|onload=|onerror=/i, weight: 45, type: 'XSS_ATTEMPT' },
    { pattern: /\.\.\/|\.\.\\/|%2e%2e%2f/i, weight: 35, type: 'PATH_TRAVERSAL' },
    { pattern: /eval\(|exec\(|system\(|shell_exec/i, weight: 55, type: 'CODE_INJECTION' },
    { pattern: /payroll|staff|employee|compensation|bonus/i, weight: 30, type: 'EMPLOYEE_DATA_ACCESS' }
  ]

  private accessPatterns = new Map<string, { count: number; lastRequest: Date; financialQueries: number; suspiciousPatterns: Set<string> }>()

  async analyzePayrollRequest(request: NextRequest, user: any, requestId: string): Promise<FinancialThreatAnalysis> {
    const userAgent = request.headers.get('user-agent') || ''
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const referer = request.headers.get('referer') || ''
    
    let riskScore = 0
    let financialRiskScore = 0
    const threats: string[] = []
    const suspiciousIndicators: string[] = []
    
    // Analyze access patterns specific to payroll
    const accessKey = `${user.id}-${ip}`
    const now = new Date()
    const accessPattern = this.accessPatterns.get(accessKey) || { 
      count: 0, 
      lastRequest: now, 
      financialQueries: 0,
      suspiciousPatterns: new Set()
    }
    
    accessPattern.count++
    accessPattern.lastRequest = now

    // Detect payroll data enumeration
    if (accessPattern.financialQueries > 50) {
      riskScore += 40
      financialRiskScore += 30
      threats.push('PAYROLL_DATA_ENUMERATION')
      suspiciousIndicators.push('Excessive payroll data access')
    }

    // Time-based financial access analysis
    const hour = now.getHours()
    if (hour < 6 || hour > 20) {
      riskScore += 20
      financialRiskScore += 15
      suspiciousIndicators.push('Payroll access outside business hours')
    }

    // Weekend access to sensitive financial data
    const dayOfWeek = now.getDay()
    if ((dayOfWeek === 0 || dayOfWeek === 6) && hour < 9 && hour > 17) {
      riskScore += 25
      financialRiskScore += 20
      threats.push('WEEKEND_FINANCIAL_ACCESS')
      suspiciousIndicators.push('Weekend payroll access')
    }

    // User agent analysis for payroll systems
    if (!userAgent || userAgent.length < 10) {
      riskScore += 20
      financialRiskScore += 15
      threats.push('SUSPICIOUS_USER_AGENT')
      suspiciousIndicators.push('Missing or invalid user agent for payroll access')
    }

    // Automated access detection
    const botPatterns = /bot|crawler|spider|scraper|curl|wget|python|java|go-http|libwww|nikto|nmap/i
    if (botPatterns.test(userAgent)) {
      riskScore += 50
      financialRiskScore += 40
      threats.push('AUTOMATED_PAYROLL_ACCESS')
      suspiciousIndicators.push('Automated bot accessing payroll system')
    }

    // Analyze referer for payroll system
    if (referer) {
      const refererUrl = new URL(referer)
      const isInternalReferer = refererUrl.hostname.includes('localhost') || 
                               refererUrl.hostname.includes('127.0.0.1') ||
                               refererUrl.hostname.includes(new URL(request.url).hostname)
      
      if (!isInternalReferer) {
        riskScore += 15
        financialRiskScore += 10
        threats.push('EXTERNAL_PAYROLL_ACCESS')
        suspiciousIndicators.push('External referer for payroll access')
      }
    }

    // Role-based risk assessment for payroll
    if (user.role !== 'HOTEL_MANAGER' && user.role !== 'ADMIN') {
      riskScore += 60
      financialRiskScore += 50
      threats.push('UNAUTHORIZED_ROLE_ACCESS')
      suspiciousIndicators.push('Insufficient role for payroll access')
    }

    // Analyze URL parameters for financial threats
    const url = new URL(request.url)
    for (const [key, value] of url.searchParams.entries()) {
      for (const threatPattern of this.financialThreatPatterns) {
        if (threatPattern.pattern.test(value)) {
          riskScore += threatPattern.weight
          if (threatPattern.type.includes('FINANCIAL') || threatPattern.type.includes('EMPLOYEE')) {
            financialRiskScore += threatPattern.weight * 0.8
          }
          threats.push(threatPattern.type)
          accessPattern.suspiciousPatterns.add(threatPattern.type)
          suspiciousIndicators.push(`Financial threat pattern detected in parameter: ${key}`)
        }
      }
    }

    // Check for sensitive parameter patterns
    const sensitiveParams = ['salary', 'wage', 'bonus', 'account', 'ssn', 'tax', 'bank']
    const hasSensitiveParams = sensitiveParams.some(param => 
      Array.from(url.searchParams.keys()).some(key => key.toLowerCase().includes(param))
    )
    
    if (hasSensitiveParams) {
      riskScore += 25
      financialRiskScore += 20
      threats.push('SENSITIVE_PARAMETERS')
      suspiciousIndicators.push('Request contains sensitive financial parameters')
    }

    // Update access pattern
    accessPattern.financialQueries++
    this.accessPatterns.set(accessKey, accessPattern)

    // Determine overall risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    let recommendedAction: string

    // Use the higher of general risk or financial risk
    const finalRiskScore = Math.max(riskScore, financialRiskScore)
    
    if (finalRiskScore >= 70) {
      riskLevel = 'CRITICAL'
      recommendedAction = 'BLOCK_REQUEST'
    } else if (finalRiskScore >= 50) {
      riskLevel = 'HIGH'
      recommendedAction = 'ENHANCED_MONITORING'
    } else if (finalRiskScore >= 25) {
      riskLevel = 'MEDIUM'
      recommendedAction = 'LOG_AND_CONTINUE'
    } else {
      riskLevel = 'LOW'
      recommendedAction = 'ALLOW_REQUEST'
    }

    return {
      riskLevel,
      threats,
      confidence: Math.min(finalRiskScore, 100),
      recommendedAction,
      suspiciousIndicators,
      financialRiskScore: finalRiskScore
    }
  }

  cleanupOldEntries() {
    const now = new Date()
    const timeout = 15 * 60 * 1000 // 15 minutes for financial data
    
    for (const [key, pattern] of this.accessPatterns.entries()) {
      if (now.getTime() - pattern.lastRequest.getTime() > timeout) {
        this.accessPatterns.delete(key)
      }
    }
  }
}

const financialThreatDetector = new FinancialThreatDetector()

// Enhanced Query Validation
const PayrollQuerySchema = z.object({
  hotelId: z.string().uuid().optional(),
  page: z.string().transform(Number).min(1).max(1000).default('1'),
  pageSize: z.string().transform(Number).min(1).max(100).default('10'),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
  filterBy: z.enum(['department', 'status', 'role']).optional(),
  filterValue: z.string().max(100).optional()
})

// Financial Data Masking
function maskFinancialData(data: any, context: string, userRole: string, userId: string): any {
  const maskValue = (value: string, visibleChars: number = 2): string => {
    if (!value || typeof value !== 'string') return value
    if (value.length <= visibleChars * 2) return '*'.repeat(value.length)
    return value.substring(0, visibleChars) + '*'.repeat(value.length - visibleChars * 2) + value.substring(value.length - visibleChars)
  }

  const maskAccountNumber = (value: string): string => {
    if (!value || typeof value !== 'string') return value
    if (value.length <= 4) return '*'.repeat(value.length)
    return '*'.repeat(value.length - 4) + value.substring(value.length - 4)
  }

  const applyFinancialMasking = (obj: any): any => {
    if (!obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(applyFinancialMasking)

    const masked = { ...obj }
    
    // Always mask sensitive financial data
    const sensitiveFields = [
      'salary', 'wage', 'bonus', 'accountNumber', 'bankAccount', 'ssn', 
      'taxId', 'iban', 'swift', 'routingNumber'
    ]
    
    for (const field of sensitiveFields) {
      if (masked[field] !== undefined) {
        if (typeof masked[field] === 'string') {
          if (field.includes('account') || field === 'iban') {
            masked[field] = maskAccountNumber(masked[field])
          } else {
            masked[field] = maskValue(masked[field], 1)
          }
        } else if (typeof masked[field] === 'number') {
          // Round salaries to nearest hundred for non-admin users
          if (userRole !== 'ADMIN' && field === 'salary') {
            masked[field] = Math.round(masked[field] / 100) * 100
          }
        }
      }
    }

    // Mask personal identifiers
    const personalFields = ['email', 'phone', 'address', 'emergencyContact']
    for (const field of personalFields) {
      if (masked[field]) {
        if (typeof masked[field] === 'string') {
          if (field === 'email') {
            masked[field] = maskValue(masked[field], 3)
          } else {
            masked[field] = maskValue(masked[field], 2)
          }
        }
      }
    }

    // Hotel Manager sees less detailed information
    if (userRole === 'HOTEL_MANAGER') {
      if (masked.employeeId) {
        masked.employeeId = maskValue(masked.employeeId, 4)
      }
      if (masked.employeeName) {
        masked.employeeName = maskValue(masked.employeeName, 1)
      }
    }

    return masked
  }

  return applyFinancialMasking(data)
}

// Comprehensive Payroll Audit Logging
async function logPayrollSecurityEvent(
  eventType: string,
  user: any,
  request: NextRequest,
  details: any,
  riskLevel: string,
  requestId: string,
  hotelId?: string
) {
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
  const userAgent = request.headers.get('user-agent') || 'unknown'
  const referer = request.headers.get('referer') || 'unknown'
  
  try {
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: `PAYROLL_${eventType}`,
        resource: 'PayrollManagement',
        resourceId: details.resourceId || null,
        ipAddress: ip,
        userAgent,
        method: 'GET',
        newValues: JSON.stringify({
          ...details,
          hotelId,
          financialAccess: true,
          complianceRequired: true
        }),
        metadata: {
          requestId,
          riskLevel,
          timestamp: new Date().toISOString(),
          referer,
          userRole: user.role,
          adminLevel: user.adminLevel,
          financialDataAccessed: true
        }
      }
    })

    // Log to security events table with financial context
    await prisma.securityEvent.create({
      data: {
        eventType: `PAYROLL_${eventType}`,
        severity: riskLevel === 'CRITICAL' ? 'high' : riskLevel === 'HIGH' ? 'medium' : 'low',
        description: `Payroll system access: ${eventType}`,
        ipAddress: ip,
        userId: user.id,
        metadata: {
          requestId,
          userRole: user.role,
          hotelId,
          details
        },
        resolved: riskLevel !== 'CRITICAL'
      }
    })
  } catch (error) {
    console.error('Failed to log payroll security event:', error)
  }
}

// Advanced Rate Limiting for Payroll
class PayrollRateLimiter {
  private buckets = new Map<string, { tokens: number; lastRefill: number; maxTokens: number; refillRate: number; financialOperations: number }>()

  constructor() {
    setInterval(() => this.cleanup(), 5 * 60 * 1000)
  }

  async checkLimit(key: string, maxTokens: number, refillRate: number, windowMs: number): Promise<{ success: boolean; remaining: number; resetTime: number; financialLimit?: boolean }> {
    const now = Date.now()
    const bucket = this.buckets.get(key) || { 
      tokens: maxTokens, 
      lastRefill: now, 
      maxTokens, 
      refillRate,
      financialOperations: 0
    }

    // Calculate tokens to add based on time passed
    const timePassed = now - bucket.lastRefill
    const tokensToAdd = (timePassed * bucket.refillRate) / windowMs
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd)
    bucket.lastRefill = now

    // Financial data access has stricter limits
    if (bucket.financialOperations >= 20) { // Max 20 financial data accesses per window
      return { 
        success: false, 
        remaining: 0, 
        resetTime: now + windowMs,
        financialLimit: true
      }
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1
      bucket.financialOperations++
      this.buckets.set(key, bucket)
      
      return { 
        success: true, 
        remaining: Math.floor(bucket.tokens), 
        resetTime: now + (windowMs / bucket.refillRate) 
      }
    }

    return { 
      success: false, 
      remaining: 0, 
      resetTime: bucket.lastRefill + (windowMs / bucket.refillRate),
      financialLimit: false
    }
  }

  private cleanup() {
    const now = Date.now()
    const timeout = 30 * 60 * 1000 // 30 minutes
    
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > timeout) {
        this.buckets.delete(key)
      }
    }
  }
}

const payrollRateLimiter = new PayrollRateLimiter()

// Enhanced Token Verification with Financial Context
function verifyFinancialToken(token: string): any {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any
    
    // Enhanced role validation for financial operations
    if (decoded.role !== 'HOTEL_MANAGER' && decoded.role !== 'ADMIN') {
      throw new Error('Insufficient role for payroll access')
    }
    
    return {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      adminLevel: decoded.adminLevel,
      hotelId: decoded.hotelId,
      permissions: decoded.permissions || []
    }
  } catch (error) {
    throw new Error('Invalid or expired token')
  }
}

// ===========================================
// GET - جلب بيانات الرواتب (Advanced Security)
// ===========================================
export async function GET(req: NextRequest) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  
  console.log(`[${requestId}] Payroll GET request initiated`)

  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    
    if (!token) {
      console.log(`[${requestId}] No authorization token provided`)
      return apiResponse.unauthorized("Authorization token required")
    }

    const user = verifyFinancialToken(token)
    console.log(`[${requestId}] User authenticated: ${user.email} (${user.role})`)

    // AI Financial Threat Analysis
    const threatAnalysis = await financialThreatDetector.analyzePayrollRequest(req, user, requestId)
    console.log(`[${requestId}] Financial threat analysis: ${threatAnalysis.riskLevel} risk`)

    // Log security event
    await logPayrollSecurityEvent('PAYROLL_ACCESS', user, req, {
      requestId,
      queryParams: Object.fromEntries(req.nextUrl.searchParams.entries())
    }, threatAnalysis.riskLevel, requestId)

    if (threatAnalysis.riskLevel === 'CRITICAL') {
      await logPayrollSecurityEvent('CRITICAL_FINANCIAL_THREAT_BLOCKED', user, req, {
        requestId,
        threats: threatAnalysis.threats,
        indicators: threatAnalysis.suspiciousIndicators,
        financialScore: threatAnalysis.financialRiskScore
      }, 'CRITICAL', requestId)
      
      return apiResponse.error("Payroll access blocked due to security concerns")
    }

    // Advanced Rate Limiting for Financial Data
    const rateLimitKey = `payroll:${user.id}`
    const rateLimitResult = await payrollRateLimiter.checkLimit(rateLimitKey, 25, 25, 60000) // 25 requests per minute for payroll
    
    if (!rateLimitResult.success) {
      console.log(`[${requestId}] Rate limit exceeded for payroll access`)
      return apiResponse.error(
        rateLimitResult.financialLimit 
          ? "Financial data access limit exceeded. Please try again later." 
          : "Rate limit exceeded. Too many payroll requests."
      )
    }

    // Enhanced query validation
    const searchParams = req.nextUrl.searchParams
    const queryData = PayrollQuerySchema.parse({
      hotelId: searchParams.get("hotelId") || undefined,
      page: searchParams.get("page") || "1",
      pageSize: searchParams.get("pageSize") || "10",
      sortBy: searchParams.get("sortBy") || undefined,
      sortOrder: searchParams.get("sortOrder") || "desc",
      filterBy: searchParams.get("filterBy") || undefined,
      filterValue: searchParams.get("filterValue") || undefined
    })

    console.log(`[${requestId}] Validated query parameters: ${JSON.stringify(queryData)}`)

    // Enhanced hotel validation for financial access
    let hotelId = queryData.hotelId
    
    if (!hotelId && user.role === 'HOTEL_MANAGER') {
      // Get hotel managed by user
      hotelId = req.nextUrl.searchParams.get("hotelId")
    }

    if (!hotelId) {
      console.log(`[${requestId}] Hotel ID required for payroll access`)
      return apiResponse.badRequest("Hotel ID required for payroll access")
    }

    // Verify hotel access permissions
    if (user.role === 'HOTEL_MANAGER') {
      // Verify the user manages this hotel
      const hotel = await prisma.hotel.findFirst({
        where: { 
          id: hotelId, 
          managerId: user.id 
        },
        select: { id: true, name: true }
      })

      if (!hotel) {
        console.log(`[${requestId}] Insufficient permissions for hotel ${hotelId}`)
        return apiResponse.forbidden("You can only access payroll data for hotels you manage")
      }
    }

    // Enhanced pagination
    const skip = (queryData.page - 1) * queryData.pageSize

    // Get payroll data with enhanced filtering
    const payrollData = await payrollService.getHotelPayroll(hotelId, skip, queryData.pageSize)

    // Apply financial data masking based on user role
    const maskedPayrollData = payrollData.payroll.map((record: any) =>
      maskFinancialData(record, 'payroll', user.role, user.id)
    )

    // Performance monitoring
    const executionTime = Date.now() - startTime
    const performanceScore = executionTime > 3000 ? 'slow' : executionTime > 800 ? 'medium' : 'fast'
    
    // Enhanced statistics calculation
    const totalRecords = payrollData.total || maskedPayrollData.length
    const pageInfo = {
      page: queryData.page,
      pageSize: queryData.pageSize,
      total: totalRecords,
      hasMore: (queryData.page * queryData.pageSize) < totalRecords
    }

    const response = {
      payroll: maskedPayrollData,
      ...pageInfo,
      performance: {
        executionTime,
        performanceScore,
        requestId,
        threatLevel: threatAnalysis.riskLevel,
        financialRiskScore: threatAnalysis.financialRiskScore
      },
      security: {
        dataMasked: true,
        userRole: user.role,
        accessLevel: user.role === 'ADMIN' ? 'COMPREHENSIVE' : 'BASIC',
        complianceMode: true
      }
    }

    console.log(`[${requestId}] Payroll data retrieved successfully in ${executionTime}ms`)

    // Log successful access
    if (threatAnalysis.riskLevel === 'HIGH') {
      await logPayrollSecurityEvent('HIGH_RISK_PAYROLL_SUCCESS', user, req, {
        requestId,
        hotelId,
        recordsAccessed: maskedPayrollData.length,
        threatLevel: threatAnalysis.riskLevel,
        executionTime
      }, 'MEDIUM', requestId, hotelId)
    }

    return NextResponse.json(
      apiResponse.success(response, "Payroll data retrieved successfully"),
      {
        status: 200,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Threat-Level': threatAnalysis.riskLevel,
          'X-Financial-Risk-Score': threatAnalysis.financialRiskScore.toString(),
          'X-Performance-Score': performanceScore,
          'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
          'X-Data-Masked': 'true',
          'X-Payroll-Access-Level': user.role === 'ADMIN' ? 'COMPREHENSIVE' : 'BASIC'
        }
      }
    )

  } catch (error: any) {
    const executionTime = Date.now() - startTime
    console.error(`[${requestId}] Error in GET payroll:`, error)
    
    // Log error with enhanced context
    try {
      const token = req.headers.get("Authorization")?.split(" ")[1]
      const user = token ? verifyFinancialToken(token) : null
      
      if (user) {
        await logPayrollSecurityEvent('PAYROLL_ERROR', user, req, {
          requestId,
          error: error.message,
          executionTime,
          stack: error.stack
        }, 'MEDIUM', requestId)
      }
    } catch (authError) {
      console.error(`[${requestId}] Failed to authenticate user for error logging:`, authError)
    }

    return NextResponse.json(
      apiResponse.error(error.message || "Failed to retrieve payroll data"),
      {
        status: 500,
        headers: {
          ...SECURITY_HEADERS,
          'X-Request-ID': requestId,
          'X-Response-Time': executionTime.toString(),
          'X-Error-Type': 'INTERNAL_SERVER_ERROR'
        }
      }
    )
  } finally {
    financialThreatDetector.cleanupOldEntries()
  }
}