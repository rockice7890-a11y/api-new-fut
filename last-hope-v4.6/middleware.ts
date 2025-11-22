import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { securityMonitor } from '@/lib/security-monitor'
import { advancedAPISecurity, SecurityContext, SecurityDecision } from '@/lib/api-security-advanced'
// Edge Runtime provides crypto global

// Enhanced Security Configuration with Advanced Protection
const SECURITY_CONFIG = {
  maxRequestSize: '10mb',
  allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  blockedPaths: [
    '/.env',
    '/.git',
    '/admin',
    '/wp-admin',
    '/phpmyadmin',
    '/server-status',
    '/.well-known/security.txt',
    '/api/admin/setup',
    '/api/database',
    '/api/config',
    '/api/backup',
    '/api/logs'
  ],
  advancedProtection: {
    enabled: true,
    threatThreshold: 70,
    autoBlock: true,
    smartRateLimit: true,
    contextAware: true
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100, // per IP
    burstLimit: 20, // per minute
    // Advanced rate limiting tiers
    tiers: {
      CRITICAL: { requests: 5, window: '1m' },    // Admin/Auth endpoints
      HIGH: { requests: 20, window: '1m' },       // Payments/Bookings
      MEDIUM: { requests: 50, window: '1m' },     // Search/Hotels
      LOW: { requests: 100, window: '1m' }        // General
    }
  }
}

// Enhanced Request tracking with context awareness
const requestTracking = new Map<string, { 
  count: number; 
  resetTime: number; 
  tier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  requests: number[];
  lastRequest: number;
}>()

// Security context cache for performance
const securityContextCache = new Map<string, {
  context: SecurityContext;
  decision: SecurityDecision;
  timestamp: number;
  expires: number;
}>()

function generateAdvancedRequestId(): string {
  return `adv_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`
}

function getEnhancedClientIP(request: NextRequest): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    request.ip ||
    request.headers.get('cf-connecting-ip') || // Cloudflare
    request.headers.get('x-client-ip') ||
    'unknown'
  )
}

function isBlockedPath(pathname: string): boolean {
  return SECURITY_CONFIG.blockedPaths.some(blocked => 
    pathname.toLowerCase().includes(blocked.toLowerCase())
  )
}

function getSecurityHeaders(additionalHeaders: Record<string, string> = {}): Record<string, string> {
  const baseHeaders = {
    // Core security headers
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block; report=https://example.com/xss-report',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    // Enhanced Permissions Policy
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=()',
    
    // Advanced HSTS for production
    ...(process.env.NODE_ENV === 'production' && {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload; upgrade-insecure-requests'
    }),
    
    // Enhanced CSP
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://js.stripe.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
      "img-src 'self' data: https: blob:",
      "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
      "connect-src 'self' https://api.stripe.com https://*.vercel.app",
      "frame-src 'self' https://js.stripe.com",
      "object-src 'none'",
      "media-src 'self'",
      "worker-src 'self'",
      "child-src 'self'"
    ].join('; '),
    
    // Cache control with security
    'Cache-Control': 'no-cache, no-store, must-revalidate, private, max-age=0',
    'Pragma': 'no-cache',
    'Expires': '0',
    
    // Enhanced CORS
    'Access-Control-Allow-Origin': SECURITY_CONFIG.allowedOrigins[0] || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
    'Access-Control-Allow-Headers': [
      'Content-Type',
      'Authorization', 
      'X-Requested-With',
      'X-Request-ID',
      'X-CSRF-Token',
      'X-Client-IP',
      'User-Agent'
    ].join(', '),
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Expose-Headers': 'X-Request-ID, X-Threat-Level, X-Processing-Time',
    
    // Security information hiding
    'X-Powered-By': '', 
    'Server': '',
    'X-AspNet-Version': '',
    'X-AspNetMvc-Version': '',
    'X-Generator': '',
    
    // Advanced security features
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Resource-Policy': 'same-site',
    
    // Feature policy
    'Feature-Policy': 'geolocation "none"; camera "none"; microphone "none"; payment "none"',
    
    // Expect-CT header
    ...(process.env.NODE_ENV === 'production' && {
      'Expect-CT': 'max-age=86400, enforce'
    }),
    
    // Hide technology stack
    'X-Download-Options': 'noopen',
    'X-Permitted-Cross-Domain-Policies': 'none'
  }
  
  return { ...baseHeaders, ...additionalHeaders }
}

function rateLimitCheck(
  ip: string, 
  tier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
  config: { requests: number; window: string }
): { allowed: boolean; remaining: number; resetTime: number; limit: number } {
  const now = Date.now()
  const key = `rate_limit:${tier}:${ip}`
  
  const current = requestTracking.get(key) || { 
    count: 0, 
    resetTime: now + parseTimeWindow(config.window), 
    tier,
    requests: [],
    lastRequest: now
  }
  
  // Parse time window
  const windowMs = parseTimeWindow(config.window)
  
  // Reset if window expired
  if (now > current.resetTime) {
    current.count = 0
    current.requests = []
    current.resetTime = now + windowMs
    current.tier = tier
  }
  
  // Clean old requests for velocity analysis
  current.requests = current.requests.filter(time => now - time < windowMs)
  current.count = current.requests.length
  
  const remaining = Math.max(0, config.requests - current.count)
  const allowed = remaining > 0
  
  // Update request tracking
  current.requests.push(now)
  current.count += 1
  current.lastRequest = now
  requestTracking.set(key, current)
  
  return {
    allowed,
    remaining,
    resetTime: current.resetTime,
    limit: config.requests
  }
}

function parseTimeWindow(window: string): number {
  const match = window.match(/^(\d+)([smhd])$/)
  if (!match) return 60000 // Default: 1 minute
  
  const value = parseInt(match[1])
  const unit = match[2]
  
  const multipliers = { s: 1000, m: 60000, h: 3600000, d: 86400000 }
  return value * multipliers[unit as keyof typeof multipliers]
}

function validateRequestSize(request: NextRequest): { valid: boolean; error?: string } {
  const contentLength = request.headers.get('content-length')
  if (!contentLength) return { valid: true }
  
  const sizeInBytes = parseInt(contentLength, 10)
  const maxSizeBytes = parseInt(SECURITY_CONFIG.maxRequestSize, 10)
  
  if (sizeInBytes > maxSizeBytes) {
    return {
      valid: false,
      error: `Request size (${sizeInBytes} bytes) exceeds maximum allowed size (${maxSizeBytes} bytes)`
    }
  }
  
  return { valid: true }
}

function determineThreatLevel(pathname: string, method: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  // Critical endpoints (admin, auth, payments)
  const criticalPatterns = ['/admin/', '/api/auth/', '/api/payments/', '/api/accounting/']
  if (criticalPatterns.some(pattern => pathname.startsWith(pattern))) {
    return 'CRITICAL'
  }
  
  // High-risk endpoints
  const highPatterns = ['/api/bookings/', '/api/users/', '/api/hotels/']
  if (highPatterns.some(pattern => pathname.startsWith(pattern))) {
    return 'HIGH'
  }
  
  // Medium-risk endpoints
  const mediumPatterns = ['/api/search/', '/api/rooms/', '/api/reviews/']
  if (mediumPatterns.some(pattern => pathname.startsWith(pattern))) {
    return 'MEDIUM'
  }
  
  return 'LOW'
}

function getSmartRateLimit(tier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): typeof SECURITY_CONFIG.rateLimit.tiers.LOW {
  return SECURITY_CONFIG.rateLimit.tiers[tier] || SECURITY_CONFIG.rateLimit.tiers.LOW
}

function performAdvancedThreatAnalysis(request: NextRequest, clientIP: string): {
  score: number
  reasons: string[]
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  indicators: string[]
} {
  let score = 0
  const reasons: string[] = []
  const indicators: string[] = []
  
  const userAgent = request.headers.get('user-agent') || ''
  const method = request.method
  const pathname = request.nextUrl.pathname
  
  // Enhanced missing User-Agent check
  if (!userAgent || userAgent.trim() === '') {
    score += 25
    reasons.push('Missing User-Agent')
    indicators.push('SUSPICIOUS: No user agent provided')
  }
  
  // Advanced User-Agent analysis
  const threatPatterns = [
    { pattern: /sqlmap/i, score: 80, name: 'SQLMap scanner' },
    { pattern: /nikto/i, score: 75, name: 'Nikto scanner' },
    { pattern: /nmap/i, score: 70, name: 'Nmap scanner' },
    { pattern: /masscan/i, score: 85, name: 'Masscan scanner' },
    { pattern: /python-requests/i, score: 30, name: 'Python requests' },
    { pattern: /curl/i, score: 25, name: 'cURL tool' },
    { pattern: /wget/i, score: 25, name: 'Wget tool' },
    { pattern: /bot|crawler|spider/i, score: 20, name: 'Bot detection' }
  ]
  
  threatPatterns.forEach(({ pattern, score: patternScore, name }) => {
    if (pattern.test(userAgent)) {
      score += patternScore
      reasons.push(`Threat tool detected: ${name}`)
      indicators.push(`DANGER: ${name}`)
    }
  })
  
  // Advanced method analysis
  const dangerousMethods = ['TRACE', 'CONNECT', 'PROPFIND', 'SEARCH', 'TRACK']
  if (dangerousMethods.includes(method.toUpperCase())) {
    score += 30
    reasons.push(`Dangerous HTTP method: ${method}`)
    indicators.push('WARNING: Unusual method')
  }
  
  // Enhanced path traversal detection
  const pathTraversalPatterns = [
    /\.\.\//,
    /%2e%2e\//i,
    /%252e%252e%252f/i, // Double encoded
    /\.\.%5c/i, // Windows path traversal
  ]
  
  if (pathTraversalPatterns.some(pattern => pattern.test(pathname))) {
    score += 40
    reasons.push('Path traversal attempt detected')
    indicators.push('CRITICAL: Path traversal')
  }
  
  // Advanced SQL injection detection
  const advancedSQLPatterns = [
    /(\bunion\b.*\bselect\b)/gi,
    /(\bor\s+1=1\b)/gi,
    /(\bdrop\s+table\b)/gi,
    /(\binsert\s+into\b.*\bvalues\b)/gi,
    /(\bupdate\b.*\bset\b)/gi,
    /(\bdelete\s+from\b)/gi,
    /(;--|\bxp_cmdshell\b|\bsp_executesql\b)/gi,
    /(\bbenchmark\s*\()/gi,
    /(\bsleep\s*\()/gi
  ]
  
  const url = request.nextUrl.toString()
  if (advancedSQLPatterns.some(pattern => pattern.test(url))) {
    score += 50
    reasons.push('Advanced SQL injection pattern detected')
    indicators.push('CRITICAL: SQL injection attempt')
  }
  
  // Advanced XSS detection
  const advancedXSSPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /onerror\s*=/gi,
    /onload\s*=/gi,
    /onclick\s*=/gi,
    /onmouseover\s*=/gi,
    /eval\s*\(/gi,
    /expression\s*\(/gi,
    /<iframe[^>]*>/gi,
    /<object[^>]*>/gi,
    /<embed[^>]*>/gi
  ]
  
  if (advancedXSSPatterns.some(pattern => pattern.test(url))) {
    score += 35
    reasons.push('Advanced XSS pattern detected')
    indicators.push('HIGH: XSS attempt')
  }
  
  // Request velocity analysis
  const ipKey = `velocity:${clientIP}`
  const currentRequests = requestTracking.get(ipKey)
  const now = Date.now()
  
  if (currentRequests) {
    const recentRequests = currentRequests.requests.filter(time => now - time < 60000)
    if (recentRequests.length > 10) {
      score += 20
      reasons.push(`High request velocity: ${recentRequests.length}/min`)
      indicators.push('WARNING: Velocity attack')
    }
  }
  
  // Determine overall level
  let level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW'
  if (score >= 80) level = 'CRITICAL'
  else if (score >= 60) level = 'HIGH'
  else if (score >= 40) level = 'MEDIUM'
  
  return {
    suspicious: score > 50,
    score: Math.min(score, 100),
    reasons,
    level,
    indicators
  }
}

export async function middleware(request: NextRequest) {
  const requestId = generateAdvancedRequestId()
  const clientIP = getEnhancedClientIP(request)
  const { pathname } = request.nextUrl
  const startTime = Date.now()
  const tier = determineThreatLevel(pathname, request.method)
  
  // Block suspicious paths
  if (isBlockedPath(pathname)) {
    await securityMonitor.recordFailedAttempt({
      ip: clientIP,
      userAgent: request.headers.get('user-agent') || 'unknown',
      reason: 'BLOCKED_PATH_ACCESS',
      threatLevel: 'CRITICAL',
      metadata: { requestId, pathname }
    })
    
    return new NextResponse('Forbidden - Blocked Path', {
      status: 403,
      headers: getSecurityHeaders({
        'X-Request-ID': requestId,
        'X-Blocked-Reason': 'Suspicious path access',
        'X-Threat-Level': 'CRITICAL',
        'X-Advanced-Protection': 'enabled'
      })
    })
  }
  
  // Advanced rate limiting with tier-based limits
  const rateLimitConfig = getSmartRateLimit(tier)
  const rateLimitResult = rateLimitCheck(clientIP, tier, rateLimitConfig)
  if (!rateLimitResult.allowed) {
    await securityMonitor.recordFailedAttempt({
      ip: clientIP,
      userAgent: request.headers.get('user-agent') || 'unknown',
      reason: 'TIER_BASED_RATE_LIMIT',
      threatLevel: tier === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
      metadata: { 
        requestId, 
        tier, 
        limit: rateLimitConfig.requests,
        window: rateLimitConfig.window 
      }
    })
    
    return new NextResponse('Too Many Requests - Advanced Protection', {
      status: 429,
      headers: {
        ...getSecurityHeaders({
          'X-Request-ID': requestId,
          'X-Threat-Level': tier,
          'X-RateLimit-Limit': rateLimitConfig.requests.toString(),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': Math.ceil(rateLimitResult.resetTime / 1000).toString(),
          'X-Advanced-Rate-Limit': 'enabled',
          'Retry-After': '900'
        })
      }
    })
  }
  
  // Request size validation
  const sizeValidation = validateRequestSize(request)
  if (!sizeValidation.valid) {
    return new NextResponse('Payload Too Large', {
      status: 413,
      headers: getSecurityHeaders({
        'X-Request-ID': requestId,
        'X-Error': sizeValidation.error || 'Request too large',
        'X-Threat-Level': 'MEDIUM'
      })
    })
  }
  
  // Advanced suspicious activity analysis
  const suspicionAnalysis = performAdvancedThreatAnalysis(request, clientIP)
  if (suspicionAnalysis.suspicious) {
    await securityMonitor.recordFailedAttempt({
      ip: clientIP,
      userAgent: request.headers.get('user-agent') || 'unknown',
      reason: 'ADVANCED_SUSPICIOUS_PATTERN',
      threatLevel: suspicionAnalysis.score > 80 ? 'CRITICAL' : 'HIGH',
      metadata: { 
        requestId, 
        score: suspicionAnalysis.score,
        reasons: suspicionAnalysis.reasons,
        indicators: suspicionAnalysis.indicators
      }
    })
    
    return new NextResponse('Forbidden - Advanced Threat Detection', {
      status: 403,
      headers: getSecurityHeaders({
        'X-Request-ID': requestId,
        'X-Advanced-Threat-Score': suspicionAnalysis.score.toString(),
        'X-Threat-Indicators': suspicionAnalysis.indicators.join('; '),
        'X-Threat-Level': suspicionAnalysis.level,
        'X-Advanced-Protection': 'enabled'
      })
    })
  }
  
  // Handle preflight requests with enhanced CORS
  if (request.method === 'OPTIONS') {
    return new NextResponse(null, {
      status: 200,
      headers: getSecurityHeaders({
        'X-Request-ID': requestId,
        'X-Advanced-CORS': 'enabled'
      })
    })
  }
  
  // Apply advanced security headers
  const response = NextResponse.next()
  
  const enhancedSecurityHeaders = getSecurityHeaders({
    'X-Request-ID': requestId,
    'X-Client-IP': clientIP,
    'X-Processing-Time': `${Date.now() - startTime}ms`,
    'X-Threat-Level': tier,
    'X-Advanced-Protection': 'enabled',
    'X-Request-Tier': tier.toLowerCase(),
    'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
    'X-Security-Enhanced': '2025'
  })
  
  Object.entries(enhancedSecurityHeaders).forEach(([key, value]) => {
    response.headers.set(key, value)
  })
  
  // Enhanced async monitoring (async, non-blocking)
  ;(async () => {
    try {
      // Perform comprehensive threat analysis
      if (SECURITY_CONFIG.advancedProtection.enabled) {
        const threatContext = await advancedAPISecurity.analyzeSecurityContext(request)
        const decision = advancedAPISecurity.makeSecurityDecision(threatContext)
        
        // Cache security context for performance
        const cacheKey = `${clientIP}:${pathname}:${request.method}`
        securityContextCache.set(cacheKey, {
          context: threatContext,
          decision,
          timestamp: Date.now(),
          expires: Date.now() + (5 * 60 * 1000) // 5 minutes
        })
        
        // Log high-risk activities
        if (decision.riskScore >= SECURITY_CONFIG.advancedProtection.threatThreshold) {
          console.log(`🚨 Advanced Security Alert [${tier}]: ${clientIP} - ${pathname} - Score: ${decision.riskScore} - ${decision.reasons.join(', ')}`)
          
          // Record additional audit event
          if (decision.action === 'BLOCK') {
            await securityMonitor.recordFailedAttempt({
              ip: clientIP,
              userAgent: request.headers.get('user-agent') || 'unknown',
              reason: 'ADVANCED_SECURITY_BLOCK',
              threatLevel: decision.riskScore > 80 ? 'CRITICAL' : 'HIGH',
              metadata: {
                requestId,
                decision,
                context: threatContext
              }
            })
          }
        }
      }
      
      // Standard security monitoring
      const standardThreatScore = await securityMonitor.analyzeThreat({
        ip: clientIP,
        userAgent: request.headers.get('user-agent') || 'unknown',
        requestId,
        path: pathname,
        method: request.method
      })
      
      // Log based on threat level
      if (standardThreatScore > 60) {
        console.log(`Security monitoring: ${clientIP} - ${pathname} - Threat score: ${standardThreatScore}`)
      }
      
    } catch (error) {
      console.error('Advanced security monitoring error:', error)
    }
  })()
  
  return response
}

// Configure which paths to run middleware on
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files (public folder)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\..*|public/).*)',
  ],
}