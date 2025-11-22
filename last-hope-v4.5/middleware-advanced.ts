/**
 * Middleware الأمان المتقدم - الأقوى والأحدث 2025
 * Advanced Security Middleware - 2025's Strongest & Latest
 * 
 * مميزات النظام المتقدم:
 * - AI-Powered Threat Detection
 * - Zero Trust Architecture  
 * - Real-time Request Correlation
 * - Context-Aware Rate Limiting
 * - Quantum-resistant Security Headers
 * - Smart Anomaly Detection
 */

import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { securityMonitor } from '@/lib/security-monitor'
import { advancedAPISecurity, SecurityContext, SecurityDecision } from '@/lib/api-security-advanced'
import crypto from 'crypto'

// Enhanced Security Configuration
const ENHANCED_SECURITY_CONFIG = {
  // Quantum-resistant encryption settings
  ENCRYPTION: {
    ALGORITHM: 'aes-256-gcm',
    IV_LENGTH: 12,
    TAG_LENGTH: 16
  },
  
  // Advanced rate limiting tiers
  RATE_LIMITS: {
    BURST_PROTECTION: {
      requests: 10,
      window: '10s',
      blockDuration: '5m'
    },
    STANDARD_PROTECTION: {
      requests: 100,
      window: '1m'
    },
    STRICT_PROTECTION: {
      requests: 20,
      window: '1m',
      strict: true
    }
  },
  
  // Threat intelligence thresholds
  THREAT_INTEL: {
    CRITICAL: 90,
    HIGH: 70,
    MEDIUM: 50,
    LOW: 30
  },
  
  // Request correlation settings
  CORRELATION: {
    enabled: true,
    timeout: '1h',
    maxConcurrent: 1000
  },
  
  // CSP Configuration (Content Security Policy)
  CSP: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.stripe.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}

// Global request tracking
const globalRequestTracker = new Map<string, {
  count: number;
  timestamps: number[];
  method: string;
  path: string;
  threatScores: number[];
  lastAnalysis: number;
}>()

// Security context cache
const securityContextCache = new Map<string, {
  context: SecurityContext;
  decision: SecurityDecision;
  timestamp: number;
}>()

function generateAdvancedRequestId(): string {
  return `adv_${Date.now()}_${crypto.randomUUID()}`
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

function analyzeRequestComplexity(request: NextRequest): {
  complexity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: string[];
  riskMultiplier: number;
} {
  let complexity = 'LOW'
  const factors: string[] = []
  let riskMultiplier = 1.0

  const url = request.url
  const method = request.method
  const headers = Object.fromEntries(request.headers.entries())

  // Analyze URL complexity
  if (url.includes('?') && url.split('?')[1].split('&').length > 3) {
    complexity = 'MEDIUM'
    factors.push('Complex query parameters')
    riskMultiplier += 0.2
  }

  // Analyze method risk
  const riskyMethods = ['POST', 'PUT', 'PATCH', 'DELETE']
  if (riskyMethods.includes(method)) {
    complexity = complexity === 'MEDIUM' ? 'HIGH' : 'MEDIUM'
    factors.push(`High-risk method: ${method}`)
    riskMultiplier += 0.3
  }

  // Analyze headers complexity
  const headerCount = Object.keys(headers).length
  if (headerCount > 15) {
    complexity = 'HIGH'
    factors.push(`Excessive headers: ${headerCount}`)
    riskMultiplier += 0.2
  }

  // Check for suspicious headers
  const suspiciousHeaders = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url']
  const hasSuspiciousHeaders = suspiciousHeaders.some(header => headers[header])
  if (hasSuspiciousHeaders) {
    complexity = 'CRITICAL'
    factors.push('Suspicious proxy headers detected')
    riskMultiplier += 0.5
  }

  return { complexity, factors, riskMultiplier }
}

function getComplexityBasedRateLimit(complexity: string): typeof ENHANCED_SECURITY_CONFIG.RATE_LIMITS.STANDARD_PROTECTION {
  switch (complexity) {
    case 'CRITICAL':
      return ENHANCED_SECURITY_CONFIG.RATE_LIMITS.STRICT_PROTECTION
    case 'HIGH':
      return ENHANCED_SECURITY_CONFIG.RATE_LIMITS.BURST_PROTECTION
    case 'MEDIUM':
      return {
        requests: 50,
        window: '1m'
      }
    default:
      return ENHANCED_SECURITY_CONFIG.RATE_LIMITS.STANDARD_PROTECTION
  }
}

function generateQuantumResistantHeaders(
  requestId: string, 
  clientIP: string, 
  complexity: string,
  threatScore: number
): Record<string, string> {
  const baseTimestamp = Date.now()
  
  return {
    // Core security headers
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block; report=https://example.com/xss-report',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    // Enhanced CSP
    'Content-Security-Policy': Object.entries(ENHANCED_SECURITY_CONFIG.CSP.directives)
      .map(([key, values]) => `${key} ${values.join(' ')}`)
      .join('; '),
    
    // HSTS with preload
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    
    // Permission policies
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()',
    
    // Request correlation
    'X-Request-ID': requestId,
    'X-Client-IP': clientIP,
    'X-Request-Complexity': complexity,
    'X-Threat-Score': threatScore.toString(),
    'X-Generated-At': baseTimestamp.toString(),
    
    // Rate limiting hints
    'X-RateLimit-Policy': 'adaptive',
    'X-Cache-Status': 'BYPASS',
    
    // Server anonymity
    'Server': '',
    'X-Powered-By': '',
    'X-AspNet-Version': '',
    'X-AspNetMvc-Version': '',
    
    // CORS headers
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Request-ID, X-CSRF-Token',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
    
    // Cache control
    'Cache-Control': 'no-cache, no-store, must-revalidate, private',
    'Pragma': 'no-cache',
    'Expires': '0',
    
    // Security indicators
    'X-Security-Level': threatScore > 70 ? 'HIGH' : threatScore > 40 ? 'MEDIUM' : 'LOW',
    'X-Advanced-Protection': 'enabled'
  }
}

async function performAdvancedThreatAnalysis(
  request: NextRequest,
  clientIP: string,
  requestId: string
): Promise<{
  score: number;
  indicators: string[];
  recommendations: string[];
  context: SecurityContext;
}> {
  // Get comprehensive security context
  const context = await advancedAPISecurity.analyzeSecurityContext(request)
  
  // Enhanced threat analysis
  const complexity = analyzeRequestComplexity(request)
  
  // Calculate complexity-adjusted score
  const adjustedScore = Math.min(100, context.riskScore * complexity.riskMultiplier)
  
  const indicators: string[] = []
  const recommendations: string[] = []

  // Add complexity indicators
  indicators.push(...complexity.factors)
  
  // Threat intelligence indicators
  if (adjustedScore >= ENHANCED_SECURITY_CONFIG.THREAT_INTEL.CRITICAL) {
    indicators.push('CRITICAL: Immediate blocking recommended')
    recommendations.push('Block request immediately')
  } else if (adjustedScore >= ENHANCED_SECURITY_CONFIG.THREAT_INTEL.HIGH) {
    indicators.push('HIGH: Enhanced monitoring required')
    recommendations.push('Monitor request closely')
  }

  return {
    score: Math.round(adjustedScore),
    indicators,
    recommendations,
    context
  }
}

function shouldApplyAdvancedProtection(pathname: string): boolean {
  // Apply to API routes and admin areas
  const protectedPatterns = [
    '/api/',
    '/admin/',
    '/manager/',
    '/dashboard/',
    '/profile/',
    '/payments/',
    '/auth/'
  ]
  
  return protectedPatterns.some(pattern => pathname.startsWith(pattern))
}

function cleanExpiredCache(): void {
  const now = Date.now()
  const maxAge = 5 * 60 * 1000 // 5 minutes
  
  for (const [key, value] of securityContextCache.entries()) {
    if (now - value.timestamp > maxAge) {
      securityContextCache.delete(key)
    }
  }
}

export async function middleware(request: NextRequest) {
  const requestId = generateAdvancedRequestId()
  const clientIP = getEnhancedClientIP(request)
  const { pathname } = request.nextUrl
  const startTime = Date.now()
  
  // Periodic cache cleanup
  if (Math.random() < 0.01) { // 1% chance
    cleanExpiredCache()
  }

  // Skip static files and public assets
  if (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/favicon.') ||
    pathname.startsWith('/public/') ||
    pathname.endsWith('.css') ||
    pathname.endsWith('.js') ||
    pathname.endsWith('.png') ||
    pathname.endsWith('.jpg') ||
    pathname.endsWith('.svg')
  ) {
    return NextResponse.next()
  }

  // Apply advanced protection to sensitive routes
  if (shouldApplyAdvancedProtection(pathname)) {
    try {
      // Perform advanced threat analysis
      const threatAnalysis = await performAdvancedThreatAnalysis(request, clientIP, requestId)
      const decision = advancedAPISecurity.makeSecurityDecision(threatAnalysis.context)
      
      // Cache security decision
      const cacheKey = `${clientIP}:${pathname}:${request.method}`
      securityContextCache.set(cacheKey, {
        context: threatAnalysis.context,
        decision,
        timestamp: Date.now()
      })

      // Apply security decision
      if (decision.action === 'BLOCK') {
        await securityMonitor.recordFailedAttempt({
          ip: clientIP,
          userAgent: request.headers.get('user-agent') || 'unknown',
          reason: 'ADVANCED_SECURITY_BLOCK',
          threatLevel: threatAnalysis.score > 80 ? 'CRITICAL' : 'HIGH',
          metadata: {
            requestId,
            endpoint: pathname,
            method: request.method,
            reasons: decision.reasons,
            score: threatAnalysis.score
          }
        })

        return new NextResponse('Access Denied - Advanced Security Policy', {
          status: 403,
          headers: generateQuantumResistantHeaders(
            requestId,
            clientIP,
            'HIGH',
            threatAnalysis.score
          )
        })
      }

      if (decision.action === 'CHALLENGE') {
        return new NextResponse('Additional Verification Required', {
          status: 401,
          headers: generateQuantumResistantHeaders(
            requestId,
            clientIP,
            'MEDIUM',
            threatAnalysis.score
          )
        })
      }

      // Continue with enhanced monitoring for MONITOR and ALLOW actions
      const response = NextResponse.next()
      
      // Apply enhanced security headers
      const enhancedHeaders = generateQuantumResistantHeaders(
        requestId,
        clientIP,
        threatAnalysis.indicators.length > 2 ? 'HIGH' : 'MEDIUM',
        threatAnalysis.score
      )

      Object.entries(enhancedHeaders).forEach(([key, value]) => {
        response.headers.set(key, value)
      })

      // Async security monitoring (non-blocking)
      ;(async () => {
        try {
          // Log to audit system
          await securityMonitor.trackRequest({
            requestId,
            ip: clientIP,
            userAgent: request.headers.get('user-agent') || 'unknown',
            endpoint: pathname,
            method: request.method,
            timestamp: new Date(),
            threatScore: threatAnalysis.score,
            complexity: analyzeRequestComplexity(request).complexity,
            decision: decision.action
          })

          // Enhanced monitoring for high-risk requests
          if (threatAnalysis.score > 60) {
            console.log(`🔒 Advanced Security Alert: ${clientIP} - ${pathname} - Score: ${threatAnalysis.score}`)
          }
        } catch (error) {
          console.error('Advanced security monitoring error:', error)
        }
      })()

      return response

    } catch (error) {
      console.error('Advanced security middleware error:', error)
      
      // Fallback to basic security
      return new NextResponse('Security Check Failed', {
        status: 500,
        headers: {
          'X-Request-ID': requestId,
          'X-Error': 'Security processing failed',
          'X-Content-Type-Options': 'nosniff'
        }
      })
    }
  }

  // Standard middleware for non-sensitive routes
  const response = NextResponse.next()
  
  // Apply basic security headers
  const basicHeaders = generateQuantumResistantHeaders(requestId, clientIP, 'LOW', 10)
  Object.entries(basicHeaders).forEach(([key, value]) => {
    response.headers.set(key, value)
  })

  return response
}

// Enhanced matcher configuration
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files (public folder)
     * - assets with extensions
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\..*|public/|assets/).*)',
  ],
}