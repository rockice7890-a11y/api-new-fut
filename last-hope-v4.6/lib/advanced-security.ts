/**
 * Advanced Security Module for Next.js 16
 * Enhanced security implementation following OWASP 2025 guidelines
 */

import { NextRequest, NextResponse } from "next/server"
import { createHash, randomBytes } from "crypto"
import { z } from "zod"
import helmet from "helmet"
import rateLimit from "express-rate-limit"

// Security schemas
const SecurityConfigSchema = z.object({
  maxRequests: z.number().min(10).max(1000),
  windowMs: z.number().min(60000).max(86400000),
  skipSuccessfulRequests: z.boolean(),
  keyGenerator: z.function()
})

const IPValidationSchema = z.object({
  ip: z.string().ip(),
  allowList: z.array(z.string()).optional(),
  blockList: z.array(z.string()).optional()
})

export interface SecurityHeaders {
  'X-Content-Type-Options': string
  'X-Frame-Options': string
  'X-XSS-Protection': string
  'Referrer-Policy': string
  'Strict-Transport-Security': string
  'Permissions-Policy': string
  'Content-Security-Policy': string
  'Cross-Origin-Embedder-Policy': string
  'Cross-Origin-Opener-Policy': string
  'Cross-Origin-Resource-Policy': string
}

export interface SecurityConfig {
  rateLimit: {
    windowMs: number
    max: number
    message: string
    standardHeaders: boolean
    legacyHeaders: boolean
  }
  cors: {
    origin: string | string[] | boolean
    credentials: boolean
    optionsSuccessStatus: number
  }
  headers: Partial<SecurityHeaders>
  csrf: {
    cookie: {
      httpOnly: boolean
      secure: boolean
      sameSite: 'strict' | 'lax' | 'none'
    }
  }
}

class AdvancedSecurityManager {
  private config: SecurityConfig
  private blockedIPs: Set<string> = new Set()
  private suspiciousActivity: Map<string, number> = new Map()

  constructor(config?: Partial<SecurityConfig>) {
    this.config = {
      rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: "Too many requests from this IP, please try again later",
        standardHeaders: true,
        legacyHeaders: false
      },
      cors: {
        origin: process.env.NODE_ENV === 'production' 
          ? process.env.ALLOWED_ORIGINS?.split(',') || false
          : true,
        credentials: true,
        optionsSuccessStatus: 200
      },
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-site'
      },
      csrf: {
        cookie: {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict'
        }
      },
      ...config
    }

    this.initializeSecurity()
  }

  private initializeSecurity() {
    // Set up enhanced CSP
    this.config.headers['Content-Security-Policy'] = this.generateCSP()
    
    // Initialize IP blocking system
    this.loadBlockedIPs()
    
    // Set up security monitoring
    this.startSecurityMonitoring()
  }

  private generateCSP(): string {
    const directives = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://apis.google.com https://www.googletagmanager.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https: blob:",
      "media-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
      "block-all-mixed-content"
    ]

    return directives.join('; ')
  }

  /**
   * Enhanced input sanitization with OWASP 2025 compliance
   */
  static sanitizeInput(input: string, options?: {
    maxLength?: number
    allowHTML?: boolean
    allowedTags?: string[]
  }): string {
    if (typeof input !== 'string') {
      return ''
    }

    const maxLength = options?.maxLength || 10000
    let sanitized = input.substring(0, maxLength)

    // Remove potentially dangerous characters
    sanitized = sanitized
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .replace(/data:/gi, '')
      .replace(/vbscript:/gi, '')
      .replace(/expression\s*\(/gi, '')
      .replace(/url\s*\(/gi, '')

    if (!options?.allowHTML) {
      // Remove all HTML tags if not allowed
      sanitized = sanitized.replace(/<[^>]*>/g, '')
    } else if (options.allowedTags) {
      // Remove tags not in allowlist
      const tagPattern = /<\/?([a-z][a-z0-9]*)\b[^>]*>/gi
      sanitized = sanitized.replace(tagPattern, (match, tag) => {
        return options.allowedTags!.includes(tag.toLowerCase()) ? match : ''
      })
    }

    return sanitized.trim()
  }

  /**
   * Generate cryptographically secure tokens
   */
  static generateSecureToken(length: number = 32): string {
    return randomBytes(length).toString('hex')
  }

  /**
   * Hash sensitive data with salt
   */
  static hashWithSalt(data: string, salt?: string): { hash: string; salt: string } {
    const usedSalt = salt || randomBytes(32).toString('hex')
    const hash = createHash('sha256').update(data + usedSalt).digest('hex')
    return { hash, salt: usedSalt }
  }

  /**
   * Validate IP address against allow/block lists
   */
  static validateIP(ip: string, config: {
    allowList?: string[]
    blockList?: string[]
  }): { valid: boolean; reason?: string } {
    const { allowList = [], blockList = [] } = config

    // Check block list first
    if (blockList.some(pattern => this.matchesIPPattern(ip, pattern))) {
      return { valid: false, reason: 'IP blocked by policy' }
    }

    // Check allow list (if exists)
    if (allowList.length > 0 && !allowList.some(pattern => this.matchesIPPattern(ip, pattern))) {
      return { valid: false, reason: 'IP not in allowed list' }
    }

    return { valid: true }
  }

  private static matchesIPPattern(ip: string, pattern: string): boolean {
    if (pattern.includes('/')) {
      // CIDR notation
      const [range, bits] = pattern.split('/')
      const ipNum = this.ipToLong(ip)
      const rangeNum = this.ipToLong(range)
      const mask = -1 << (32 - parseInt(bits))
      return (ipNum & mask) === (rangeNum & mask)
    } else if (pattern.includes('*')) {
      // Wildcard notation (e.g., 192.168.1.*)
      const regex = new RegExp(pattern.replace(/\*/g, '(\\d{1,3})'))
      return regex.test(ip)
    } else {
      // Exact match
      return ip === pattern
    }
  }

  private static ipToLong(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0
  }

  /**
   * Detect suspicious activity patterns
   */
  detectSuspiciousActivity(ip: string, userAgent: string, endpoint: string): {
    suspicious: boolean
    score: number
    reasons: string[]
  } {
    let score = 0
    const reasons: string[] = []

    // Check for automated user agents
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i
    ]

    if (botPatterns.some(pattern => pattern.test(userAgent))) {
      score += 20
      reasons.push('Automated user agent detected')
    }

    // Check for rapid requests to different endpoints
    const key = `${ip}-${Date.now() - (Date.now() % 60000)}` // Minute-based key
    const recentRequests = this.suspiciousActivity.get(key) || 0
    
    if (recentRequests > 50) {
      score += 30
      reasons.push('High request frequency detected')
    }

    // Check for suspicious patterns in endpoint access
    const sensitiveEndpoints = [
      '/api/admin', '/api/auth', '/api/users', '/api/permissions'
    ]

    if (sensitiveEndpoints.some(endpoint => endpoint.includes(endpoint))) {
      score += 15
      reasons.push('Access to sensitive endpoint')
    }

    // Check for unusual request methods
    const suspiciousMethods = ['TRACE', 'CONNECT', 'PROPFIND']
    if (suspiciousMethods.some(method => endpoint.includes(method))) {
      score += 25
      reasons.push('Suspicious HTTP method')
    }

    const suspicious = score >= 30
    this.suspiciousActivity.set(key, recentRequests + 1)

    if (suspicious) {
      this.blockedIPs.add(ip)
      this.scheduleUnblock(ip)
    }

    return { suspicious, score, reasons }
  }

  private scheduleUnblock(ip: string, delay: number = 300000): void { // 5 minutes
    setTimeout(() => {
      this.blockedIPs.delete(ip)
    }, delay)
  }

  private loadBlockedIPs(): void {
    // In production, load from database
    const blockedIPs = process.env.BLOCKED_IPS?.split(',') || []
    blockedIPs.forEach(ip => this.blockedIPs.add(ip))
  }

  private startSecurityMonitoring(): void {
    // Clean up old suspicious activity data
    setInterval(() => {
      const now = Date.now()
      for (const [key] of this.suspiciousActivity) {
        const keyTime = parseInt(key.split('-')[1])
        if (now - keyTime > 3600000) { // 1 hour
          this.suspiciousActivity.delete(key)
        }
      }
    }, 300000) // Every 5 minutes
  }

  /**
   * Apply comprehensive security headers to response
   */
  applySecurityHeaders(response: NextResponse, additionalHeaders?: Partial<SecurityHeaders>): NextResponse {
    const headers = { ...this.config.headers, ...additionalHeaders }

    for (const [key, value] of Object.entries(headers)) {
      response.headers.set(key, value)
    }

    return response
  }

  /**
   * Check if IP is blocked
   */
  isIPBlocked(ip: string): boolean {
    return this.blockedIPs.has(ip)
  }

  /**
   * Get security configuration
   */
  getConfig(): SecurityConfig {
    return { ...this.config }
  }

  /**
   * Update security configuration
   */
  updateConfig(newConfig: Partial<SecurityConfig>): void {
    this.config = { ...this.config, ...newConfig }
    this.initializeSecurity()
  }
}

// Export singleton instance
export const securityManager = new AdvancedSecurityManager()

// Utility functions
export const SecurityUtils = {
  sanitizeInput: AdvancedSecurityManager.sanitizeInput,
  generateSecureToken: AdvancedSecurityManager.generateSecureToken,
  hashWithSalt: AdvancedSecurityManager.hashWithSalt,
  validateIP: AdvancedSecurityManager.validateIP
}

// Security middleware for Next.js
export function withAdvancedSecurity(handler: Function) {
  return async (req: NextRequest, res: NextResponse) => {
    try {
      const ip = req.headers.get('x-forwarded-for')?.split(',')[0] || 
                 req.headers.get('x-real-ip') || 
                 req.ip || 
                 'unknown'

      const userAgent = req.headers.get('user-agent') || 'unknown'
      const endpoint = new URL(req.url).pathname

      // Check if IP is blocked
      if (securityManager.isIPBlocked(ip)) {
        return NextResponse.json({
          error: 'IP address blocked',
          code: 'IP_BLOCKED'
        }, { status: 403 })
      }

      // Detect suspicious activity
      const suspicion = securityManager.detectSuspiciousActivity(ip, userAgent, endpoint)
      
      if (suspicion.suspicious) {
        console.warn(`Suspicious activity detected from ${ip}:`, suspicion.reasons)
        
        // Log security event (in production, send to SIEM)
        // await securityLogger.log({
        //   type: 'SUSPICIOUS_ACTIVITY',
        //   ip,
        //   userAgent,
        //   endpoint,
        //   score: suspicion.score,
        //   reasons: suspicion.reasons
        // })

        return NextResponse.json({
          error: 'Request blocked due to suspicious activity',
          code: 'SUSPICIOUS_ACTIVITY',
          score: suspicion.score
        }, { status: 429 })
      }

      // Apply security headers
      const response = await handler(req, res)
      return securityManager.applySecurityHeaders(response)

    } catch (error) {
      console.error('Security middleware error:', error)
      return NextResponse.json({
        error: 'Security check failed',
        code: 'SECURITY_ERROR'
      }, { status: 500 })
    }
  }
}

// Export security schemas for validation
export { SecurityConfigSchema, IPValidationSchema }