/**
 * Advanced Security Monitoring and Alerting System
 * Real-time security monitoring and automated threat detection
 */

import { PrismaClient } from "@prisma/client"
import { createHash } from "crypto"
import { NextRequest } from "next/server"

const prisma = new PrismaClient()

export interface SecurityEvent {
  type: 'LOGIN_SUCCESS' | 'LOGIN_FAILURE' | 'PERMISSION_DENIED' | 'SUSPICIOUS_ACTIVITY' | 'DATA_EXPORT' | 'CONFIG_CHANGE'
  userId?: string
  ipAddress: string
  userAgent: string
  endpoint: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  details: Record<string, any>
  timestamp: Date
}

export interface ThreatPattern {
  id: string
  name: string
  pattern: RegExp
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  action: 'BLOCK' | 'ALERT' | 'LOG' | 'RATE_LIMIT'
  description: string
}

export interface SecurityAlert {
  id: string
  type: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  title: string
  description: string
  userId?: string
  ipAddress: string
  resolved: boolean
  createdAt: Date
  resolvedAt?: Date
  resolvedBy?: string
}

class AdvancedSecurityMonitor {
  private threatPatterns: ThreatPattern[] = []
  private ipReputation: Map<string, { score: number; lastSeen: Date; events: number }> = new Map()
  private sessionTracking: Map<string, { userId: string; ipAddress: string; startTime: Date; lastActivity: Date }> = new Map()
  private alertCallbacks: Array<(alert: SecurityAlert) => void> = []

  constructor() {
    this.initializeThreatPatterns()
    this.startMonitoring()
  }

  private initializeThreatPatterns() {
    this.threatPatterns = [
      {
        id: 'sql-injection',
        name: 'SQL Injection Attempt',
        pattern: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)/gi,
        severity: 'HIGH',
        action: 'BLOCK',
        description: 'Potential SQL injection attack detected'
      },
      {
        id: 'xss-attempt',
        name: 'Cross-Site Scripting Attempt',
        pattern: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        severity: 'HIGH',
        action: 'BLOCK',
        description: 'Potential XSS attack detected'
      },
      {
        id: 'path-traversal',
        name: 'Path Traversal Attempt',
        pattern: /\.\.[\/\\]/g,
        severity: 'MEDIUM',
        action: 'ALERT',
        description: 'Potential directory traversal attack'
      },
      {
        id: 'command-injection',
        name: 'Command Injection Attempt',
        pattern: /[;&|`$()]/g,
        severity: 'HIGH',
        action: 'BLOCK',
        description: 'Potential command injection attack'
      },
      {
        id: 'brute-force',
        name: 'Brute Force Attack',
        pattern: /\/api\/auth\/login/gi,
        severity: 'HIGH',
        action: 'RATE_LIMIT',
        description: 'Multiple failed login attempts detected'
      }
    ]
  }

  /**
   * Monitor security event in real-time
   */
  async monitorEvent(event: SecurityEvent): Promise<boolean> {
    try {
      // Check against threat patterns
      for (const pattern of this.threatPatterns) {
        if (pattern.pattern.test(JSON.stringify(event.details))) {
          await this.handleThreatDetection(pattern, event)
          if (pattern.action === 'BLOCK') {
            return false // Block the request
          }
        }
      }

      // Update IP reputation
      this.updateIPReputation(event.ipAddress, event)

      // Track session activity
      this.trackSessionActivity(event)

      // Log the event
      await this.logSecurityEvent(event)

      // Check for automated alerts
      await this.checkForAlerts(event)

      return true

    } catch (error) {
      console.error('Security monitoring error:', error)
      return true // Allow request on monitoring error
    }
  }

  private async handleThreatDetection(pattern: ThreatPattern, event: SecurityEvent): Promise<void> {
    console.warn(`🚨 Threat detected: ${pattern.name}`, {
      pattern: pattern.id,
      event: event.endpoint,
      ip: event.ipAddress,
      severity: pattern.severity
    })

    // Create security alert
    await this.createAlert({
      type: pattern.id,
      severity: pattern.severity,
      title: pattern.name,
      description: `${pattern.description} from ${event.ipAddress}`,
      userId: event.userId,
      ipAddress: event.ipAddress,
      resolved: false
    })

    // Execute action based on pattern
    switch (pattern.action) {
      case 'BLOCK':
        await this.blockIP(event.ipAddress, pattern.id)
        break
      case 'RATE_LIMIT':
        await this.applyRateLimit(event.ipAddress, pattern.id)
        break
      case 'ALERT':
        await this.sendImmediateAlert(pattern, event)
        break
      case 'LOG':
        // Just log (already done above)
        break
    }
  }

  private updateIPReputation(ipAddress: string, event: SecurityEvent): void {
    const current = this.ipReputation.get(ipAddress) || { 
      score: 0, 
      lastSeen: new Date(), 
      events: 0 
    }

    let scoreChange = 0

    // Adjust score based on event type
    switch (event.type) {
      case 'LOGIN_FAILURE':
        scoreChange += 10
        break
      case 'PERMISSION_DENIED':
        scoreChange += 5
        break
      case 'SUSPICIOUS_ACTIVITY':
        scoreChange += 25
        break
      case 'LOGIN_SUCCESS':
        scoreChange -= 2 // Good behavior
        break
    }

    // Adjust for severity
    switch (event.severity) {
      case 'CRITICAL':
        scoreChange += 50
        break
      case 'HIGH':
        scoreChange += 20
        break
      case 'MEDIUM':
        scoreChange += 10
        break
      case 'LOW':
        scoreChange += 5
        break
    }

    // Update reputation
    const newScore = Math.max(0, Math.min(100, current.score + scoreChange))
    
    this.ipReputation.set(ipAddress, {
      score: newScore,
      lastSeen: new Date(),
      events: current.events + 1
    })

    // If reputation score is too high, create alert
    if (newScore >= 80) {
      this.createAlert({
        type: 'HIGH_REPUTATION_IP',
        severity: newScore >= 90 ? 'CRITICAL' : 'HIGH',
        title: 'High Risk IP Address',
        description: `IP ${ipAddress} has reputation score of ${newScore}/100`,
        ipAddress,
        resolved: false
      })
    }
  }

  private trackSessionActivity(event: SecurityEvent): void {
    if (!event.userId) return

    const sessionKey = `${event.userId}-${event.ipAddress}`
    const session = this.sessionTracking.get(sessionKey)

    if (session) {
      session.lastActivity = new Date()
    } else {
      this.sessionTracking.set(sessionKey, {
        userId: event.userId,
        ipAddress: event.ipAddress,
        startTime: new Date(),
        lastActivity: new Date()
      })
    }
  }

  private async logSecurityEvent(event: SecurityEvent): Promise<void> {
    try {
      // Store in database for audit trail
      await prisma.auditLog.create({
        data: {
          userId: event.userId || 'system',
          action: event.type,
          resource: event.endpoint,
          oldValues: null,
          newValues: JSON.stringify(event.details),
          success: event.severity !== 'CRITICAL',
          ipAddress: event.ipAddress,
          userAgent: event.userAgent,
          endpoint: event.endpoint,
          method: 'SECURITY_MONITOR'
        }
      })

      // Also log to system logs for real-time monitoring
      console.log(`🔍 Security Event: ${event.type}`, {
        userId: event.userId,
        ip: event.ipAddress,
        severity: event.severity,
        endpoint: event.endpoint
      })

    } catch (error) {
      console.error('Failed to log security event:', error)
    }
  }

  private async createAlert(alertData: Omit<SecurityAlert, 'id' | 'createdAt'>): Promise<void> {
    try {
      const alert = await prisma.auditLog.create({
        data: {
          userId: alertData.userId || 'system',
          action: 'SECURITY_ALERT',
          resource: alertData.type,
          newValues: JSON.stringify(alertData),
          success: false,
          ipAddress: alertData.ipAddress,
          endpoint: 'security-monitor',
          method: 'ALERT'
        }
      })

      console.log(`🚨 Security Alert Created: ${alertData.title}`)
      
      // Notify registered callbacks
      this.alertCallbacks.forEach(callback => {
        callback({
          ...alertData,
          id: alert.id,
          createdAt: new Date()
        })
      })

    } catch (error) {
      console.error('Failed to create security alert:', error)
    }
  }

  private async checkForAlerts(event: SecurityEvent): Promise<void> {
    // Check for unusual activity patterns
    const ipData = this.ipReputation.get(event.ipAddress)
    
    if (ipData && ipData.events > 100) {
      await this.createAlert({
        type: 'HIGH_ACTIVITY_VOLUME',
        severity: 'MEDIUM',
        title: 'High Activity Volume',
        description: `IP ${event.ipAddress} has ${ipData.events} events`,
        ipAddress: event.ipAddress,
        resolved: false
      })
    }

    // Check for rapid login attempts
    if (event.type === 'LOGIN_FAILURE') {
      const recentFailures = this.getRecentLoginFailures(event.ipAddress)
      if (recentFailures >= 5) {
        await this.createAlert({
          type: 'BRUTE_FORCE_ATTACK',
          severity: 'HIGH',
          title: 'Brute Force Attack Detected',
          description: `${recentFailures} failed login attempts from ${event.ipAddress}`,
          ipAddress: event.ipAddress,
          resolved: false
        })
      }
    }

    // Check for unusual user agent patterns
    if (this.isSuspiciousUserAgent(event.userAgent)) {
      await this.createAlert({
        type: 'SUSPICIOUS_USER_AGENT',
        severity: 'MEDIUM',
        title: 'Suspicious User Agent',
        description: `Unusual user agent detected: ${event.userAgent}`,
        userId: event.userId,
        ipAddress: event.ipAddress,
        resolved: false
      })
    }
  }

  private async blockIP(ipAddress: string, reason: string): Promise<void> {
    // In production, this would update a blocklist in the database or firewall
    console.log(`🚫 Blocking IP: ${ipAddress} for: ${reason}`)
    
    await this.createAlert({
      type: 'IP_BLOCKED',
      severity: 'HIGH',
      title: 'IP Address Blocked',
      description: `IP ${ipAddress} blocked for: ${reason}`,
      ipAddress,
      resolved: false
    })
  }

  private async applyRateLimit(ipAddress: string, reason: string): Promise<void> {
    console.log(`⏱️ Rate limiting IP: ${ipAddress} for: ${reason}`)
    
    // In production, this would integrate with rate limiting middleware
  }

  private async sendImmediateAlert(pattern: ThreatPattern, event: SecurityEvent): Promise<void> {
    // In production, this would send immediate notifications (email, SMS, Slack, etc.)
    console.log(`🚨 IMMEDIATE ALERT: ${pattern.name} from ${event.ipAddress}`)
  }

  private getRecentLoginFailures(ipAddress: string): number {
    // In production, this would query recent failed login attempts
    return Math.floor(Math.random() * 10) // Mock implementation
  }

  private isSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i,
      /libwww-perl/i, /w3c_validator/i
    ]

    return suspiciousPatterns.some(pattern => pattern.test(userAgent)) && 
           !userAgent.includes('Mozilla') // Legitimate browsers usually include Mozilla
  }

  private startMonitoring(): void {
    // Clean up old session tracking data
    setInterval(() => {
      const now = new Date()
      for (const [key, session] of this.sessionTracking) {
        const inactiveTime = now.getTime() - session.lastActivity.getTime()
        if (inactiveTime > 3600000) { // 1 hour
          this.sessionTracking.delete(key)
        }
      }
    }, 300000) // Every 5 minutes

    // Clean up old IP reputation data
    setInterval(() => {
      const now = new Date()
      for (const [ip, data] of this.ipReputation) {
        const inactiveTime = now.getTime() - data.lastSeen.getTime()
        if (inactiveTime > 86400000 && data.score < 20) { // 24 hours, low score
          this.ipReputation.delete(ip)
        }
      }
    }, 3600000) // Every hour
  }

  /**
   * Register alert callback
   */
  registerAlertCallback(callback: (alert: SecurityAlert) => void): void {
    this.alertCallbacks.push(callback)
  }

  /**
   * Get IP reputation score
   */
  getIPReputation(ipAddress: string): number {
    return this.ipReputation.get(ipAddress)?.score || 0
  }

  /**
   * Check if IP is blocked
   */
  isIPBlocked(ipAddress: string): boolean {
    return this.getIPReputation(ipAddress) >= 90
  }

  /**
   * Get active sessions
   */
  getActiveSessions(): Array<{ userId: string; ipAddress: string; startTime: Date; lastActivity: Date }> {
    return Array.from(this.sessionTracking.values())
  }

  /**
   * Get security statistics
   */
  getSecurityStats(): {
    totalEvents: number
    blockedIPs: number
    activeAlerts: number
    suspiciousActivities: number
  } {
    return {
      totalEvents: Array.from(this.ipReputation.values()).reduce((acc, data) => acc + data.events, 0),
      blockedIPs: Array.from(this.ipReputation.values()).filter(data => data.score >= 90).length,
      activeAlerts: 0, // Would query database in production
      suspiciousActivities: Array.from(this.ipReputation.values()).filter(data => data.score >= 60).length
    }
  }

  /**
   * Advanced threat analysis for login attempts
   */
  async analyzeThreat(threatData: {
    ip: string
    userAgent: string
    requestId: string
    path: string
    method: string
  }): Promise<number> {
    let threatScore = 0

    // IP reputation analysis
    const ipData = this.ipReputation.get(threatData.ip)
    if (ipData) {
      threatScore += ipData.score * 0.3
    }

    // User agent analysis
    const suspiciousUserAgents = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /requests/i
    ]
    
    if (suspiciousUserAgents.some(pattern => pattern.test(threatData.userAgent))) {
      threatScore += 20
    }

    // Request pattern analysis
    if (threatData.method === 'POST' && threatData.path.includes('/login')) {
      threatScore += 10 // Baseline for login attempts
    }

    // Velocity checks (rapid requests)
    const recentEvents = this.getRecentEvents(threatData.ip, 5 * 60 * 1000) // Last 5 minutes
    if (recentEvents.length > 10) {
      threatScore += 30
    }

    // Geo-location risk (simplified - in production would use GeoIP)
    const privateIPs = [
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./
    ]
    
    if (privateIPs.some(pattern => pattern.test(threatData.ip))) {
      threatScore -= 10 // Lower risk for private IPs
    }

    // Time-based analysis
    const hour = new Date().getHours()
    if (hour >= 2 && hour <= 6) {
      threatScore += 15 // Higher risk during night hours
    }

    return Math.min(Math.max(threatScore, 0), 100) // Clamp between 0-100
  }

  /**
   * Record failed login attempt with enhanced tracking
   */
  async recordFailedAttempt(data: {
    ip: string
    userAgent: string
    reason: string
    userId?: string
    threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  }): Promise<void> {
    // Update IP reputation
    const currentData = this.ipReputation.get(data.ip) || { score: 0, lastSeen: new Date(), events: 0 }
    
    const scoreIncrease = {
      LOW: 10,
      MEDIUM: 20,
      HIGH: 35,
      CRITICAL: 50
    }[data.threatLevel]

    currentData.score = Math.min(currentData.score + scoreIncrease, 100)
    currentData.lastSeen = new Date()
    currentData.events += 1
    
    this.ipReputation.set(data.ip, currentData)

    // Log security event
    const event: SecurityEvent = {
      type: 'LOGIN_FAILURE',
      userId: data.userId,
      ipAddress: data.ip,
      userAgent: data.userAgent,
      endpoint: '/api/auth/login',
      severity: data.threatLevel,
      details: {
        reason: data.reason,
        threatScore: currentData.score,
        reputationUpdated: true
      },
      timestamp: new Date()
    }

    await this.monitorEvent(event)

    // Trigger alerts for critical threats
    if (data.threatLevel === 'CRITICAL' || currentData.score >= 80) {
      await this.triggerAlert({
        type: 'BRUTE_FORCE_ATTACK',
        severity: 'CRITICAL',
        title: 'Critical Security Threat Detected',
        description: `Multiple failed login attempts from IP ${data.ip}. Threat score: ${currentData.score}`,
        ipAddress: data.ip,
        userId: data.userId
      })
    }
  }

  /**
   * Record successful login with security context
   */
  async recordSuccessfulLogin(data: {
    userId: string
    ip: string
    userAgent: string
    deviceFingerprint: string
    isTrustedDevice: boolean
    threatScore: number
  }): Promise<void> {
    // Update IP reputation (positive reputation)
    const currentData = this.ipReputation.get(data.ip) || { score: 50, lastSeen: new Date(), events: 0 }
    
    // Successful login improves reputation but not below 30
    currentData.score = Math.max(currentData.score - 5, 30)
    currentData.lastSeen = new Date()
    currentData.events += 1
    
    this.ipReputation.set(data.ip, currentData)

    // Log security event
    const event: SecurityEvent = {
      type: 'LOGIN_SUCCESS',
      userId: data.userId,
      ipAddress: data.ip,
      userAgent: data.userAgent,
      endpoint: '/api/auth/login',
      severity: data.threatScore > 70 ? 'HIGH' : 'LOW',
      details: {
        deviceFingerprint: data.deviceFingerprint.substring(0, 20) + '...',
        isTrustedDevice: data.isTrustedDevice,
        threatScore: data.threatScore,
        securityLevel: data.threatScore > 30 ? 'ENHANCED' : 'STANDARD'
      },
      timestamp: new Date()
    }

    await this.monitorEvent(event)

    // Alert for high threat score successful logins
    if (data.threatScore > 70) {
      await this.triggerAlert({
        type: 'SUSPICIOUS_LOGIN',
        severity: 'HIGH',
        title: 'High Threat Score Login',
        description: `User ${data.userId} logged in with high threat score (${data.threatScore})`,
        ipAddress: data.ip,
        userId: data.userId
      })
    }
  }

  /**
   * Get recent events for an IP
   */
  private getRecentEvents(ip: string, timeframeMs: number): SecurityEvent[] {
    // In production, this would query the database
    // For now, return empty array as we're using in-memory tracking
    return []
  }

  /**
   * Trigger security alert
   */
  private async triggerAlert(alertData: {
    type: string
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    title: string
    description: string
    ipAddress: string
    userId?: string
  }): Promise<void> {
    // In production, this would:
    // 1. Save alert to database
    // 2. Send notifications (email, Slack, etc.)
    // 3. Update security dashboard
    
    console.log('🚨 SECURITY ALERT:', alertData)
    
    // Execute registered callbacks
    const alert: SecurityAlert = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: alertData.type,
      severity: alertData.severity,
      title: alertData.title,
      description: alertData.description,
      userId: alertData.userId,
      ipAddress: alertData.ipAddress,
      resolved: false,
      createdAt: new Date()
    }

    this.alertCallbacks.forEach(callback => {
      try {
        callback(alert)
      } catch (error) {
        console.error('Error executing alert callback:', error)
      }
    })
  }

  /**
   * Register alert callback
   */
  onAlert(callback: (alert: SecurityAlert) => void): void {
    this.alertCallbacks.push(callback)
  }

  /**
   * Get IP reputation score
   */
  getIPReputation(ip: string): { score: number; level: string; events: number } {
    const data = this.ipReputation.get(ip) || { score: 50, lastSeen: new Date(), events: 0 }
    
    let level = 'LOW'
    if (data.score >= 80) level = 'CRITICAL'
    else if (data.score >= 60) level = 'HIGH'
    else if (data.score >= 40) level = 'MEDIUM'
    
    return {
      score: data.score,
      level,
      events: data.events
    }
  }

  /**
   * Reset IP reputation (for whitelisting)
   */
  resetIPReputation(ip: string): void {
    this.ipReputation.delete(ip)
  }
}

// Export singleton instance
export const securityMonitor = new AdvancedSecurityMonitor()

// Export class for custom instances
export { AdvancedSecurityMonitor }

// Export named SecurityMonitor class for compatibility
export class SecurityMonitor extends AdvancedSecurityMonitor {}

// Middleware for Next.js API routes
export function withSecurityMonitoring(handler: Function) {
  return async (req: NextRequest) => {
    try {
      const ipAddress = req.headers.get('x-forwarded-for')?.split(',')[0] || 
                       req.headers.get('x-real-ip') || 
                       req.ip || 
                       'unknown'

      const userAgent = req.headers.get('user-agent') || 'unknown'
      const userId = req.headers.get('authorization')?.split(' ')[1] // Mock user extraction
      
      const event: SecurityEvent = {
        type: 'SUSPICIOUS_ACTIVITY',
        userId,
        ipAddress,
        userAgent,
        endpoint: new URL(req.url).pathname,
        severity: 'MEDIUM',
        details: {
          method: req.method,
          headers: Object.fromEntries(req.headers.entries())
        },
        timestamp: new Date()
      }

      const allowRequest = await securityMonitor.monitorEvent(event)
      
      if (!allowRequest) {
        return new Response(JSON.stringify({
          error: 'Request blocked due to security policy',
          code: 'SECURITY_BLOCK'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        })
      }

      return await handler(req)

    } catch (error) {
      console.error('Security monitoring middleware error:', error)
      return await handler(req) // Allow request on monitoring error
    }
  }
}
