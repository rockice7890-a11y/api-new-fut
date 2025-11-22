import crypto from 'crypto'

export enum AuditAction {
  // Authentication events
  USER_LOGIN = "USER_LOGIN",
  USER_LOGOUT = "USER_LOGOUT",
  USER_REGISTER = "USER_REGISTER",
  PASSWORD_CHANGE = "PASSWORD_CHANGE",
  PASSWORD_RESET = "PASSWORD_RESET",
  EMAIL_VERIFICATION = "EMAIL_VERIFICATION",
  
  // Security events
  FAILED_AUTH = "FAILED_AUTH",
  ACCOUNT_LOCKED = "ACCOUNT_LOCKED",
  ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED",
  SECURITY_INCIDENT = "SECURITY_INCIDENT",
  SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY",
  PERMISSION_DENIED = "PERMISSION_DENIED",
  
  // Business events
  BOOKING_CREATE = "BOOKING_CREATE",
  BOOKING_UPDATE = "BOOKING_UPDATE",
  BOOKING_CANCEL = "BOOKING_CANCEL",
  BOOKING_COMPLETE = "BOOKING_COMPLETE",
  HOTEL_CREATE = "HOTEL_CREATE",
  HOTEL_UPDATE = "HOTEL_UPDATE",
  HOTEL_DELETE = "HOTEL_DELETE",
  PAYMENT_PROCESS = "PAYMENT_PROCESS",
  REFUND_PROCESS = "REFUND_PROCESS",
  
  // Admin events
  ADMIN_ACTION = "ADMIN_ACTION",
  SYSTEM_CONFIG_CHANGE = "SYSTEM_CONFIG_CHANGE",
  USER_ROLE_CHANGE = "USER_ROLE_CHANGE",
  BULK_OPERATION = "BULK_OPERATION",
  
  // Data events
  DATA_EXPORT = "DATA_EXPORT",
  DATA_IMPORT = "DATA_IMPORT",
  DATA_DELETE = "DATA_DELETE",
  
  // Session events
  SESSION_CREATE = "SESSION_CREATE",
  SESSION_EXPIRE = "SESSION_EXPIRE",
  SESSION_TERMINATE = "SESSION_TERMINATE",
  
  // Device events
  DEVICE_REGISTER = "DEVICE_REGISTER",
  DEVICE_TRUST = "DEVICE_TRUST",
  DEVICE_REVOKE = "DEVICE_REVOKE",
  
  // API events
  API_ACCESS = "API_ACCESS",
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
  
  // Compliance events
  GDPR_REQUEST = "GDPR_REQUEST",
  DATA_RETENTION = "DATA_RETENTION"
}

export interface SecurityEvent {
  type: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  description: string
  metadata?: Record<string, any>
}

export interface AuditEvent {
  id: string
  action: AuditAction
  userId?: string
  ipAddress: string
  userAgent: string
  timestamp: Date
  status: 'SUCCESS' | 'FAILURE' | 'WARNING'
  details: Record<string, any>
  requestId?: string
  sessionId?: string
  riskScore?: number
  compliance?: {
    gdprRelevant: boolean
    dataRetention: boolean
    consentRequired: boolean
  }
}

// In-memory storage for demo (use database in production)
const auditLogs: AuditEvent[] = []
const MAX_LOGS = 10000

// Risk scoring constants
const RISK_SCORES = {
  FAILED_AUTH: 30,
  ACCOUNT_LOCKED: 70,
  SUSPICIOUS_ACTIVITY: 60,
  SECURITY_INCIDENT: 80,
  PERMISSION_DENIED: 40,
  RATE_LIMIT_EXCEEDED: 50,
} as const

function generateEventId(): string {
  return `audit_${crypto.randomUUID()}`
}

function calculateRiskScore(action: AuditAction, details: Record<string, any>): number {
  let score = RISK_SCORES[action as keyof typeof RISK_SCORES] || 0
  
  // Increase risk based on details
  if (details.threatScore) {
    score = Math.max(score, details.threatScore)
  }
  
  if (details.multipleAttempts) {
    score += 20
  }
  
  if (details.unusualTime) {
    score += 15
  }
  
  if (details.newDevice) {
    score += 10
  }
  
  return Math.min(score, 100)
}

function isGDPRRelevant(action: AuditAction): boolean {
  const gdprActions = [
    AuditAction.USER_REGISTER,
    AuditAction.PASSWORD_RESET,
    AuditAction.EMAIL_VERIFICATION,
    AuditAction.DATA_EXPORT,
    AuditAction.DATA_DELETE,
    AuditAction.GDPR_REQUEST,
    AuditAction.PERSONAL_DATA_ACCESS,
    AuditAction.PERSONAL_DATA_ERASURE
  ]
  
  return gdprActions.includes(action)
}

export async function logAuditEvent(
  action: AuditAction,
  userId: string | null,
  details: Record<string, any>,
  ipAddress?: string,
  userAgent?: string,
  requestId?: string,
  sessionId?: string
): Promise<void> {
  try {
    const event: AuditEvent = {
      id: generateEventId(),
      action,
      userId: userId || undefined,
      ipAddress: ipAddress || 'unknown',
      userAgent: userAgent || 'unknown',
      timestamp: new Date(),
      status: action.includes('FAILED') || action.includes('SECURITY') ? 'FAILURE' : 'SUCCESS',
      details,
      requestId,
      sessionId,
      riskScore: calculateRiskScore(action, details),
      compliance: {
        gdprRelevant: isGDPRRelevant(action),
        dataRetention: ['USER_DELETE', 'DATA_DELETE'].includes(action),
        consentRequired: ['MARKETING', 'PROFILING'].some(type => details[type])
      }
    }
    
    // Store in memory (replace with database in production)
    auditLogs.push(event)
    
    // Maintain log size limit
    if (auditLogs.length > MAX_LOGS) {
      auditLogs.splice(0, auditLogs.length - MAX_LOGS)
    }
    
    // Enhanced logging with structured format
    const logEntry = {
      timestamp: event.timestamp.toISOString(),
      eventId: event.id,
      action: event.action,
      userId: event.userId,
      ip: event.ipAddress,
      status: event.status,
      riskScore: event.riskScore,
      requestId: event.requestId,
      sessionId: event.sessionId,
      details: event.details,
      compliance: event.compliance
    }
    
    console.log(`[AUDIT] ${JSON.stringify(logEntry)}`)
    
    // Log critical security events with higher priority
    if (event.riskScore >= 70) {
      console.error(`🚨 SECURITY ALERT: ${JSON.stringify(logEntry)}`)
    }
    
  } catch (error) {
    console.error("Error logging audit event:", error)
  }
}

// Log security event with enhanced details
export async function logSecurityEvent(
  type: string,
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
  description: string,
  metadata: Record<string, any> = {}
): Promise<void> {
  await logAuditEvent(
    AuditAction.SECURITY_INCIDENT,
    metadata.userId || null,
    {
      securityEventType: type,
      severity,
      description,
      metadata,
      automatedDetection: metadata.automatedDetection || false
    },
    metadata.ipAddress,
    metadata.userAgent,
    metadata.requestId,
    metadata.sessionId
  )
}

// Log compliance event
export async function logComplianceEvent(
  action: AuditAction,
  userId: string | null,
  details: Record<string, any>,
  ipAddress?: string,
  gdprRelevant: boolean = false
): Promise<void> {
  await logAuditEvent(
    action,
    userId,
    {
      ...details,
      complianceEvent: true,
      gdprRelevant,
      dataSubject: gdprRelevant ? userId : undefined
    },
    ipAddress
  )
}

// Get audit logs with filtering
export function getAuditLogs(
  filters: {
    userId?: string
    action?: AuditAction
    status?: 'SUCCESS' | 'FAILURE' | 'WARNING'
    startDate?: Date
    endDate?: Date
    riskScoreMin?: number
    ipAddress?: string
  } = {},
  limit: number = 100
): AuditEvent[] {
  let filteredLogs = [...auditLogs]
  
  if (filters.userId) {
    filteredLogs = filteredLogs.filter(log => log.userId === filters.userId)
  }
  
  if (filters.action) {
    filteredLogs = filteredLogs.filter(log => log.action === filters.action)
  }
  
  if (filters.status) {
    filteredLogs = filteredLogs.filter(log => log.status === filters.status)
  }
  
  if (filters.startDate) {
    filteredLogs = filteredLogs.filter(log => log.timestamp >= filters.startDate!)
  }
  
  if (filters.endDate) {
    filteredLogs = filteredLogs.filter(log => log.timestamp <= filters.endDate!)
  }
  
  if (filters.riskScoreMin) {
    filteredLogs = filteredLogs.filter(log => (log.riskScore || 0) >= filters.riskScoreMin!)
  }
  
  if (filters.ipAddress) {
    filteredLogs = filteredLogs.filter(log => log.ipAddress === filters.ipAddress)
  }
  
  // Sort by timestamp descending and apply limit
  return filteredLogs
    .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
    .slice(0, limit)
}

// Get security statistics
export function getSecurityStats(): {
  totalEvents: number
  failedAuth: number
  securityIncidents: number
  averageRiskScore: number
  topThreatSources: Array<{ ip: string; count: number; avgRisk: number }>
} {
  const failedAuth = auditLogs.filter(log => log.action === AuditAction.FAILED_AUTH).length
  const securityIncidents = auditLogs.filter(log => log.action === AuditAction.SECURITY_INCIDENT).length
  
  const riskScores = auditLogs
    .filter(log => log.riskScore !== undefined)
    .map(log => log.riskScore!)
  
  const averageRiskScore = riskScores.length > 0 
    ? riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length 
    : 0
  
  // Top threat sources
  const ipStats = new Map<string, { count: number; totalRisk: number }>()
  
  auditLogs
    .filter(log => (log.riskScore || 0) >= 50)
    .forEach(log => {
      const stats = ipStats.get(log.ipAddress) || { count: 0, totalRisk: 0 }
      stats.count += 1
      stats.totalRisk += log.riskScore || 0
      ipStats.set(log.ipAddress, stats)
    })
  
  const topThreatSources = Array.from(ipStats.entries())
    .map(([ip, stats]) => ({
      ip,
      count: stats.count,
      avgRisk: Math.round(stats.totalRisk / stats.count)
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
  
  return {
    totalEvents: auditLogs.length,
    failedAuth,
    securityIncidents,
    averageRiskScore: Math.round(averageRiskScore),
    topThreatSources
  }
}

// Export SecurityEvent type for external use
export type { SecurityEvent as SecurityEventType }
