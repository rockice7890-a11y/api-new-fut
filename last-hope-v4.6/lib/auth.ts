import jwt from "jsonwebtoken"
// Crypto module for Node.js environment
import type { UserRole } from "@prisma/client"
import type { NextRequest } from "next/server"

const JWT_SECRET = process.env.JWT_SECRET
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || "refresh-secret-change-in-production"

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is not set")
}

export interface JWTPayload {
  userId: string
  email: string
  role: UserRole
  deviceFingerprint?: string
  requestId?: string
  isTrustedDevice?: boolean
  iat?: number
  exp?: number
}

export interface DeviceInfo {
  userAgent?: string
  platform?: string
  timezone?: string
  language?: string
  screenResolution?: string
  colorDepth?: number
}

// Enhanced device fingerprinting
export function generateDeviceFingerprint(deviceInfo: DeviceInfo): string {
  const data = {
    userAgent: deviceInfo.userAgent || 'unknown',
    platform: deviceInfo.platform || 'unknown',
    timezone: deviceInfo.timezone || 'unknown',
    language: deviceInfo.language || 'unknown',
    screenResolution: deviceInfo.screenResolution || 'unknown',
    colorDepth: deviceInfo.colorDepth || 'unknown',
  }
  
  const fingerprint = crypto
    .createHash('sha256')
    .update(JSON.stringify(data))
    .digest('hex')
  
  return fingerprint
}

// Enhanced token generation with security features
export function generateToken(payload: JWTPayload & { deviceFingerprint?: string; requestId?: string; isTrustedDevice?: boolean }): string {
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined')
  }
  
  const enhancedPayload = {
    ...payload,
    jti: crypto.randomUUID(), // JWT ID for token tracking
    aud: 'hotel-booking-system',
    iss: 'hotel-booking-api',
    tokenType: 'access_token',
  }
  
  return jwt.sign(enhancedPayload, JWT_SECRET, { 
    expiresIn: "1h", // Extended to 1 hour for better UX
    algorithm: 'HS256',
    header: {
      typ: 'JWT',
      alg: 'HS256'
    }
  })
}

// Enhanced refresh token with device binding
export function generateRefreshToken(userId: string, deviceFingerprint?: string): string {
  if (!REFRESH_TOKEN_SECRET) {
    throw new Error('REFRESH_TOKEN_SECRET is not defined')
  }
  
  const payload = {
    userId,
    deviceFingerprint,
    jti: crypto.randomUUID(),
    tokenType: 'refresh_token',
    aud: 'hotel-booking-system',
    iss: 'hotel-booking-api',
  }
  
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { 
    expiresIn: "7d",
    algorithm: 'HS256'
  })
}

// Token validation with enhanced security checks
export function verifyToken(token: string): JWTPayload | null {
  try {
    if (!JWT_SECRET) {
      throw new Error('JWT_SECRET is not defined')
    }
    
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      audience: 'hotel-booking-system',
      issuer: 'hotel-booking-api',
    }) as JWTPayload & { jti: string; aud: string; iss: string; tokenType: string }
    
    // Additional security validations
    if (decoded.tokenType !== 'access_token') {
      return null
    }
    
    return decoded
  } catch (error) {
    console.error('Token verification failed:', error)
    return null
  }
}

// Enhanced refresh token validation
export function verifyRefreshToken(token: string): { userId: string; deviceFingerprint?: string; jti: string } | null {
  try {
    if (!REFRESH_TOKEN_SECRET) {
      throw new Error('REFRESH_TOKEN_SECRET is not defined')
    }
    
    const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET, {
      algorithms: ['HS256'],
      audience: 'hotel-booking-system',
      issuer: 'hotel-booking-api',
    }) as { userId: string; deviceFingerprint?: string; jti: string; tokenType: string }
    
    if (decoded.tokenType !== 'refresh_token') {
      return null
    }
    
    return decoded
  } catch (error) {
    console.error('Refresh token verification failed:', error)
    return null
  }
}

// Extract token from Authorization header
export function extractToken(authHeader?: string): string | undefined {
  if (!authHeader?.startsWith("Bearer ")) return undefined
  return authHeader.slice(7)
}

// Enhanced authentication verification with security checks
export async function verifyAuth(request: NextRequest): Promise<JWTPayload | null> {
  const authHeader = request.headers.get("authorization") || undefined
  const token = extractToken(authHeader)
  if (!token) return null
  
  const payload = verifyToken(token)
  if (!payload) return null
  
  // Additional security checks can be added here
  // For example: check if user is still active, if device is trusted, etc.
  
  return payload
}

// Session security validation
export function validateSessionSecurity(
  tokenPayload: JWTPayload, 
  currentDeviceFingerprint?: string,
  currentRequestId?: string
): { isValid: boolean; reason?: string } {
  
  // Check if device fingerprint matches (for additional security)
  if (tokenPayload.deviceFingerprint && currentDeviceFingerprint) {
    if (tokenPayload.deviceFingerprint !== currentDeviceFingerprint) {
      return { isValid: false, reason: 'DEVICE_MISMATCH' }
    }
  }
  
  // Check if this is the same request session
  if (tokenPayload.requestId && currentRequestId) {
    // Allow some flexibility for concurrent requests from same user
    const requests = [tokenPayload.requestId, currentRequestId]
    // Additional session validation logic can be added here
    
  }
  
  return { isValid: true }
}

// Generate secure session ID
export function generateSessionId(): string {
  return `sess_${crypto.randomUUID()}`
}

// Hash sensitive data for storage
export function hashSensitiveData(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex')
}

// Generate secure random string
export function generateSecureRandom(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex')
}

// Validate password strength
export function validatePasswordStrength(password: string): {
  isValid: boolean
  score: number
  feedback: string[]
} {
  const feedback: string[] = []
  let score = 0
  
  if (password.length >= 8) {
    score += 1
  } else {
    feedback.push('Password should be at least 8 characters long')
  }
  
  if (/[a-z]/.test(password)) {
    score += 1
  } else {
    feedback.push('Password should contain lowercase letters')
  }
  
  if (/[A-Z]/.test(password)) {
    score += 1
  } else {
    feedback.push('Password should contain uppercase letters')
  }
  
  if (/\d/.test(password)) {
    score += 1
  } else {
    feedback.push('Password should contain numbers')
  }
  
  if (/[^a-zA-Z\d]/.test(password)) {
    score += 1
  } else {
    feedback.push('Password should contain special characters')
  }
  
  const isValid = score >= 4
  
  return { isValid, score, feedback }
}

// Generate CSRF token
export function generateCSRFToken(): string {
  return generateSecureRandom(32)
}

// Validate CSRF token
export function validateCSRFToken(token: string, sessionToken: string): boolean {
  return token === sessionToken
}
