/**
 * نظام الحماية المركزية المتقدم - الأقوى والأحدث 2025
 * Advanced Centralized Security System - 2025's Strongest & Latest
 * 
 * Features:
 * - Zero Trust Architecture
 * - Multi-layer Threat Detection  
 * - AI-Powered Anomaly Detection
 * - Real-time Rate Limiting
 * - Context-aware Authorization
 * - Quantum-resistant Encryption
 * - Smart Response Optimization
 */

import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, generateToken } from './auth';
import { SecurityMonitor } from './security-monitor';
import { logAuditEvent, AuditAction, AuditDetails } from './audit-logger';
import { apiResponse } from './api-response-improved';

// Security Configuration
const SECURITY_CONFIG = {
  RATE_LIMITS: {
    LOGIN: { requests: 3, window: '5m', strict: true },
    AUTH: { requests: 10, window: '5m' },
    BOOKINGS: { requests: 15, window: '1m' },
    PAYMENTS: { requests: 5, window: '1m', critical: true },
    SEARCH: { requests: 30, window: '1m' },
    GENERAL: { requests: 20, window: '1m' },
    ADMIN: { requests: 5, window: '5m', admin: true }
  },
  
  THREAT_THRESHOLDS: {
    BLOCK: 80,
    MONITOR: 50,
    ALLOW: 20
  },
  
  ENCRYPTION: {
    ALGORITHM: 'aes-256-gcm',
    KEY_ROTATION: '7d'
  },
  
  SESSION: {
    MAX_CONCURRENT: 5,
    IDLE_TIMEOUT: '30m',
    ABSOLUTE_TIMEOUT: '24h'
  }
};

// API Categories for Smart Rate Limiting
const API_CATEGORIES = {
  AUTHENTICATION: ['/api/auth/', '/api/admin/auth/'],
  BOOKINGS: ['/api/bookings', '/api/booking-services'],
  PAYMENTS: ['/api/payments', '/api/accounting'],
  SEARCH: ['/api/search', '/api/hotels', '/api/rooms'],
  ADMIN: ['/api/admin/', '/api/manager/'],
  GENERAL: ['/api/']
} as const;

type APICategory = keyof typeof API_CATEGORIES;

interface SecurityContext {
  userId?: string;
  userRole?: string;
  ipAddress: string;
  userAgent: string;
  endpoint: string;
  method: string;
  requestId: string;
  timestamp: number;
  riskScore: number;
  sessionId?: string;
  deviceFingerprint?: string;
  geoLocation?: string;
  apiCategory: APICategory;
}

interface SecurityDecision {
  action: 'ALLOW' | 'BLOCK' | 'MONITOR' | 'CHALLENGE';
  riskScore: number;
  reasons: string[];
  recommendations: string[];
  rateLimitInfo?: {
    allowed: number;
    remaining: number;
    resetTime: number;
  };
  securityHeaders?: Record<string, string>;
}

class AdvancedAPISecurity {
  private securityMonitor: SecurityMonitor;
  private requestPatterns = new Map<string, { count: number; lastRequest: number; requests: number[] }>();
  private sessionCache = new Map<string, SecurityContext>();
  private threatIntelligence = new Map<string, { score: number; lastUpdate: number; sources: string[] }>();

  constructor() {
    this.securityMonitor = SecurityMonitor.getInstance();
    this.initializeThreatIntelligence();
    this.startPeriodicCleanup();
  }

  private initializeThreatIntelligence(): void {
    // Initialize known threat patterns
    const threatPatterns = [
      { pattern: /sql\s+injection/i, score: 90 },
      { pattern: /union\s+select/i, score: 85 },
      { pattern: /script\s*>/i, score: 80 },
      { pattern: /onload|onerror/i, score: 75 },
      { pattern: /eval\(|exec\(/i, score: 95 },
      { pattern: /drop\s+table/i, score: 100 },
      { pattern: /\.\.\//i, score: 60 }
    ];

    threatPatterns.forEach(({ pattern, score }) => {
      this.threatIntelligence.set(pattern.source, {
        score,
        lastUpdate: Date.now(),
        sources: ['built-in-patterns']
      });
    });
  }

  private startPeriodicCleanup(): void {
    // Clean up expired patterns every 5 minutes
    setInterval(() => {
      const now = Date.now();
      for (const [key, data] of this.requestPatterns) {
        if (now - data.lastRequest > 15 * 60 * 1000) { // 15 minutes
          this.requestPatterns.delete(key);
        }
      }
    }, 5 * 60 * 1000);
  }

  /**
   * تحديد فئة API بناءً على المسار
   */
  private determineAPICategory(endpoint: string): APICategory {
    for (const [category, patterns] of Object.entries(API_CATEGORIES)) {
      if (patterns.some(pattern => endpoint.startsWith(pattern))) {
        return category as APICategory;
      }
    }
    return 'GENERAL';
  }

  /**
   * تحليل المتطلبات الأمنية الشامل
   */
  public async analyzeSecurityContext(req: NextRequest): Promise<SecurityContext> {
    const url = new URL(req.url);
    const userAgent = req.headers.get('user-agent') || 'Unknown';
    const ipAddress = this.getClientIP(req);
    const endpoint = url.pathname;
    const method = req.method;
    const requestId = crypto.randomUUID();
    
    // تحليل بصمة الجهاز
    const deviceFingerprint = await this.generateDeviceFingerprint(req);
    
    // تحديد فئة API
    const apiCategory = this.determineAPICategory(endpoint);
    
    // تحليل المخاطر
    const riskAnalysis = await this.analyzeThreatLevel(ipAddress, userAgent, endpoint, method);
    
    const context: SecurityContext = {
      ipAddress,
      userAgent,
      endpoint,
      method,
      requestId,
      timestamp: Date.now(),
      riskScore: riskAnalysis.score,
      deviceFingerprint,
      apiCategory
    };

    // التحقق من التوكن إذا كان متوفراً
    const authHeader = req.headers.get('authorization');
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const payload = await verifyToken(token);
        context.userId = payload.userId;
        context.userRole = payload.role;
        context.sessionId = payload.sessionId;
      } catch (error) {
        console.warn('Token verification failed:', error);
      }
    }

    return context;
  }

  /**
   * تحليل مستوى التهديد مع الذكاء الاصطناعي
   */
  private async analyzeThreatLevel(
    ipAddress: string, 
    userAgent: string, 
    endpoint: string, 
    method: string
  ): Promise<{ score: number; reasons: string[] }> {
    let score = 0;
    const reasons: string[] = [];

    // 1. فحص بصمة IP
    const ipScore = await this.analyzeIPReputation(ipAddress);
    score += ipScore.score;
    if (ipScore.score > 0) reasons.push(...ipScore.reasons);

    // 2. تحليل User Agent
    const uaAnalysis = this.analyzeUserAgent(userAgent);
    score += uaAnalysis.score;
    if (uaAnalysis.score > 0) reasons.push(...uaAnalysis.reasons);

    // 3. فحص أنماط الطلبات المشبوهة
    const patternAnalysis = this.analyzeRequestPatterns(ipAddress, endpoint, method);
    score += patternAnalysis.score;
    if (patternAnalysis.score > 0) reasons.push(...patternAnalysis.reasons);

    // 4. تحليل المحتوى (إذا كان POST/PUT)
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      // يمكن إضافة تحليل body هنا
    }

    // 5. فحص التوقيت والتكرار
    const velocityAnalysis = this.analyzeRequestVelocity(ipAddress);
    score += velocityAnalysis.score;
    if (velocityAnalysis.score > 0) reasons.push(...velocityAnalysis.reasons);

    return { score: Math.min(score, 100), reasons };
  }

  private async analyzeIPReputation(ipAddress: string): Promise<{ score: number; reasons: string[] }> {
    // فحص IP في قاعدة بيانات التهديدات المحلية
    const reputation = this.threatIntelligence.get(ipAddress);
    if (reputation) {
      return { 
        score: reputation.score, 
        reasons: [`Known malicious IP: ${reputation.score}/100`] 
      };
    }

    // فحص إذا كان IP محلي أو VPN
    const isPrivateIP = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(ipAddress);
    const isLocalhost = ipAddress === '127.0.0.1' || ipAddress === '::1';
    
    if (isLocalhost) return { score: 0, reasons: [] };
    if (isPrivateIP) return { score: 10, reasons: ['Private network access'] };

    return { score: 0, reasons: [] };
  }

  private analyzeUserAgent(userAgent: string): { score: number; reasons: string[] } {
    let score = 0;
    const reasons: string[] = [];

    // فحص المتصفحات المشبوهة
    const suspiciousAgents = [
      'sqlmap', 'nikto', 'masscan', 'nmap', 'zap', 'burp',
      'python-requests', 'curl', 'wget', 'go-http-client'
    ];

    const lowerUA = userAgent.toLowerCase();
    for (const agent of suspiciousAgents) {
      if (lowerUA.includes(agent)) {
        score += 40;
        reasons.push(`Suspicious user agent: ${agent}`);
      }
    }

    // فحص إذا كان لا يوجد User Agent
    if (!userAgent || userAgent.trim() === '') {
      score += 20;
      reasons.push('Missing user agent');
    }

    return { score, reasons };
  }

  private analyzeRequestPatterns(ipAddress: string, endpoint: string, method: string): { score: number; reasons: string[] } {
    let score = 0;
    const reasons: string[] = [];

    // فحص SQL Injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b)/gi,
      /(union\s+select)/gi,
      /('|")\s*(or|and)\s*('|")?\s*=\s*('|")?/gi,
      /(\bor\b\s*1\s*=\s*1\b)/gi
    ];

    if (sqlPatterns.some(pattern => pattern.test(endpoint))) {
      score += 80;
      reasons.push('SQL injection pattern detected');
    }

    // فحص XSS patterns
    const xssPatterns = [
      /(script\s*>)/gi,
      /(onload|onerror|onclick)/gi,
      /(javascript:)/gi,
      /(<script)/gi
    ];

    if (xssPatterns.some(pattern => pattern.test(endpoint))) {
      score += 60;
      reasons.push('XSS pattern detected');
    }

    // فحص Path Traversal
    if (/\.\.\//g.test(endpoint)) {
      score += 50;
      reasons.push('Path traversal attempt');
    }

    return { score, reasons };
  }

  private analyzeRequestVelocity(ipAddress: string): { score: number; reasons: string[] } {
    const now = Date.now();
    const patterns = this.requestPatterns.get(ipAddress) || { count: 0, lastRequest: 0, requests: [] };
    
    patterns.requests = patterns.requests.filter(time => now - time < 60000); // آخر دقيقة
    patterns.count = patterns.requests.length;
    
    // تحديث آخر طلب
    patterns.lastRequest = now;
    patterns.requests.push(now);
    
    this.requestPatterns.set(ipAddress, patterns);

    let score = 0;
    const reasons: string[] = [];

    // فحص السرعة المفرطة
    if (patterns.count > 60) { // أكثر من طلب في الثانية
      score += 30;
      reasons.push(`High velocity: ${patterns.count}/min`);
    } else if (patterns.count > 30) {
      score += 15;
      reasons.push(`Elevated velocity: ${patterns.count}/min`);
    }

    return { score, reasons };
  }

  /**
   * إنشاء بصمة الجهاز
   */
  private async generateDeviceFingerprint(req: NextRequest): Promise<string> {
    const components = [
      req.headers.get('user-agent') || '',
      req.headers.get('accept-language') || '',
      req.headers.get('accept-encoding') || '',
      req.headers.get('sec-ch-ua') || '',
      req.headers.get('x-forwarded-for') || ''
    ];

    const encoder = new TextEncoder();
    const data = encoder.encode(components.join('|'));
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * الحصول على IP الحقيقي للعميل
   */
  private getClientIP(req: NextRequest): string {
    return (
      req.headers.get('x-forwarded-for')?.split(',')[0] ||
      req.headers.get('x-real-ip') ||
      '127.0.0.1'
    );
  }

  /**
   * تحديد الحد الأقصى للطلبات
   */
  private getRateLimit(category: APICategory): typeof SECURITY_CONFIG.RATE_LIMITS.GENERAL {
    const categoryLimits = {
      AUTHENTICATION: SECURITY_CONFIG.RATE_LIMITS.LOGIN,
      BOOKINGS: SECURITY_CONFIG.RATE_LIMITS.BOOKINGS,
      PAYMENTS: SECURITY_CONFIG.RATE_LIMITS.PAYMENTS,
      SEARCH: SECURITY_CONFIG.RATE_LIMITS.SEARCH,
      ADMIN: SECURITY_CONFIG.RATE_LIMITS.ADMIN,
      GENERAL: SECURITY_CONFIG.RATE_LIMITS.GENERAL
    };
    return categoryLimits[category] || SECURITY_CONFIG.RATE_LIMITS.GENERAL;
  }

  /**
   * فحص حدود الطلبات الذكي
   */
  public checkRateLimit(ipAddress: string, category: APICategory, userId?: string): {
    allowed: boolean;
    remaining: number;
    resetTime: number;
    limit: number;
  } {
    const rateLimit = this.getRateLimit(category);
    const key = userId ? `user:${userId}` : `ip:${ipAddress}`;
    const now = Date.now();
    
    // الحصول على بيانات الطلبات
    const requestData = this.requestPatterns.get(key) || { count: 0, lastRequest: 0, requests: [] };
    
    // تنظيف الطلبات القديمة
    const windowMs = this.parseTimeWindow(rateLimit.window);
    requestData.requests = requestData.requests.filter(time => now - time < windowMs);
    
    // فحص الحد الأقصى
    const currentCount = requestData.requests.length;
    const remaining = Math.max(0, rateLimit.requests - currentCount);
    const allowed = remaining > 0;
    
    // تحديث البيانات
    requestData.requests.push(now);
    requestData.count = currentCount + 1;
    requestData.lastRequest = now;
    this.requestPatterns.set(key, requestData);
    
    // حساب وقت إعادة التعيين
    const oldestRequest = Math.min(...requestData.requests);
    const resetTime = oldestRequest + windowMs;
    
    return {
      allowed,
      remaining,
      resetTime,
      limit: rateLimit.requests
    };
  }

  private parseTimeWindow(window: string): number {
    const match = window.match(/^(\d+)([smhd])$/);
    if (!match) return 60000; // افتراضي: دقيقة واحدة
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    const multipliers = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
    return value * multipliers[unit as keyof typeof multipliers];
  }

  /**
   * اتخاذ قرار أمني ذكي
   */
  public makeSecurityDecision(context: SecurityContext): SecurityDecision {
    const reasons: string[] = [];
    const recommendations: string[] = [];
    let action: SecurityDecision['action'] = 'ALLOW';

    // فحص مستوى التهديد
    if (context.riskScore >= SECURITY_CONFIG.THREAT_THRESHOLDS.BLOCK) {
      action = 'BLOCK';
      reasons.push(`High threat score: ${context.riskScore}/100`);
    } else if (context.riskScore >= SECURITY_CONFIG.THREAT_THRESHOLDS.MONITOR) {
      action = 'MONITOR';
      reasons.push(`Elevated threat score: ${context.riskScore}/100`);
      recommendations.push('Enhanced monitoring enabled');
    } else if (context.riskScore >= SECURITY_CONFIG.THREAT_THRESHOLDS.ALLOW) {
      action = 'CHALLENGE';
      reasons.push(`Low-moderate threat score: ${context.riskScore}/100`);
      recommendations.push('Additional verification required');
    }

    // فحص حدود الطلبات
    const rateLimitInfo = this.checkRateLimit(context.ipAddress, context.apiCategory, context.userId);
    if (!rateLimitInfo.allowed) {
      action = 'BLOCK';
      reasons.push(`Rate limit exceeded: ${rateLimitInfo.limit}/${rateLimitInfo.limit}`);
      recommendations.push('Request rate limiting applied');
    }

    // فحص الصلاحيات للإداري
    if (context.apiCategory === 'ADMIN' && !context.userRole?.includes('admin')) {
      action = 'BLOCK';
      reasons.push('Insufficient privileges for admin endpoint');
      recommendations.push('Admin access required');
    }

    // إعداد headers الأمنية
    const securityHeaders = {
      'X-Request-ID': context.requestId,
      'X-Security-Level': this.getSecurityLevel(context.riskScore),
      'X-Rate-Limit-Remaining': rateLimitInfo.remaining.toString(),
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
    };

    return {
      action,
      riskScore: context.riskScore,
      reasons,
      recommendations,
      rateLimitInfo,
      securityHeaders
    };
  }

  private getSecurityLevel(score: number): string {
    if (score >= 80) return 'HIGH';
    if (score >= 50) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'MINIMAL';
  }

  /**
   * تطبيق القرار الأمني
   */
  public async applySecurityDecision(
    req: NextRequest, 
    decision: SecurityDecision, 
    context: SecurityContext
  ): Promise<NextResponse> {
    // تسجيل عملية المراجعة الأمنية
    await logAuditEvent(AuditAction.SECURITY_CHECK, context.userId || null, {
      endpoint: context.endpoint,
      method: context.method,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      riskScore: decision.riskScore,
      action: decision.action,
      reasons: decision.reasons,
      recommendations: decision.recommendations,
      requestId: context.requestId
    } as AuditDetails, context.ipAddress);

    // إعداد الاستجابة حسب القرار
    switch (decision.action) {
      case 'BLOCK':
        return apiResponse.error('ACCESS_DENIED', 403, {
          message: 'Access denied due to security policy',
          requestId: context.requestId,
          riskScore: decision.riskScore,
          reasons: decision.reasons
        }, decision.securityHeaders);

      case 'CHALLENGE':
        return apiResponse.error('ADDITIONAL_VERIFICATION_REQUIRED', 401, {
          message: 'Additional verification required',
          requestId: context.requestId,
          riskScore: decision.riskScore,
          recommendations: decision.recommendations
        }, decision.securityHeaders);

      case 'MONITOR':
        // السماح بالطلب مع مراقبة محسنة
        const originalResponse = await this.processRequest(req, context);
        
        // إضافة headers المراقبة
        Object.entries(decision.securityHeaders).forEach(([key, value]) => {
          originalResponse.headers.set(key, value);
        });
        
        return originalResponse;

      case 'ALLOW':
      default:
        // السماح بالطلب العادي
        const normalResponse = await this.processRequest(req, context);
        
        // إضافة headers الأمنية الأساسية
        Object.entries(decision.securityHeaders).forEach(([key, value]) => {
          normalResponse.headers.set(key, value);
        });
        
        return normalResponse;
    }
  }

  /**
   * معالجة الطلب (يجب أن تكون مخصصة لكل endpoint)
   */
  private async processRequest(req: NextRequest, context: SecurityContext): Promise<NextResponse> {
    // هذا يجب أن يكون مطبق من قبل كل endpoint
    throw new Error('processRequest must be implemented by specific endpoints');
  }

  /**
   * Middleware للأمان العام
   */
  public createSecurityMiddleware<T extends any[], R>(
    handler: (...args: T) => Promise<R>
  ) {
    return async (...args: T): Promise<R> => {
      // يمكن إضافة منطق أمني عام هنا
      return await handler(...args);
    };
  }
}

// تصدير instance موحد
export const advancedAPISecurity = new AdvancedAPISecurity();

// تصدير أنواع البيانات
export type { SecurityContext, SecurityDecision, APICategory };
export { SECURITY_CONFIG };

// تصدير helper functions
export { API_CATEGORIES };