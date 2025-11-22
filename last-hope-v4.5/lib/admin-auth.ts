/**
 * Admin Authentication System
 * نظام مصادقة المدير الآمن
 */

import { compare, hash } from 'bcryptjs'
import jwt from 'jsonwebtoken'

export interface AdminUser {
  email: string
  phone: string
  role: 'ADMIN'
}

export interface AdminTokenPayload {
  email: string
  phone: string
  role: 'ADMIN'
  iat: number
  exp: number
}

/**
 * التحقق من إعداد المدير
 */
export function isAdminConfigured(): boolean {
  return !!(
    process.env.ADMIN_EMAIL &&
    process.env.ADMIN_PASSWORD_HASH &&
    process.env.ADMIN_PHONE
  )
}

/**
 * التحقق من بيانات المدير
 */
export async function verifyAdminCredentials(
  email: string,
  password: string
): Promise<{ valid: boolean; message: string; admin?: AdminUser }> {
  try {
    // التحقق من الإعداد
    if (!isAdminConfigured()) {
      return {
        valid: false,
        message: 'لم يتم إعداد حساب المدير. الرجاء زيارة /admin-setup'
      }
    }

    // التحقق من البريد الإلكتروني
    if (email !== process.env.ADMIN_EMAIL) {
      return {
        valid: false,
        message: 'بريد إلكتروني غير صحيح'
      }
    }

    // التحقق من كلمة المرور
    const isValid = await compare(password, process.env.ADMIN_PASSWORD_HASH!)
    
    if (!isValid) {
      return {
        valid: false,
        message: 'كلمة مرور غير صحيحة'
      }
    }

    // نجح التحقق
    return {
      valid: true,
      message: 'تم التحقق بنجاح',
      admin: {
        email: process.env.ADMIN_EMAIL!,
        phone: process.env.ADMIN_PHONE!,
        role: 'ADMIN'
      }
    }

  } catch (error: any) {
    console.error('Admin verification error:', error)
    return {
      valid: false,
      message: 'حدث خطأ في التحقق'
    }
  }
}

/**
 * إنشاء JWT Token للمدير
 */
export function createAdminToken(admin: AdminUser): string {
  const secret = process.env.JWT_SECRET
  if (!secret) {
    throw new Error('JWT_SECRET not configured')
  }

  return jwt.sign(
    {
      email: admin.email,
      phone: admin.phone,
      role: admin.role
    },
    secret,
    {
      expiresIn: '8h',
      issuer: 'hotel-booking-admin',
      audience: 'hotel-booking-api'
    }
  )
}

/**
 * التحقق من صحة Admin Token
 */
export function verifyAdminToken(token: string): {
  valid: boolean
  payload?: AdminTokenPayload
  message?: string
} {
  try {
    const secret = process.env.JWT_SECRET
    if (!secret) {
      return { valid: false, message: 'JWT_SECRET not configured' }
    }

    const payload = jwt.verify(token, secret, {
      issuer: 'hotel-booking-admin',
      audience: 'hotel-booking-api'
    }) as AdminTokenPayload

    // التحقق من أن المستخدم هو المدير
    if (payload.email !== process.env.ADMIN_EMAIL) {
      return { valid: false, message: 'Invalid admin token' }
    }

    return {
      valid: true,
      payload
    }

  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      return { valid: false, message: 'انتهت صلاحية الجلسة. الرجاء تسجيل الدخول مجدداً.' }
    }
    return { valid: false, message: 'رمز دخول غير صالح' }
  }
}

/**
 * تشفير كلمة مرور جديدة
 */
export async function hashPassword(password: string): Promise<string> {
  return hash(password, 12)
}

/**
 * التحقق من قوة كلمة المرور
 */
export function validatePasswordStrength(password: string): {
  valid: boolean
  message: string
} {
  if (password.length < 8) {
    return {
      valid: false,
      message: 'كلمة المرور يجب أن تحتوي على 8 أحرف على الأقل'
    }
  }

  if (!/[A-Z]/.test(password)) {
    return {
      valid: false,
      message: 'كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل'
    }
  }

  if (!/[a-z]/.test(password)) {
    return {
      valid: false,
      message: 'كلمة المرور يجب أن تحتوي على حرف صغير واحد على الأقل'
    }
  }

  if (!/[0-9]/.test(password)) {
    return {
      valid: false,
      message: 'كلمة المرور يجب أن تحتوي على رقم واحد على الأقل'
    }
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return {
      valid: false,
      message: 'كلمة المرور يجب أن تحتوي على رمز خاص واحد على الأقل'
    }
  }

  return {
    valid: true,
    message: 'كلمة مرور قوية'
  }
}

/**
 * التحقق من صحة البريد الإلكتروني
 */
export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

/**
 * التحقق من صحة رقم الهاتف (WhatsApp)
 */
export function validateWhatsAppNumber(phone: string): {
  valid: boolean
  message: string
} {
  // يجب أن يبدأ بـ whatsapp:+
  if (!phone.startsWith('whatsapp:+')) {
    return {
      valid: false,
      message: 'الرقم يجب أن يبدأ بـ whatsapp:+ (مثال: whatsapp:+966500000000)'
    }
  }

  // يجب أن يحتوي على رقم بعد whatsapp:+
  const number = phone.replace('whatsapp:+', '')
  if (!/^\d{10,15}$/.test(number)) {
    return {
      valid: false,
      message: 'رقم هاتف غير صالح'
    }
  }

  return {
    valid: true,
    message: 'رقم صالح'
  }
}
