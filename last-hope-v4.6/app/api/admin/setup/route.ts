/**
 * Admin Setup API
 * إعداد حساب المدير للمرة الأولى فقط
 */

import { NextRequest, NextResponse } from 'next/server'
import { promises as fs } from 'fs'
import path from 'path'
import {
  hashPassword,
  validatePasswordStrength,
  validateEmail,
  validateWhatsAppNumber,
  isAdminConfigured
} from '@/lib/admin-auth'

export async function POST(req: NextRequest) {
  try {
    // التحقق من أن المدير غير مُعد مسبقاً
    if (isAdminConfigured()) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'حساب المدير مُعد مسبقاً. لا يمكن إعادة الإعداد.'
        },
        { status: 403 }
      )
    }

    const { email, password, phone } = await req.json()

    // التحقق من البيانات
    if (!email || !password || !phone) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'جميع الحقول مطلوبة'
        },
        { status: 400 }
      )
    }

    // التحقق من البريد الإلكتروني
    if (!validateEmail(email)) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'بريد إلكتروني غير صالح'
        },
        { status: 400 }
      )
    }

    // التحقق من كلمة المرور
    const passwordValidation = validatePasswordStrength(password)
    if (!passwordValidation.valid) {
      return NextResponse.json(
        {
          status: 'error',
          message: passwordValidation.message
        },
        { status: 400 }
      )
    }

    // التحقق من رقم الواتساب
    const phoneValidation = validateWhatsAppNumber(phone)
    if (!phoneValidation.valid) {
      return NextResponse.json(
        {
          status: 'error',
          message: phoneValidation.message
        },
        { status: 400 }
      )
    }

    // تشفير كلمة المرور
    const hashedPassword = await hashPassword(password)

    // تحديث ملف .env
    const envPath = path.join(process.cwd(), '.env')
    let envContent = await fs.readFile(envPath, 'utf-8')

    // تحديث القيم
    envContent = envContent.replace(
      /ADMIN_EMAIL=".*"/,
      `ADMIN_EMAIL="${email}"`
    )
    envContent = envContent.replace(
      /ADMIN_PASSWORD_HASH=".*"/,
      `ADMIN_PASSWORD_HASH="${hashedPassword}"`
    )
    envContent = envContent.replace(
      /ADMIN_PHONE=".*"/,
      `ADMIN_PHONE="${phone}"`
    )
    envContent = envContent.replace(
      /ADMIN_WHATSAPP_NUMBER=".*"/,
      `ADMIN_WHATSAPP_NUMBER="${phone}"`
    )

    await fs.writeFile(envPath, envContent, 'utf-8')

    // إعادة تحميل المتغيرات البيئية
    process.env.ADMIN_EMAIL = email
    process.env.ADMIN_PASSWORD_HASH = hashedPassword
    process.env.ADMIN_PHONE = phone
    process.env.ADMIN_WHATSAPP_NUMBER = phone

    return NextResponse.json({
      status: 'success',
      message: 'تم إعداد حساب المدير بنجاح! يمكنك الآن تسجيل الدخول.',
      data: {
        email,
        phone
      }
    })

  } catch (error: any) {
    console.error('Admin setup error:', error)
    return NextResponse.json(
      {
        status: 'error',
        message: 'حدث خطأ في إعداد الحساب: ' + error.message
      },
      { status: 500 }
    )
  }
}

/**
 * التحقق من حالة الإعداد
 */
export async function GET() {
  return NextResponse.json({
    status: 'success',
    data: {
      isConfigured: isAdminConfigured(),
      hasEmail: !!process.env.ADMIN_EMAIL,
      hasPhone: !!process.env.ADMIN_PHONE
    }
  })
}
