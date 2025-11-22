/**
 * Request OTP API
 * طلب رمز OTP عبر WhatsApp
 */

import { NextRequest, NextResponse } from 'next/server'
import { sendWhatsAppOTP } from '@/lib/whatsapp-otp'
import { isAdminConfigured } from '@/lib/admin-auth'

export async function POST(req: NextRequest) {
  try {
    // التحقق من إعداد المدير
    if (!isAdminConfigured()) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'لم يتم إعداد حساب المدير. الرجاء زيارة /admin-setup'
        },
        { status: 403 }
      )
    }

    const { email } = await req.json()

    // التحقق من البريد الإلكتروني
    if (!email || email !== process.env.ADMIN_EMAIL) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'بريد إلكتروني غير صحيح'
        },
        { status: 401 }
      )
    }

    // إرسال OTP إلى رقم المدير المسجل
    const adminPhone = process.env.ADMIN_WHATSAPP_NUMBER || process.env.ADMIN_PHONE
    
    if (!adminPhone) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'رقم واتساب المدير غير مُعد'
        },
        { status: 500 }
      )
    }

    const result = await sendWhatsAppOTP(adminPhone)

    if (!result.success) {
      return NextResponse.json(
        {
          status: 'error',
          message: result.message
        },
        { status: 500 }
      )
    }

    // إخفاء جزء من رقم الهاتف للخصوصية
    const maskedPhone = adminPhone.replace(/(\d{4})\d+(\d{3})/, '$1****$2')

    return NextResponse.json({
      status: 'success',
      message: result.message,
      data: {
        phone: maskedPhone,
        expiresIn: result.expiresIn
      }
    })

  } catch (error: any) {
    console.error('Request OTP error:', error)
    return NextResponse.json(
      {
        status: 'error',
        message: 'حدث خطأ في إرسال الرمز'
      },
      { status: 500 }
    )
  }
}
