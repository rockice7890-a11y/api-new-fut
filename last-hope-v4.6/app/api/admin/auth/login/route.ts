/**
 * Admin Login API
 * تسجيل دخول المدير باستخدام OTP
 */

import { NextRequest, NextResponse } from 'next/server'
import { verifyOTP } from '@/lib/whatsapp-otp'
import { verifyAdminCredentials, createAdminToken } from '@/lib/admin-auth'

export async function POST(req: NextRequest) {
  try {
    const { email, password, otp } = await req.json()

    // التحقق من البيانات
    if (!email || !password) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'البريد الإلكتروني وكلمة المرور مطلوبان'
        },
        { status: 400 }
      )
    }

    // التحقق من بيانات الاعتماد
    const credentialsCheck = await verifyAdminCredentials(email, password)
    
    if (!credentialsCheck.valid) {
      return NextResponse.json(
        {
          status: 'error',
          message: credentialsCheck.message
        },
        { status: 401 }
      )
    }

    // إذا تم توفير OTP، التحقق منه
    if (otp) {
      const adminPhone = process.env.ADMIN_WHATSAPP_NUMBER || process.env.ADMIN_PHONE!
      const otpCheck = verifyOTP(adminPhone, otp)
      
      if (!otpCheck.valid) {
        return NextResponse.json(
          {
            status: 'error',
            message: otpCheck.message
          },
          { status: 401 }
        )
      }
    }

    // إنشاء JWT Token
    const token = createAdminToken(credentialsCheck.admin!)

    return NextResponse.json({
      status: 'success',
      message: 'تم تسجيل الدخول بنجاح',
      data: {
        token,
        expiresIn: '8h',
        admin: {
          email: credentialsCheck.admin!.email,
          role: credentialsCheck.admin!.role
        }
      }
    })

  } catch (error: any) {
    console.error('Admin login error:', error)
    return NextResponse.json(
      {
        status: 'error',
        message: 'حدث خطأ في تسجيل الدخول'
      },
      { status: 500 }
    )
  }
}
