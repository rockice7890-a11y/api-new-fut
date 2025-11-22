/**
 * Verify Admin Token API
 * التحقق من صحة توكن المدير
 */

import { NextRequest, NextResponse } from 'next/server'
import { verifyAdminToken } from '@/lib/admin-auth'

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get('authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        {
          status: 'error',
          message: 'رمز الدخول مفقود'
        },
        { status: 401 }
      )
    }

    const token = authHeader.substring(7)
    const verification = verifyAdminToken(token)

    if (!verification.valid) {
      return NextResponse.json(
        {
          status: 'error',
          message: verification.message
        },
        { status: 401 }
      )
    }

    return NextResponse.json({
      status: 'success',
      message: 'رمز صالح',
      data: {
        admin: {
          email: verification.payload!.email,
          role: verification.payload!.role
        }
      }
    })

  } catch (error: any) {
    console.error('Token verification error:', error)
    return NextResponse.json(
      {
        status: 'error',
        message: 'حدث خطأ في التحقق'
      },
      { status: 500 }
    )
  }
}
