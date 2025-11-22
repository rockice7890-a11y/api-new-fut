import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization')
    const { requiredRole, adminKey } = await request.json()

    if (!authHeader) {
      return NextResponse.json(
        { 
          valid: false, 
          message: 'مطلوب Authorization header' 
        },
        { status: 401 }
      )
    }

    const token = authHeader.replace('Bearer ', '')

    try {
      // فك تشفير token بسيط (يجب استخدام JWT الحقيقي في الإنتاج)
      const decoded = JSON.parse(atob(token))
      
      // التحقق من صحة البيانات
      if (!decoded.adminKey || !decoded.role || !decoded.timestamp || !decoded.expires) {
        return NextResponse.json(
          { 
            valid: false, 
            message: 'Token غير صحيح' 
          },
          { status: 401 }
        )
      }

      // التحقق من انتهاء صلاحية token
      if (Date.now() > decoded.expires) {
        return NextResponse.json(
          { 
            valid: false, 
            message: 'انتهت صلاحية token' 
          },
          { status: 401 }
        )
      }

      // التحقق من الدور المطلوب
      if (requiredRole && decoded.role !== requiredRole) {
        return NextResponse.json(
          { 
            valid: false, 
            message: 'دور غير صحيح' 
          },
          { status: 403 }
        )
      }

      // التحقق من المفتاح الإداري (إذا كان مطلوباً)
      if (adminKey && decoded.adminKey !== adminKey) {
        return NextResponse.json(
          { 
            valid: false, 
            message: 'مفتاح إداري غير صحيح' 
          },
          { status: 403 }
        )
      }

      return NextResponse.json({
        valid: true,
        user: {
          adminKey: decoded.adminKey,
          role: decoded.role,
          timestamp: decoded.timestamp
        }
      })

    } catch (decodeError) {
      console.error('Token decode error:', decodeError)
      return NextResponse.json(
        { 
          valid: false, 
          message: 'فشل في فك تشفير token' 
        },
        { status: 401 }
      )
    }

  } catch (error) {
    console.error('Token verification error:', error)
    return NextResponse.json(
      { 
        valid: false, 
        message: 'خطأ في التحقق من token' 
      },
      { status: 500 }
    )
  }
}
