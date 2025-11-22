import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

// ===========================================
// OPERATIONAL MANAGEMENT APIs
// إدارة العمليات - APIs شاملة للتحكم الإداري
// ===========================================

export const dynamic = 'force-dynamic'

// Schema للتحقق من البيانات
const OperationalControlSchema = z.object({
  moduleName: z.string(),
  action: z.enum(['LOCK', 'UNLOCK', 'HIDE', 'SHOW', 'SUSPEND', 'ACTIVATE', 'MAINTENANCE_MODE', 'EMERGENCY_MODE']),
  reason: z.string().optional(),
  message: z.string().optional(),
  controlLevel: z.enum(['SOFT_LOCK', 'HARD_LOCK', 'DEPARTMENTS', 'ROLES', 'GLOBAL']).default('SOFT_LOCK'),
  allowedRoles: z.array(z.string()).optional(),
  restrictedRoles: z.array(z.string()).optional(),
  unlockAt: z.string().datetime().optional(),
  adminOnly: z.boolean().default(false),
  allowOverride: z.boolean().default(false)
})

// Schema لاستعلام العمليات
const OperationsQuerySchema = z.object({
  hotelId: z.string().optional(),
  status: z.string().optional(),
  operationType: z.string().optional(),
  page: z.string().transform(Number).default('1'),
  pageSize: z.string().transform(Number).default('20')
})

// ===========================================
// GET - قائمة جميع العمليات الحالية
// ===========================================
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  const rateLimitResult = await rateLimit(`operations:${auth.payload.userId}`, 30, 60000) // 30 طلب/دقيقة
  if (!rateLimitResult.success) {
    return NextResponse.json(failResponse(null, "تم تجاوز حد الطلبات المسموح", "RATE_LIMIT_EXCEEDED"), { status: 429 })
  }

  try {
    const searchParams = req.nextUrl.searchParams
    const queryData = OperationsQuerySchema.parse({
      hotelId: searchParams.get("hotelId") || undefined,
      status: searchParams.get("status") || undefined,
      operationType: searchParams.get("operationType") || undefined,
      page: searchParams.get("page") || "1",
      pageSize: searchParams.get("pageSize") || "20"
    })

    const where: any = {}

    // فلترة حسب الفندق (إذا لم يكن SUPER_ADMIN)
    if (auth.payload.role !== 'ADMIN' && auth.payload.adminLevel !== 'SUPER_ADMIN') {
      if (auth.payload.role === 'HOTEL_MANAGER') {
        // مدير الفندق يرى عمليات فندقه فقط
        const userHotels = await prisma.hotel.findMany({
          where: { managerId: auth.payload.userId },
          select: { id: true }
        })
        where.hotelId = { in: userHotels.map(h => h.id) }
      } else {
        // المستخدمون العاديون لا يرون أي عمليات
        return NextResponse.json(failResponse(null, "صلاحيات غير كافية", "INSUFFICIENT_PERMISSIONS"), { status: 403 })
      }
    } else {
      // الأدمن يرى الكل أو عمليات الفندق المحدد
      if (queryData.hotelId) {
        where.hotelId = queryData.hotelId
      }
    }

    // فلترة حسب الحالة
    if (queryData.status) {
      where.status = queryData.status
    }

    // فلترة حسب نوع العملية
    if (queryData.operationType) {
      where.operationType = queryData.operationType
    }

    const operations = await prisma.operationalModule.findMany({
      where,
      include: {
        operationLogs: {
          take: 5,
          orderBy: { createdAt: 'desc' },
          include: {
            performedByUser: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true,
                role: true
              }
            }
          }
        }
      },
      orderBy: { updatedAt: 'desc' },
      skip: (queryData.page - 1) * queryData.pageSize,
      take: queryData.pageSize
    })

    const total = await prisma.operationalModule.count({ where })

    // إحصائيات العمليات
    const stats = await prisma.operationalModule.groupBy({
      by: ['status'],
      where,
      _count: { status: true }
    })

    return NextResponse.json(
      successResponse(
        {
          operations,
          stats: stats.reduce((acc, stat) => {
            acc[stat.status] = stat._count.status
            return acc
          }, {} as Record<string, number>),
          total,
          page: queryData.page,
          pageSize: queryData.pageSize,
          hasMore: (queryData.page * queryData.pageSize) < total
        },
        "تم جلب قائمة العمليات بنجاح"
      ),
    )
  } catch (error: any) {
    console.error("[Get Operations Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "فشل في جلب قائمة العمليات", "GET_OPERATIONS_ERROR"), 
      { status: 500 }
    )
  }
}

// ===========================================
// POST - التحكم في العمليات
// ===========================================
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  const rateLimitResult = await rateLimit(`operation_control:${auth.payload.userId}`, 10, 60000) // 10 عمليات/دقيقة
  if (!rateLimitResult.success) {
    return NextResponse.json(failResponse(null, "تم تجاوز حد العمليات المسموح", "RATE_LIMIT_EXCEEDED"), { status: 429 })
  }

  try {
    const body = await req.json()
    const validated = OperationalControlSchema.parse(body)

    // التحقق من الصلاحيات
    if (auth.payload.role === 'HOTEL_MANAGER') {
      // مدير الفندق يمكنه التحكم في فندقه فقط
      const hotel = await prisma.hotel.findFirst({
        where: { 
          id: validated.moduleName.startsWith('hotel_') ? validated.moduleName.replace('hotel_', '') : undefined,
          managerId: auth.payload.userId 
        }
      })
      
      if (!hotel) {
        return NextResponse.json(
          failResponse(null, "يمكنك التحكم في عمليات فندقك فقط", "INSUFFICIENT_HOTEL_PERMISSIONS"), 
          { status: 403 }
        )
      }
    }

    // البحث عن الوحدة أو إنشاؤها
    let operationalModule = await prisma.operationalModule.findFirst({
      where: { 
        moduleName: validated.moduleName,
        ...(auth.payload.role === 'HOTEL_MANAGER' && {
          hotelId: await prisma.hotel.findFirst({
            where: { managerId: auth.payload.userId },
            select: { id: true }
          }).then(h => h?.id)
        })
      }
    })

    const currentStatus = operationalModule?.status || 'ACTIVE'
    let newStatus = currentStatus

    // تحديد الحالة الجديدة حسب الإجراء
    switch (validated.action) {
      case 'LOCK':
        newStatus = 'LOCKED'
        break
      case 'UNLOCK':
        newStatus = 'ACTIVE'
        break
      case 'HIDE':
        newStatus = 'HIDDEN'
        break
      case 'SHOW':
        newStatus = 'ACTIVE'
        break
      case 'SUSPEND':
        newStatus = 'SUSPENDED'
        break
      case 'ACTIVATE':
        newStatus = 'ACTIVE'
        break
      case 'MAINTENANCE_MODE':
        newStatus = 'MAINTENANCE'
        break
      case 'EMERGENCY_MODE':
        newStatus = 'EMERGENCY'
        break
    }

    // إنشاء أو تحديث الوحدة
    if (!operationalModule) {
      operationalModule = await prisma.operationalModule.create({
        data: {
          moduleName: validated.moduleName,
          operationType: validated.moduleName.includes('BOOKING') ? 'BOOKING_SYSTEM' :
                        validated.moduleName.includes('PAYMENT') ? 'PAYMENT_SYSTEM' :
                        validated.moduleName.includes('ROOM') ? 'ROOM_MANAGEMENT' :
                        validated.moduleName.includes('STAFF') ? 'STAFF_MANAGEMENT' :
                        validated.moduleName.includes('FINANCIAL') ? 'FINANCIAL_SYSTEM' :
                        'BOOKING_SYSTEM',
          status: newStatus,
          controlLevel: validated.controlLevel,
          lockedBy: auth.payload.userId,
          lockedAt: new Date(),
          unlockAt: validated.unlockAt ? new Date(validated.unlockAt) : null,
          lastAction: validated.action as any,
          lockMessage: validated.message,
          adminOnly: validated.adminOnly,
          allowOverride: validated.allowOverride,
          requiredRole: auth.payload.role as any,
          restrictedRoles: validated.restrictedRoles as any || [],
          ...(auth.payload.role === 'HOTEL_MANAGER' && {
            hotelId: await prisma.hotel.findFirst({
              where: { managerId: auth.payload.userId },
              select: { id: true }
            }).then(h => h?.id)
          })
        }
      })
    } else {
      // تحديث الوحدة الموجودة
      operationalModule = await prisma.operationalModule.update({
        where: { id: operationalModule.id },
        data: {
          status: newStatus,
          controlLevel: validated.controlLevel,
          lockedBy: auth.payload.userId,
          lockedAt: new Date(),
          unlockAt: validated.unlockAt ? new Date(validated.unlockAt) : null,
          lastAction: validated.action as any,
          lockMessage: validated.message,
          adminOnly: validated.adminOnly,
          allowOverride: validated.allowOverride,
          restrictedRoles: validated.restrictedRoles as any || [],
          updatedAt: new Date()
        }
      })
    }

    // تسجيل العملية في السجل
    await prisma.operationLog.create({
      data: {
        moduleId: operationalModule.id,
        action: validated.action as any,
        performedBy: auth.payload.userId,
        reason: validated.reason,
        previousStatus: currentStatus as any,
        newStatus: newStatus as any,
        message: validated.message,
        ipAddress: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown',
        userAgent: req.headers.get('user-agent') || 'unknown',
        metadata: {
          controlLevel: validated.controlLevel,
          adminOnly: validated.adminOnly,
          allowOverride: validated.allowOverride
        }
      }
    })

    // إرسال إشعار للأدمن أو المستخدم المعني
    if (newStatus === 'EMERGENCY' || newStatus === 'MAINTENANCE') {
      await prisma.operationalAlert.create({
        data: {
          hotelId: operationalModule.hotelId,
          alertType: newStatus === 'EMERGENCY' ? 'error' : 'warning',
          title: `${validated.action} - ${validated.moduleName}`,
          message: validated.message || `تم ${validated.action === 'LOCK' ? 'قفل' : validated.action === 'UNLOCK' ? 'فتح' : validated.action} ${validated.moduleName}`,
          priority: newStatus === 'EMERGENCY' ? 'critical' : 'high',
          targetRoles: ['ADMIN', 'HOTEL_MANAGER']
        }
      })
    }

    return NextResponse.json(
      successResponse(
        {
          module: operationalModule,
          action: validated.action,
          status: newStatus,
          timestamp: new Date().toISOString()
        },
        `تم تنفيذ العملية ${validated.action} بنجاح`
      ),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Control Operation Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "فشل في تنفيذ العملية", "CONTROL_OPERATION_ERROR"), 
      { status: 500 }
    )
  }
}