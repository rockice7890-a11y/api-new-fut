import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

// ===========================================
// SYSTEM MONITORING & ALERTS APIs
// مراقبة النظام والإشعارات - APIs للمديرين
// ===========================================

export const dynamic = 'force-dynamic'

// Schema للتحقق من البيانات
const AlertSchema = z.object({
  alertType: z.enum(['warning', 'error', 'info', 'success']),
  title: z.string(),
  message: z.string(),
  priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  targetRoles: z.array(z.string()).default(['ADMIN']),
  targetUsers: z.array(z.string()).optional(),
  expiresAt: z.string().datetime().optional()
})

const PerformanceQuerySchema = z.object({
  hotelId: z.string().optional(),
  metricName: z.string().optional(),
  moduleName: z.string().optional(),
  status: z.string().optional(),
  timeRange: z.string().default('24h'), // 1h, 24h, 7d, 30d
  page: z.string().transform(Number).default('1'),
  pageSize: z.string().transform(Number).default('50')
})

// ===========================================
// GET - جلب التنبيهات والإحصائيات
// ===========================================
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  const rateLimitResult = await rateLimit(`monitoring:${auth.payload.userId}`, 60, 60000) // 60 طلب/دقيقة
  if (!rateLimitResult.success) {
    return NextResponse.json(failResponse(null, "تم تجاوز حد الطلبات المسموح", "RATE_LIMIT_EXCEEDED"), { status: 429 })
  }

  try {
    const searchParams = req.nextUrl.searchParams
    const endpoint = searchParams.get("type") || "alerts"

    switch (endpoint) {
      case "performance": {
        const queryData = PerformanceQuerySchema.parse({
          hotelId: searchParams.get("hotelId") || undefined,
          metricName: searchParams.get("metricName") || undefined,
          moduleName: searchParams.get("moduleName") || undefined,
          status: searchParams.get("status") || undefined,
          timeRange: searchParams.get("timeRange") || "24h",
          page: searchParams.get("page") || "1",
          pageSize: searchParams.get("pageSize") || "50"
        })

        // تحديد الفترة الزمنية
        const now = new Date()
        let startTime = new Date()
        
        switch (queryData.timeRange) {
          case '1h':
            startTime.setHours(now.getHours() - 1)
            break
          case '24h':
            startTime.setDate(now.getDate() - 1)
            break
          case '7d':
            startTime.setDate(now.getDate() - 7)
            break
          case '30d':
            startTime.setDate(now.getDate() - 30)
            break
        }

        const where: any = {
          measuredAt: {
            gte: startTime,
            lte: now
          }
        }

        if (queryData.hotelId) where.hotelId = queryData.hotelId
        if (queryData.metricName) where.metricName = queryData.metricName
        if (queryData.moduleName) where.moduleName = queryData.moduleName
        if (queryData.status) where.status = queryData.status

        const performance = await prisma.performanceMonitor.findMany({
          where,
          orderBy: { measuredAt: 'desc' },
          skip: (queryData.page - 1) * queryData.pageSize,
          take: queryData.pageSize
        })

        const total = await prisma.performanceMonitor.count({ where })

        // إحصائيات الأداء
        const stats = await prisma.performanceMonitor.groupBy({
          by: ['metricName', 'status'],
          where,
          _count: { metricName: true },
          _avg: { value: true },
          _max: { value: true },
          _min: { value: true }
        })

        return NextResponse.json(
          successResponse(
            {
              performance,
              stats,
              total,
              timeRange: queryData.timeRange,
              page: queryData.page,
              pageSize: queryData.pageSize
            },
            "تم جلب إحصائيات الأداء بنجاح"
          ),
        )
      }

      case "operation-logs": {
        const moduleId = searchParams.get("moduleId")
        const page = Number(searchParams.get("page") || "1")
        const pageSize = Number(searchParams.get("pageSize") || "20")

        if (!moduleId) {
          return NextResponse.json(failResponse(null, "معرف الوحدة مطلوب", "MODULE_ID_REQUIRED"), { status: 400 })
        }

        // التحقق من الصلاحيات
        if (auth.payload.role === 'HOTEL_MANAGER') {
          const operationalModule = await prisma.operationalModule.findFirst({
            where: {
              id: moduleId,
              hotelId: await prisma.hotel.findFirst({
                where: { managerId: auth.payload.userId },
                select: { id: true }
              }).then(h => h?.id)
            }
          })

          if (!operationalModule) {
            return NextResponse.json(failResponse(null, "صلاحيات غير كافية", "INSUFFICIENT_PERMISSIONS"), { status: 403 })
          }
        }

        const logs = await prisma.operationLog.findMany({
          where: { moduleId },
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
          },
          orderBy: { createdAt: 'desc' },
          skip: (page - 1) * pageSize,
          take: pageSize
        })

        const total = await prisma.operationLog.count({ where: { moduleId } })

        return NextResponse.json(
          successResponse(
            {
              logs,
              total,
              page,
              pageSize,
              hasMore: (page * pageSize) < total
            },
            "تم جلب سجل العمليات بنجاح"
          ),
        )
      }

      default: {
        // جلب التنبيهات
        const page = Number(searchParams.get("page") || "1")
        const pageSize = Number(searchParams.get("pageSize") || "20")
        const priority = searchParams.get("priority")
        const isActive = searchParams.get("isActive")

        const where: any = {}

        // فلترة حسب الأولوية
        if (priority) where.priority = priority
        
        // فلترة حسب الحالة
        if (isActive !== null) where.isActive = isActive === 'true'

        // فلترة حسب المستخدم (إذا لم يكن admin)
        if (auth.payload.role !== 'ADMIN' && auth.payload.adminLevel !== 'SUPER_ADMIN') {
          where.OR = [
            { targetRoles: { has: auth.payload.role } },
            { targetUsers: { has: auth.payload.userId } }
          ]
        }

        const alerts = await prisma.operationalAlert.findMany({
          where,
          orderBy: [
            { priority: 'desc' },
            { createdAt: 'desc' }
          ],
          skip: (page - 1) * pageSize,
          take: pageSize
        })

        const total = await prisma.operationalAlert.count({ where })

        // إحصائيات التنبيهات
        const stats = await prisma.operationalAlert.groupBy({
          by: ['priority', 'isActive'],
          where: {
            ...where,
            // استثناء التنبيهات المنتهية الصلاحية
            OR: [
              { expiresAt: null },
              { expiresAt: { gte: new Date() } }
            ]
          },
          _count: { priority: true }
        })

        return NextResponse.json(
          successResponse(
            {
              alerts,
              stats: stats.reduce((acc, stat) => {
                const key = `${stat.priority}_${stat.isActive ? 'active' : 'inactive'}`
                acc[key] = stat._count.priority
                return acc
              }, {} as Record<string, number>),
              total,
              page,
              pageSize,
              hasMore: (page * pageSize) < total
            },
            "تم جلب التنبيهات بنجاح"
          ),
        )
      }
    }
  } catch (error: any) {
    console.error("[Monitoring Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "فشل في جلب بيانات المراقبة", "MONITORING_ERROR"), 
      { status: 500 }
    )
  }
}

// ===========================================
// POST - إنشاء تنبيه أو إلغاء تنبيه
// ===========================================
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  const rateLimitResult = await rateLimit(`alerts:${auth.payload.userId}`, 20, 60000) // 20 تنبيه/دقيقة
  if (!rateLimitResult.success) {
    return NextResponse.json(failResponse(null, "تم تجاوز حد التنبيهات المسموح", "RATE_LIMIT_EXCEEDED"), { status: 429 })
  }

  try {
    const body = await req.json()
    const validated = AlertSchema.parse(body)

    // إنشاء التنبيه
    const alert = await prisma.operationalAlert.create({
      data: {
        hotelId: auth.payload.role === 'HOTEL_MANAGER' ? 
          await prisma.hotel.findFirst({
            where: { managerId: auth.payload.userId },
            select: { id: true }
          }).then(h => h?.id) : null,
        alertType: validated.alertType,
        title: validated.title,
        message: validated.message,
        priority: validated.priority,
        targetRoles: validated.targetRoles as any,
        targetUsers: validated.targetUsers as any || [],
        expiresAt: validated.expiresAt ? new Date(validated.expiresAt) : null
      }
    })

    return NextResponse.json(
      successResponse(
        alert,
        "تم إنشاء التنبيه بنجاح"
      ),
      { status: 201 }
    )
  } catch (error: any) {
    console.error("[Create Alert Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "فشل في إنشاء التنبيه", "CREATE_ALERT_ERROR"), 
      { status: 500 }
    )
  }
}

// ===========================================
// PUT - إلغاء أو قراءة تنبيه
// ===========================================
export async function PUT(req: NextRequest) {
  const auth = await withAuth(req, ["ADMIN", "HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  const rateLimitResult = await rateLimit(`alerts_update:${auth.payload.userId}`, 30, 60000) // 30 تحديث/دقيقة
  if (!rateLimitResult.success) {
    return NextResponse.json(failResponse(null, "تم تجاوز حد التحديثات المسموح", "RATE_LIMIT_EXCEEDED"), { status: 429 })
  }

  try {
    const body = await req.json()
    const { alertId, action, reason } = body

    if (!alertId || !action) {
      return NextResponse.json(
        failResponse(null, "معرف التنبيه والإجراء مطلوبان", "MISSING_PARAMETERS"), 
        { status: 400 }
      )
    }

    const where: any = { id: alertId }

    // فلترة حسب الصلاحيات
    if (auth.payload.role !== 'ADMIN' && auth.payload.adminLevel !== 'SUPER_ADMIN') {
      where.OR = [
        { targetRoles: { has: auth.payload.role } },
        { targetUsers: { has: auth.payload.userId } }
      ]
    }

    let updatedAlert

    switch (action) {
      case 'dismiss': {
        updatedAlert = await prisma.operationalAlert.update({
          where,
          data: {
            isActive: false,
            dismissedBy: auth.payload.userId,
            dismissedAt: new Date()
          }
        })
        break
      }

      case 'mark_read': {
        updatedAlert = await prisma.operationalAlert.update({
          where,
          data: {
            isRead: true
          }
        })
        break
      }

      default:
        return NextResponse.json(
          failResponse(null, "إجراء غير مدعوم", "UNSUPPORTED_ACTION"), 
          { status: 400 }
        )
    }

    // تسجيل العملية
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: `ALERT_${action.toUpperCase()}`,
        resource: 'OperationalAlert',
        resourceId: alertId,
        ipAddress: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown',
        userAgent: req.headers.get('user-agent') || undefined,
        method: 'PUT',
        newValues: JSON.stringify({ 
          action, 
          reason, 
          originalAlert: updatedAlert 
        })
      }
    })

    return NextResponse.json(
      successResponse(
        updatedAlert,
        `تم ${action === 'dismiss' ? 'إلغاء' : 'قراءة'} التنبيه بنجاح`
      ),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Update Alert Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "فشل في تحديث التنبيه", "UPDATE_ALERT_ERROR"), 
      { status: 500 }
    )
  }
}