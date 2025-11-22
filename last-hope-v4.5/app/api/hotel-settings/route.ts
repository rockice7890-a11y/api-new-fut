import type { NextRequest } from "next/server"
import { authenticate } from "@/lib/middleware"
import { prisma } from "@/lib/prisma"
import { apiResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const hotelSettingsSchema = z.object({
  checkInTime: z.string().optional(),
  checkOutTime: z.string().optional(),
  autoCheckoutEnabled: z.boolean().optional(),
  autoCheckoutTime: z.string().optional(),
  gracePeriodMinutes: z.number().optional(),
  realtimeUpdatesEnabled: z.boolean().optional(),
  autoSendInvoices: z.boolean().optional(),
  invoiceSendTime: z.string().optional(),
  taxRate: z.number().optional(),
  serviceFee: z.number().optional(),
  currencyCode: z.string().optional(),
})

export async function GET(request: NextRequest) {
  try {
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    const { searchParams } = new URL(request.url)
    const hotelId = searchParams.get("hotelId")

    if (!hotelId) {
      return apiResponse.badRequest("معرف الفندق مطلوب")
    }

    const settings = await prisma.hotelSettings.findUnique({
      where: { hotelId },
    })

    if (!settings) {
      return apiResponse.notFound("الإعدادات غير موجودة")
    }

    return apiResponse.success(settings, "تم استرجاع الإعدادات بنجاح")
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في استرجاع الإعدادات")
  }
}

export async function PUT(request: NextRequest) {
  try {
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    const body = await request.json()
    const { hotelId, ...updateData } = body

    if (!hotelId) {
      return apiResponse.badRequest("معرف الفندق مطلوب")
    }

    // التحقق من البيانات
    const validated = hotelSettingsSchema.parse(updateData)

    const settings = await prisma.hotelSettings.update({
      where: { hotelId },
      data: validated,
    })

    return apiResponse.success(settings, "تم تحديث الإعدادات بنجاح")
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في تحديث الإعدادات")
  }
}
