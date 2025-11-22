import type { NextRequest } from "next/server"
import { autoCheckoutService } from "@/lib/services/auto-checkout.service"
import { authenticate } from "@/lib/middleware"
import { prisma } from "@/lib/prisma"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    // الحصول على الفندق التابع للمدير
    const hotel = await prisma.hotel.findFirst({
      where: { managerId: user.id },
    })

    if (!hotel) {
      return apiResponse.notFound("الفندق غير موجود")
    }

    const pending = await autoCheckoutService.getPendingCheckouts(hotel.id)

    return apiResponse.success(pending, "تم استرجاع المهام المعلقة بنجاح")
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في استرجاع المهام")
  }
}

export async function PUT(request: NextRequest) {
  try {
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    const body = await request.json()
    const { pendingCheckoutId, notes } = body

    if (!pendingCheckoutId) {
      return apiResponse.badRequest("معرف المهمة المعلقة مطلوب")
    }

    const confirmed = await autoCheckoutService.confirmCheckout(pendingCheckoutId, user.id, notes)

    return apiResponse.success(confirmed, "تم تأكيد المغادرة بنجاح")
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في تأكيد المغادرة")
  }
}
