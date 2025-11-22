import type { NextRequest } from "next/server"
import { autoCheckoutService } from "@/lib/services/auto-checkout.service"
import { authenticate } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    const body = await request.json()
    const { taskId, hotelId } = body

    if (!taskId || !hotelId) {
      return apiResponse.badRequest("معرفات المهمة والفندق مطلوبة")
    }

    // معالجة المغادرة
    const result = await autoCheckoutService.processAutoCheckout(taskId, user.id)

    return apiResponse.success(result, "تمت معالجة المغادرة التلقائية بنجاح")
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في معالجة المغادرة")
  }
}
