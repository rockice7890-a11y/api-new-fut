import type { NextRequest } from "next/server"
import { autoCheckoutService } from "@/lib/services/auto-checkout.service"
import { authenticate } from "@/lib/middleware"
import { authorize } from "@/lib/middleware/permissions.middleware"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    // التحقق من المصادقة والصلاحيات
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    await authorize(user.id, "ADMIN")

    // جدولة المغادرة التلقائية
    await autoCheckoutService.scheduleAutoCheckouts()

    return apiResponse.success({ message: "تم جدولة المغادرة التلقائية بنجاح" }, "تم جدولة المغادرة التلقائية")
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في جدولة المغادرة")
  }
}
