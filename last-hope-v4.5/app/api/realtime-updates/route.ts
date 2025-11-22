import type { NextRequest } from "next/server"
import { realtimeUpdateService } from "@/lib/services/realtime-updates.service"
import { authenticate } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    const { searchParams } = new URL(request.url)
    const hotelId = searchParams.get("hotelId")
    const resourceType = searchParams.get("resourceType")
    const resourceId = searchParams.get("resourceId")

    if (!hotelId) {
      return apiResponse.badRequest("معرف الفندق مطلوب")
    }

    let updates

    if (resourceType && resourceId) {
      updates = await realtimeUpdateService.getUpdatesForResource(hotelId, resourceType, resourceId)
    } else {
      updates = await realtimeUpdateService.getRecentUpdates(hotelId)
    }

    return apiResponse.success(updates, "تم استرجاع التحديثات بنجاح")
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في استرجاع التحديثات")
  }
}
