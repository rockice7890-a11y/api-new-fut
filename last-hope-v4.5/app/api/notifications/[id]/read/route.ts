import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { NotificationService } from "@/lib/services/notification.service"

export const dynamic = 'force-dynamic'

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const { id } = await params
    const notification = await NotificationService.markAsRead(id)
    return apiResponse.success(notification, "Notification marked as read")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
