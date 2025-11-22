import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import { staffNotificationService } from "@/lib/services/staff-notification.service"
import type { StaffNotificationType } from "@prisma/client"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const notificationSchema = z.object({
  hotelId: z.string(),
  recipientId: z.string(),
  type: z.enum(['URGENT', 'BOOKING_ALERT', 'MAINTENANCE', 'STAFF_MEETING', 'SHIFT_UPDATE', 'GENERAL']),
  subject: z.string(),
  message: z.string(),
  priority: z.string().optional(),
})

export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user || (user.role !== "HOTEL_MANAGER" && user.role !== "ADMIN")) {
      return apiResponse.forbidden()
    }

    const data = notificationSchema.parse(await req.json())

    const notification = await staffNotificationService.sendNotification(
      data.hotelId,
      user.userId,
      data.recipientId,
      data.type,
      data.subject,
      data.message,
      data.priority,
    )

    return apiResponse.success(notification, "Notification sent successfully")
  } catch (error) {
    return apiResponse.error("Failed to send notification")
  }
}

export async function GET(req: NextRequest) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized()
    }

    const page = Number.parseInt(req.nextUrl.searchParams.get("page") || "1")
    const pageSize = Number.parseInt(req.nextUrl.searchParams.get("pageSize") || "10")
    const skip = (page - 1) * pageSize
    const unreadOnly = req.nextUrl.searchParams.get("unreadOnly") === "true"

    let notifications
    if (unreadOnly) {
      notifications = await staffNotificationService.getUnreadNotifications(user.userId)
    } else {
      notifications = await staffNotificationService.getStaffNotifications(user.userId, skip, pageSize)
    }

    return apiResponse.success({ notifications }, "Notifications retrieved")
  } catch (error) {
    return apiResponse.error("Failed to retrieve notifications")
  }
}
