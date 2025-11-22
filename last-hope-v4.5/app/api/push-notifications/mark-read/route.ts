import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Schema for marking notifications as read
const markAsReadSchema = z.object({
  notificationIds: z.array(z.string()).optional(),
  markAll: z.boolean().default(false),
  type: z.enum([
    "BOOKING_CONFIRMED",
    "BOOKING_CANCELLED", 
    "REVIEW_RECEIVED",
    "SPECIAL_OFFER",
    "PAYMENT_REMINDER",
    "CHECK_IN_REMINDER",
    "SYSTEM_ALERT"
  ]).optional()
})

export async function PUT(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = markAsReadSchema.parse(body)

    let updatedCount = 0

    if (validated.markAll) {
      // Mark all notifications as read
      const result = await prisma.pushNotification.updateMany({
        where: {
          userId: auth.payload.userId,
          isRead: false,
          isSent: true,
          ...(validated.type && { type: validated.type })
        },
        data: {
          isRead: true,
          readAt: new Date()
        }
      })
      updatedCount = result.count
    } else if (validated.notificationIds && validated.notificationIds.length > 0) {
      // Mark specific notifications as read
      const result = await prisma.pushNotification.updateMany({
        where: {
          id: { in: validated.notificationIds },
          userId: auth.payload.userId
        },
        data: {
          isRead: true,
          readAt: new Date()
        }
      })
      updatedCount = result.count
    } else {
      return NextResponse.json(
        failResponse(null, "Either notificationIds or markAll must be provided", "INVALID_INPUT"),
        { status: 400 }
      )
    }

    // Get updated statistics
    const unreadCount = await prisma.pushNotification.count({
      where: {
        userId: auth.payload.userId,
        isRead: false,
        isSent: true
      }
    })

    return successResponse({
      updated: updatedCount,
      unreadCount: unreadCount,
      message: updatedCount > 0 ? `${updatedCount} notifications marked as read` : "No notifications were updated"
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid input data: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("Mark notifications as read error:", error)
    return NextResponse.json(
      failResponse(null, "Failed to mark notifications as read", "INTERNAL_ERROR"),
      { status: 500 }
    )
  }
}