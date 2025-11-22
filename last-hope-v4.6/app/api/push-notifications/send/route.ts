import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Schema for sending push notifications
const sendNotificationSchema = z.object({
  userId: z.string().optional(),
  title: z.string().min(1).max(100),
  body: z.string().min(1).max(500),
  type: z.enum([
    "BOOKING_CONFIRMED",
    "BOOKING_CANCELLED", 
    "REVIEW_RECEIVED",
    "SPECIAL_OFFER",
    "PAYMENT_REMINDER",
    "CHECK_IN_REMINDER",
    "SYSTEM_ALERT"
  ]),
  data: z.record(z.any()).optional(),
  priority: z.enum(["LOW", "NORMAL", "HIGH", "URGENT"]).default("NORMAL"),
  scheduledAt: z.string().datetime().optional(),
  expiresAt: z.string().datetime().optional()
})

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = sendNotificationSchema.parse(body)

    // Determine target users
    let targetUserIds: string[] = []

    if (validated.userId) {
      // Single user
      targetUserIds = [validated.userId]
    } else {
      // Get all active users (could be filtered further)
      const activeUsers = await prisma.user.findMany({
        where: {
          role: { in: ["USER", "GUEST"] }
        },
        select: {
          id: true
        }
      })
      targetUserIds = activeUsers.map(user => user.id)
    }

    const notifications = []
    const errors = []

    for (const userId of targetUserIds) {
      try {
        const notification = await prisma.pushNotification.create({
          data: {
            userId: userId,
            title: validated.title,
            body: validated.body,
            type: validated.type,
            priority: validated.priority,
            data: validated.data,
            scheduledAt: validated.scheduledAt ? new Date(validated.scheduledAt) : null,
            expiresAt: validated.expiresAt ? new Date(validated.expiresAt) : null,
            sentAt: validated.scheduledAt ? null : new Date() // Send immediately if not scheduled
          }
        })
        notifications.push(notification)
      } catch (error) {
        errors.push({ userId, error: error instanceof Error ? error.message : "Unknown error" })
      }
    }

    return successResponse({
      sent: notifications.length,
      errors: errors.length,
      notifications: notifications.map(n => ({
        id: n.id,
        userId: n.userId,
        title: n.title,
        body: n.body,
        type: n.type,
        priority: n.priority,
        scheduledAt: n.scheduledAt,
        sentAt: n.sentAt
      })),
      errorDetails: errors.length > 0 ? errors : undefined
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid notification data: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("Send notification error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to send notification", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}