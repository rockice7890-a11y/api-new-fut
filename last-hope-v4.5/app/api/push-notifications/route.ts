import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Schema for getting notifications
const getNotificationsSchema = z.object({
  limit: z.number().min(1).max(100).default(20),
  offset: z.number().min(0).default(0),
  type: z.enum([
    "BOOKING_CONFIRMED",
    "BOOKING_CANCELLED", 
    "REVIEW_RECEIVED",
    "SPECIAL_OFFER",
    "PAYMENT_REMINDER",
    "CHECK_IN_REMINDER",
    "SYSTEM_ALERT"
  ]).optional(),
  isRead: z.boolean().optional(),
  isSent: z.boolean().default(true),
  priority: z.enum(["LOW", "NORMAL", "HIGH", "URGENT"]).optional()
})

export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { searchParams } = new URL(req.url)
    const queryParams = {
      limit: parseInt(searchParams.get("limit") || "20"),
      offset: parseInt(searchParams.get("offset") || "0"),
      type: searchParams.get("type") || undefined,
      isRead: searchParams.get("isRead") === "true" ? true : 
              searchParams.get("isRead") === "false" ? false : undefined,
      isSent: searchParams.get("isSent") !== "false", // default true
      priority: searchParams.get("priority") || undefined
    }

    const validated = getNotificationsSchema.parse(queryParams)

    // Build where clause
    const where: any = {
      userId: auth.payload.userId
    }

    if (validated.type) {
      where.type = validated.type
    }

    if (validated.isRead !== undefined) {
      where.isRead = validated.isRead
    }

    if (validated.isSent) {
      where.isSent = true
    }

    if (validated.priority) {
      where.priority = validated.priority
    }

    // Get notifications
    const notifications = await prisma.pushNotification.findMany({
      where,
      orderBy: [
        { priority: 'desc' },
        { createdAt: 'desc' }
      ],
      take: validated.limit,
      skip: validated.offset
    })

    // Get total count for pagination
    const totalCount = await prisma.pushNotification.count({ where })

    // Get unread count
    const unreadCount = await prisma.pushNotification.count({
      where: {
        userId: auth.payload.userId,
        isRead: false,
        isSent: true
      }
    })

    // Get statistics
    const stats = await prisma.pushNotification.groupBy({
      by: ['type'],
      where: {
        userId: auth.payload.userId,
        isSent: true
      },
      _count: {
        type: true
      }
    })

    return successResponse({
      notifications: notifications.map(n => ({
        id: n.id,
        title: n.title,
        body: n.body,
        type: n.type,
        priority: n.priority,
        data: n.data,
        isRead: n.isRead,
        isSent: n.isSent,
        sentAt: n.sentAt,
        readAt: n.readAt,
        scheduledAt: n.scheduledAt,
        expiresAt: n.expiresAt,
        createdAt: n.createdAt
      })),
      pagination: {
        total: totalCount,
        limit: validated.limit,
        offset: validated.offset,
        hasMore: totalCount > (validated.offset + validated.limit)
      },
      summary: {
        unread: unreadCount,
        total: totalCount,
        byType: stats.reduce((acc, stat) => {
          acc[stat.type] = stat._count.type
          return acc
        }, {} as Record<string, number>)
      }
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid query parameters: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("Get notifications error:", error)
    return NextResponse.json(
      failResponse(null, "Failed to get notifications", "INTERNAL_ERROR"),
      { status: 500 }
    )
  }
}