import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createNotificationSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  // Only admins and hotel managers can create notifications
  if (!['ADMIN', 'HOTEL_MANAGER'].includes(auth.payload.role)) {
    return NextResponse.json(
      failResponse(null, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS"),
      { status: 403 }
    )
  }

  try {
    const body = await req.json()
    const validated = createNotificationSchema.parse(body)

    // Create notification
    const notification = await prisma.notification.create({
      data: {
        userId: validated.userId,
        type: validated.type,
        title: validated.title,
        message: validated.message,
        data: validated.data,
      },
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
            email: true,
          },
        },
      },
    })

    return NextResponse.json(
      successResponse(notification, "Notification created successfully"),
      { status: 201 }
    )
  } catch (error: any) {
    console.error("[Create Notification Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create notification", "CREATE_NOTIFICATION_ERROR"), 
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const type = searchParams.get("type")
    const isRead = searchParams.get("read")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Number.parseInt(searchParams.get("pageSize") || "20")

    const where: any = { userId: auth.payload.userId }
    if (type) where.type = type
    if (isRead !== null) where.read = isRead === 'true'

    const notifications = await prisma.notification.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.notification.count({ where })
    const unreadCount = await prisma.notification.count({
      where: {
        userId: auth.payload.userId,
        read: false,
      },
    })

    return NextResponse.json(
      successResponse(
        {
          notifications,
          total,
          unreadCount,
          page,
          pageSize,
          hasMore: (page * pageSize) < total,
        },
        "Notifications retrieved successfully"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Notifications Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch notifications", "FETCH_NOTIFICATIONS_ERROR"), 
      { status: 500 }
    )
  }
}

export async function PUT(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const { action, notificationIds } = body

    switch (action) {
      case 'mark_all_read':
        await prisma.notification.updateMany({
          where: {
            userId: auth.payload.userId,
            read: false,
          },
          data: {
            read: true,
          },
        })

        return NextResponse.json(
          successResponse(null, "All notifications marked as read"),
          { status: 200 }
        )

      case 'mark_selected_read':
        if (!notificationIds || !Array.isArray(notificationIds)) {
          return NextResponse.json(
            failResponse(null, "Notification IDs are required", "INVALID_REQUEST"),
            { status: 400 }
          )
        }

        await prisma.notification.updateMany({
          where: {
            id: { in: notificationIds },
            userId: auth.payload.userId,
          },
          data: {
            read: true,
          },
        })

        return NextResponse.json(
          successResponse(null, "Selected notifications marked as read"),
          { status: 200 }
        )

      case 'delete_selected':
        if (!notificationIds || !Array.isArray(notificationIds)) {
          return NextResponse.json(
            failResponse(null, "Notification IDs are required", "INVALID_REQUEST"),
            { status: 400 }
          )
        }

        await prisma.notification.deleteMany({
          where: {
            id: { in: notificationIds },
            userId: auth.payload.userId,
          },
        })

        return NextResponse.json(
          successResponse(null, "Selected notifications deleted"),
          { status: 200 }
        )

      case 'delete_all':
        await prisma.notification.deleteMany({
          where: {
            userId: auth.payload.userId,
          },
        })

        return NextResponse.json(
          successResponse(null, "All notifications deleted"),
          { status: 200 }
        )

      default:
        return NextResponse.json(
          failResponse(null, "Invalid action", "INVALID_ACTION"),
          { status: 400 }
        )
    }
  } catch (error: any) {
    console.error("[Update Notifications Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update notifications", "UPDATE_NOTIFICATIONS_ERROR"), 
      { status: 500 }
    )
  }
}
