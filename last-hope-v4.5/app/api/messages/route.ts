import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { prisma } from "@/lib/prisma"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const bookingId = request.nextUrl.searchParams.get("bookingId")

    const messages = await prisma.message.findMany({
      where: {
        ...(bookingId && { bookingId }),
        OR: [{ userId: user.userId }],
      },
      include: { user: true, hotel: true },
      orderBy: { createdAt: "asc" },
      take: 100,
    })

    return apiResponse.success(messages, "Messages retrieved")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}

export async function POST(request: NextRequest) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const { hotelId, bookingId, message, senderType } = await request.json()

    const newMessage = await prisma.message.create({
      data: {
        userId: user.userId,
        hotelId,
        bookingId,
        message,
        senderType: senderType || "USER",
      },
      include: { user: true, hotel: true },
    })

    return apiResponse.success(newMessage, "Message sent")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
