import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { prisma } from "@/lib/prisma"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const [bookings, totalSpent, reviews, wishlist] = await Promise.all([
      prisma.booking.count({ where: { userId: user.id } }),
      prisma.booking.aggregate({
        where: { userId: user.id, status: "COMPLETED" },
        _sum: { totalPrice: true },
      }),
      prisma.review.count({ where: { userId: user.id } }),
      prisma.wishlist.count({ where: { userId: user.id } }),
    ])

    return apiResponse.success(
      {
        totalBookings: bookings,
        totalSpent: totalSpent._sum.totalPrice || 0,
        totalReviews: reviews,
        wishlistCount: wishlist,
      },
      "Analytics retrieved",
    )
  } catch (error) {
    return apiResponse.error(error instanceof Error ? error.message : String(error))
  }
}
