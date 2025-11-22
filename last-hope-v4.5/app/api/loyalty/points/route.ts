import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { prisma } from "@/lib/prisma"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const loyalty = await prisma.loyaltyPoint.findUnique({
      where: { userId: user.userId },
    })

    return apiResponse.success(loyalty || { points: 0, tier: "BRONZE", totalEarned: 0 }, "Loyalty points retrieved")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
