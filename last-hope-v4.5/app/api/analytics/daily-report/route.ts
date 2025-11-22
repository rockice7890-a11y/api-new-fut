import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import prisma from "@/lib/prisma"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized("Unauthorized")
    }

    const hotelId = req.nextUrl.searchParams.get("hotelId")
    const date = req.nextUrl.searchParams.get("date")

    if (!hotelId || !date) {
      return apiResponse.badRequest("hotelId and date are required")
    }

    const report = await prisma.dailyBookingReport.findFirst({
      where: {
        hotelId,
        date: new Date(date),
      },
    })

    return apiResponse.success(report, "Daily report retrieved")
  } catch (error) {
    return apiResponse.error("Failed to retrieve report")
  }
}
