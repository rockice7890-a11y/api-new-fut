import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import { workingHoursService } from "@/lib/services/working-hours.service"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest, { params }: { params: Promise<{ hotelId: string }> }) {
  try {
    const { hotelId } = await params
    const hours = await workingHoursService.getWorkingHours(hotelId)

    return apiResponse.success(hours, "Working hours retrieved")
  } catch (error) {
    return apiResponse.error("Failed to retrieve working hours")
  }
}

export async function PUT(req: NextRequest, { params }: { params: Promise<{ hotelId: string }> }) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user || user.role !== "HOTEL_MANAGER") {
      return apiResponse.forbidden()
    }

    const { monday, tuesday, wednesday, thursday, friday, saturday, sunday, timezone } = await req.json()

    const { hotelId } = await params

    const hours = await workingHoursService.setWorkingHours(
      hotelId,
      {
        monday,
        tuesday,
        wednesday,
        thursday,
        friday,
        saturday,
        sunday,
      },
      timezone,
    )

    return apiResponse.success(hours, "Working hours updated")
  } catch (error) {
    return apiResponse.error("Failed to update working hours")
  }
}
