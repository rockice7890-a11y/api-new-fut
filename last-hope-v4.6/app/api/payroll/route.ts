import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import { payrollService } from "@/lib/services/payroll.service"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user || user.role !== "HOTEL_MANAGER") {
      return apiResponse.forbidden()
    }

    // Get hotel managed by user
    const page = Number.parseInt(req.nextUrl.searchParams.get("page") || "1")
    const pageSize = Number.parseInt(req.nextUrl.searchParams.get("pageSize") || "10")
    const skip = (page - 1) * pageSize

    // Get hotelId from manager's hotels
    const hotelId = req.nextUrl.searchParams.get("hotelId")

    if (!hotelId) {
      return apiResponse.badRequest("Hotel ID required")
    }

    const payroll = await payrollService.getHotelPayroll(hotelId, skip, pageSize)

    return apiResponse.success({ payroll, page, pageSize }, "Payroll retrieved")
  } catch (error) {
    return apiResponse.error("Failed to retrieve payroll")
  }
}
