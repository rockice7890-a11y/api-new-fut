import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { GuestDetailsService } from "@/lib/services/guest-details.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest, { params }: { params: Promise<{ bookingId: string }> }) {
  try {
    const token = request.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized()
    }

    const { bookingId } = await params
    const guestDetails = await GuestDetailsService.getGuestDetails(bookingId)

    return apiResponse.success({ guestDetails }, "Guest details retrieved")
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ bookingId: string }> }) {
  try {
    const token = request.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized()
    }

    const data = await request.json()
    const { bookingId } = await params

    const guestDetails = await GuestDetailsService.saveGuestDetails(bookingId, user.userId, data)

    return apiResponse.success({ guestDetails }, "تم تحديث بيانات النزيل بنجاح")
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
