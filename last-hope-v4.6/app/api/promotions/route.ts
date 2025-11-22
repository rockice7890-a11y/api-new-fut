import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { PromotionService } from "@/lib/services/promotion.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const token = request.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized()
    }

    const { hotelId, ...data } = await request.json()

    if (!hotelId) {
      return apiResponse.badRequest("Hotel ID is required")
    }

    // Verify user is manager of this hotel
    // ... verification logic ...

    const promotion = await PromotionService.addPromotionImage(hotelId, data)

    return apiResponse.success({ promotion }, "تم إضافة صورة العرض بنجاح")
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const hotelId = searchParams.get("hotelId")
    const onlyActive = searchParams.get("onlyActive") !== "false"

    if (!hotelId) {
      return apiResponse.badRequest("Hotel ID is required")
    }

    const promotions = await PromotionService.getPromotionImages(hotelId, onlyActive)

    return apiResponse.success({ promotions }, "Promotions retrieved")
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
