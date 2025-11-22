import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { DiscountService } from "@/lib/services/discount.service"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const { hotelId, code, bookingDetails } = await request.json()

    const validation = await DiscountService.validateDiscount(hotelId, code, bookingDetails)

    if (!validation.valid) {
      return apiResponse.badRequest(validation.error)
    }

    const discountAmount = await DiscountService.calculateDiscount(validation.discount, bookingDetails.totalPrice)

    return apiResponse.success(
      {
        discount: validation.discount,
        discountAmount,
      },
      "Discount validated",
    )
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
