import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { WishlistService } from "@/lib/services/wishlist.service"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const wishlist = await WishlistService.getUserWishlist(user.id)
    return apiResponse.success(wishlist, "Wishlist retrieved successfully")
  } catch (error) {
    return apiResponse.error(error instanceof Error ? error.message : String(error))
  }
}

export async function POST(request: NextRequest) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const { hotelId } = await request.json()
    const result = await WishlistService.addToWishlist(user.id, hotelId)

    return apiResponse.success(result, "Added to wishlist")
  } catch (error) {
    return apiResponse.error(error instanceof Error ? error.message : String(error))
  }
}
