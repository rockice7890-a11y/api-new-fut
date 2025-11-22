import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { WishlistService } from "@/lib/services/wishlist.service"

export const dynamic = 'force-dynamic'

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ hotelId: string }> }) {
  try {
    const user = await authenticateRequest(request)
    if (!user) return apiResponse.unauthorized()

    const { hotelId } = await params
    await WishlistService.removeFromWishlist(user.id, hotelId)
    return apiResponse.success(null, "Removed from wishlist")
  } catch (error) {
    return apiResponse.error(error instanceof Error ? error.message : String(error))
  }
}
