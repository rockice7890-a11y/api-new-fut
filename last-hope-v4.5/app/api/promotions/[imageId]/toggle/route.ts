import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { PromotionService } from "@/lib/services/promotion.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function PUT(request: NextRequest, { params }: { params: Promise<{ imageId: string }> }) {
  try {
    const token = request.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized()
    }

    const { isActive } = await request.json()
    const { imageId } = await params

    const promotion = await PromotionService.togglePromotionVisibility(imageId, isActive)

    return apiResponse.success({ promotion }, "تم تحديث حالة العرض بنجاح")
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
