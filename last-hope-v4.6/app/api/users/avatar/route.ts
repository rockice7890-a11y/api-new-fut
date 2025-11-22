import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { UserProfileService } from "@/lib/services/user-profile.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function PUT(request: NextRequest) {
  try {
    const token = request.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return NextResponse.json(apiResponse.error("Unauthorized"), { status: 401 })
    }

    const { avatarUrl } = await request.json()

    if (!avatarUrl) {
      return NextResponse.json(apiResponse.error("Avatar URL is required"), { status: 400 })
    }

    const updatedUser = await UserProfileService.updateUserAvatar(user.userId, avatarUrl)

    return NextResponse.json(apiResponse.success({ user: updatedUser }, "تم تحديث الصورة بنجاح"))
  } catch (error: any) {
    return NextResponse.json(apiResponse.error(error.message), { status: 400 })
  }
}
