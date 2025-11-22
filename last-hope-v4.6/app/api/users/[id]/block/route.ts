import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import { userBlockService } from "@/lib/services/user-block.service"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user || user.role !== "ADMIN") {
      return NextResponse.json(apiResponse.error("Unauthorized"), { status: 403 })
    }

    const { reason, description } = await req.json()
    const { id: userId } = await params

    const blocked = await userBlockService.blockUser(userId, reason, description, user.userId)

    return NextResponse.json(apiResponse.success(blocked, "User blocked successfully"), { status: 200 })
  } catch (error) {
    return NextResponse.json(apiResponse.error("Failed to block user"), { status: 500 })
  }
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user || user.role !== "ADMIN") {
      return NextResponse.json(apiResponse.error("Unauthorized"), { status: 403 })
    }

    const { id: userId } = await params
    const unblocked = await userBlockService.unblockUser(userId)

    return NextResponse.json(apiResponse.success(unblocked, "User unblocked successfully"), { status: 200 })
  } catch (error) {
    return NextResponse.json(apiResponse.error("Failed to unblock user"), { status: 500 })
  }
}
