import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { generateToken, verifyRefreshToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    const refreshToken = req.cookies.get("refreshToken")?.value

    if (!refreshToken) {
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "Refresh token missing" }, { status: 401 }),
      )
    }

    const payload = verifyRefreshToken(refreshToken)
    if (!payload) {
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "Invalid refresh token" }, { status: 401 }),
      )
    }

    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: { id: true, email: true, role: true },
    })

    if (!user) {
      return addSecurityHeaders(NextResponse.json({ status: "error", message: "User not found" }, { status: 404 }))
    }

    const newToken = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    })

    return addSecurityHeaders(
      NextResponse.json({ status: "success", data: { token: newToken }, message: "Token refreshed" }),
    )
  } catch (error) {
    console.error("[Refresh Token Error]", error)
    return addSecurityHeaders(NextResponse.json({ status: "error", message: "Token refresh failed" }, { status: 500 }))
  }
}
