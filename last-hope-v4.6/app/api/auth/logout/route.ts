import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { addSecurityHeaders } from "@/lib/security"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"
import { verifyToken } from "@/lib/auth"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"

    const authHeader = req.headers.get("authorization")
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Unauthorized", code: "NO_TOKEN" },
          { status: 401 },
        ),
      )
    }

    const token = authHeader.substring(7)
    const decoded = verifyToken(token)

    if (!decoded) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Invalid token", code: "INVALID_TOKEN" },
          { status: 401 },
        ),
      )
    }

    const userId = decoded.userId as string

    await logAuditEvent(AuditAction.USER_LOGOUT, userId, { email: decoded.email }, clientIP)

    const response = addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          message: "Logged out successfully",
          data: { userId },
        },
        { status: 200 },
      ),
    )

    response.cookies.set("refreshToken", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 0,
    })

    return response
  } catch (error: any) {
    console.error("[Logout Error]", error)
    return addSecurityHeaders(
      NextResponse.json({ status: "error", message: "Logout failed" }, { status: 500 }),
    )
  }
}
