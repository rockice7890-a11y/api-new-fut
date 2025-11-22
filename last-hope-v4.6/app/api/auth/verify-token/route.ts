import { type NextRequest, NextResponse } from "next/server"
import { addSecurityHeaders } from "@/lib/security"
import { verifyToken } from "@/lib/auth"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization")
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Unauthorized", code: "NO_TOKEN", valid: false },
          { status: 401 },
        ),
      )
    }

    const token = authHeader.substring(7)
    const decoded = verifyToken(token)

    if (!decoded) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Invalid token", code: "INVALID_TOKEN", valid: false },
          { status: 401 },
        ),
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          valid: true,
          data: { userId: decoded.userId, email: decoded.email, role: decoded.role },
        },
        { status: 200 },
      ),
    )
  } catch (error: any) {
    return addSecurityHeaders(
      NextResponse.json(
        { status: "error", message: "Token verification failed", valid: false },
        { status: 500 },
      ),
    )
  }
}
