import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { addSecurityHeaders } from "@/lib/security"
import { verifyToken } from "@/lib/auth"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
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

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId as string },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        avatar: true,
        phone: true,
        bio: true,
        createdAt: true,
        updatedAt: true,
        preferences: true,
        userProfile: true,
      },
    })

    if (!user) {
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "User not found" }, { status: 404 }),
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          data: { user },
          message: "Profile retrieved successfully",
        },
        { status: 200 },
      ),
    )
  } catch (error: any) {
    console.error("[Profile Error]", error)
    return addSecurityHeaders(
      NextResponse.json({ status: "error", message: "Failed to retrieve profile" }, { status: 500 }),
    )
  }
}
