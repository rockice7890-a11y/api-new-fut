import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await withAuth(req, ["ADMIN"])
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params
    const { role } = await req.json()

    if (!["USER", "HOTEL_MANAGER", "ADMIN"].includes(role)) {
      return NextResponse.json(failResponse(null, "Invalid role", "INVALID_ROLE"), { status: 400 })
    }

    const user = await prisma.user.update({
      where: { id },
      data: { role },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
      },
    })

    return NextResponse.json(successResponse(user, "User role updated successfully"))
  } catch (error: any) {
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
