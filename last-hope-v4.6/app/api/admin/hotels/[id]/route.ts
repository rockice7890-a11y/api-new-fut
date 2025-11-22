import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await withAuth(req, ["ADMIN"])
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params

    const hotel = await prisma.hotel.findUnique({ where: { id } })
    if (!hotel) {
      return NextResponse.json(failResponse(null, "Hotel not found", "NOT_FOUND"), { status: 404 })
    }

    await prisma.hotel.delete({ where: { id } })

    return NextResponse.json(successResponse(null, "Hotel deleted successfully"))
  } catch (error: any) {
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
