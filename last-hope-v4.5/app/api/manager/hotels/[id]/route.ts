import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await withAuth(req, ["HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params
    const body = await req.json()

    const hotel = await prisma.hotel.findUnique({ where: { id } })

    if (!hotel) {
      return NextResponse.json(failResponse(null, "Hotel not found", "NOT_FOUND"), { status: 404 })
    }

    if (hotel.managerId !== auth.payload.userId) {
      return NextResponse.json({ status: "error", message: "Forbidden" }, { status: 403 })
    }

    const updated = await prisma.hotel.update({
      where: { id },
      data: body,
    })

    return NextResponse.json(successResponse(updated, "Hotel updated successfully"))
  } catch (error: any) {
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
