import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params

    const booking = await prisma.booking.findUnique({
      where: { id },
    })

    if (!booking) {
      return NextResponse.json(failResponse(null, "Booking not found", "NOT_FOUND"), { status: 404 })
    }

    // Verify ownership
    if (booking.userId !== auth.payload.userId) {
      return NextResponse.json({ status: "error", message: "Forbidden" }, { status: 403 })
    }

    // Check if booking can be cancelled (not already cancelled or completed)
    if (booking.status === "CANCELLED" || booking.status === "COMPLETED") {
      return NextResponse.json(failResponse(null, "Cannot cancel booking with status: " + booking.status), {
        status: 400,
      })
    }

    const updated = await prisma.booking.update({
      where: { id },
      data: { status: "CANCELLED" },
      include: { hotel: true, room: true },
    })

    return NextResponse.json(successResponse(updated, "Booking cancelled successfully"))
  } catch (error: any) {
    console.error("[Cancel Booking Error]", error)
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
