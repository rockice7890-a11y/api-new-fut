import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await withAuth(req, ["HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params
    const body = await req.json()
    const { roomId, date, available, price } = body

    // Verify hotel ownership
    const hotel = await prisma.hotel.findUnique({ where: { id } })
    if (!hotel || hotel.managerId !== auth.payload.userId) {
      return NextResponse.json({ status: "error", message: "Forbidden" }, { status: 403 })
    }

    const inventory = await prisma.roomInventory.upsert({
      where: { roomId_date: { roomId, date: new Date(date) } },
      update: { available, price },
      create: {
        roomId,
        date: new Date(date),
        available,
        price,
      },
    })

    return NextResponse.json(successResponse(inventory, "Inventory updated successfully"))
  } catch (error: any) {
    console.error("[Update Inventory Error]", error)
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
