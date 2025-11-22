import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse } from "@/lib/api-response"
import { createHotelSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ["HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = createHotelSchema.parse(body)

    const hotel = await prisma.hotel.create({
      data: {
        ...validated,
        managerId: auth.payload.userId,
      },
    })

    return NextResponse.json(successResponse(hotel, "Hotel created successfully"), { status: 201 })
  } catch (error: any) {
    console.error("[Create Hotel Error]", error)
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}

export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ["HOTEL_MANAGER"])
  if (!auth.isValid) return auth.response!

  try {
    const hotels = await prisma.hotel.findMany({
      where: { managerId: auth.payload.userId },
      include: {
        rooms: true,
        bookings: true,
      },
    })

    return NextResponse.json(successResponse(hotels, "Manager hotels retrieved"))
  } catch (error: any) {
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
