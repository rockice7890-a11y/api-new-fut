import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createRoomSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  // Check if user is admin or hotel manager
  if (!['ADMIN', 'HOTEL_MANAGER'].includes(auth.payload.role)) {
    return NextResponse.json(
      failResponse(null, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS"),
      { status: 403 }
    )
  }

  try {
    const body = await req.json()
    const validated = createRoomSchema.parse(body)

    // Verify the hotel exists and user has access
    const hotel = await prisma.hotel.findFirst({
      where: {
        id: validated.hotelId,
        ...(auth.payload.role !== 'ADMIN' && { managerId: auth.payload.userId }),
      },
    })

    if (!hotel) {
      return NextResponse.json(
        failResponse(null, "Hotel not found or access denied", "HOTEL_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check if room number already exists for this hotel
    if (validated.roomNumber) {
      const existingRoom = await prisma.room.findFirst({
        where: {
          hotelId: validated.hotelId,
          roomNumber: validated.roomNumber,
        },
      })

      if (existingRoom) {
        return NextResponse.json(
          failResponse(null, "Room number already exists for this hotel", "ROOM_NUMBER_EXISTS"),
          { status: 409 }
        )
      }
    }

    // Create room
    const room = await prisma.room.create({
      data: {
        hotelId: validated.hotelId,
        roomType: validated.roomType,
        roomNumber: validated.roomNumber,
        capacity: validated.capacity,
        beds: validated.beds,
        basePrice: validated.basePrice,
        description: validated.description,
        amenities: validated.amenities || [],
        images: validated.images || [],
        status: 'AVAILABLE',
      },
      include: {
        hotel: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    })

    return NextResponse.json(
      successResponse(room, "Room created successfully"),
      { status: 201 }
    )
  } catch (error: any) {
    console.error("[Create Room Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create room", "CREATE_ROOM_ERROR"), 
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  try {
    const searchParams = req.nextUrl.searchParams
    const hotelId = searchParams.get("hotelId")
    const roomType = searchParams.get("roomType")
    const status = searchParams.get("status")
    const minPrice = searchParams.get("minPrice") ? Number.parseFloat(searchParams.get("minPrice")!) : undefined
    const maxPrice = searchParams.get("maxPrice") ? Number.parseFloat(searchParams.get("maxPrice")!) : undefined
    const capacity = searchParams.get("capacity") ? Number.parseInt(searchParams.get("capacity")!) : undefined
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Number.parseInt(searchParams.get("pageSize") || "10")

    const where: any = {}

    if (hotelId) where.hotelId = hotelId
    if (roomType) where.roomType = { contains: roomType, mode: "insensitive" }
    if (status) where.status = status
    if (minPrice !== undefined) where.basePrice = { gte: minPrice, ...(maxPrice !== undefined && { lte: maxPrice }) }
    if (capacity) where.capacity = { gte: capacity }

    const rooms = await prisma.room.findMany({
      where,
      include: {
        hotel: {
          select: {
            id: true,
            name: true,
            city: true,
            country: true,
          },
        },
        inventory: {
          where: {
            date: {
              gte: new Date(),
            },
          },
          orderBy: { date: "asc" },
          take: 7, // Next 7 days
        },
        _count: {
          select: {
            bookings: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.room.count({ where })

    // Enrich room data
    const enrichedRooms = rooms.map(room => ({
      ...room,
      availableToday: room.inventory.length > 0 ? room.inventory[0]?.available || 0 : 0,
      nextAvailableDate: room.inventory.length > 0 ? room.inventory[0]?.date : null,
      totalBookings: room._count.bookings,
      // Clean up data
      inventory: undefined,
      _count: undefined,
    }))

    return NextResponse.json(
      successResponse(
        {
          rooms: enrichedRooms,
          total,
          page,
          pageSize,
          hasMore: (page * pageSize) < total,
        },
        "Rooms retrieved successfully"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Rooms Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch rooms", "FETCH_ROOMS_ERROR"), 
      { status: 500 }
    )
  }
}
