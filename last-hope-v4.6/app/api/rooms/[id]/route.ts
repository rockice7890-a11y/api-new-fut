import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updateRoomSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    
    const room = await prisma.room.findUnique({
      where: { id },
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
          orderBy: { date: "asc" },
          take: 30, // Next 30 days
        },
        bookings: {
          include: {
            user: {
              select: {
                firstName: true,
                lastName: true,
              },
            },
          },
          orderBy: { createdAt: "desc" },
          take: 5, // Latest 5 bookings
        },
        services: {
          include: {
            service: true,
          },
        },
        _count: {
          select: {
            bookings: true,
          },
        },
      },
    })

    if (!room) {
      return NextResponse.json(
        failResponse(null, "Room not found", "ROOM_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Calculate room statistics
    const availableDates = room.inventory.filter(inv => inv.available > 0)
    const nextAvailableDate = availableDates.length > 0 ? availableDates[0].date : null
    
    const enrichedRoom = {
      ...room,
      availableDatesCount: availableDates.length,
      nextAvailableDate,
      totalBookings: room._count.bookings,
      totalServices: room.services.length,
      // Clean up data
      _count: undefined,
    }

    return NextResponse.json(
      successResponse(enrichedRoom, "Room retrieved successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Room Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch room", "FETCH_ROOM_ERROR"), 
      { status: 500 }
    )
  }
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params
    const body = await req.json()
    const validated = updateRoomSchema.parse(body)

    // Find the room and verify ownership
    const existingRoom = await prisma.room.findUnique({
      where: { id },
      include: {
        hotel: {
          select: { managerId: true },
        },
      },
    })

    if (!existingRoom) {
      return NextResponse.json(
        failResponse(null, "Room not found", "ROOM_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check permissions
    if (auth.payload.role !== 'ADMIN' && existingRoom.hotel.managerId !== auth.payload.userId) {
      return NextResponse.json(
        failResponse(null, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Check if room number already exists for this hotel (if being changed)
    if (validated.roomNumber && validated.roomNumber !== existingRoom.roomNumber) {
      const duplicateRoom = await prisma.room.findFirst({
        where: {
          hotelId: existingRoom.hotelId,
          roomNumber: validated.roomNumber,
          NOT: { id },
        },
      })

      if (duplicateRoom) {
        return NextResponse.json(
          failResponse(null, "Room number already exists for this hotel", "ROOM_NUMBER_EXISTS"),
          { status: 409 }
        )
      }
    }

    // Update room
    const updateData: any = {}
    
    if (validated.roomType !== undefined) updateData.roomType = validated.roomType
    if (validated.roomNumber !== undefined) updateData.roomNumber = validated.roomNumber
    if (validated.capacity !== undefined) updateData.capacity = validated.capacity
    if (validated.beds !== undefined) updateData.beds = validated.beds
    if (validated.basePrice !== undefined) updateData.basePrice = validated.basePrice
    if (validated.status !== undefined) updateData.status = validated.status
    if (validated.description !== undefined) updateData.description = validated.description
    if (validated.amenities !== undefined) updateData.amenities = validated.amenities
    if (validated.images !== undefined) updateData.images = validated.images

    const updatedRoom = await prisma.room.update({
      where: { id },
      data: updateData,
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
      successResponse(updatedRoom, "Room updated successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Update Room Error]", error)
    
    if (error.code === 'P2002') {
      return NextResponse.json(
        failResponse(null, "Room number already exists for this hotel", "ROOM_NUMBER_EXISTS"),
        { status: 409 }
      )
    }
    
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update room", "UPDATE_ROOM_ERROR"), 
      { status: 500 }
    )
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params

    // Find the room and verify ownership
    const room = await prisma.room.findUnique({
      where: { id },
      include: {
        hotel: {
          select: { managerId: true },
        },
        _count: {
          select: {
            bookings: true,
          },
        },
      },
    })

    if (!room) {
      return NextResponse.json(
        failResponse(null, "Room not found", "ROOM_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check permissions
    if (auth.payload.role !== 'ADMIN' && room.hotel.managerId !== auth.payload.userId) {
      return NextResponse.json(
        failResponse(null, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Check for active bookings
    const activeBookings = await prisma.booking.update({
      where: { id },
      data: { status: 'CANCELLED' }
    }).catch(() => null)

    const hasActiveBookings = await prisma.booking.count({
      where: {
        roomId: id,
        status: {
          in: ['PENDING', 'CONFIRMED', 'CHECKED_IN'],
        },
      },
    }) > 0

    if (hasActiveBookings) {
      return NextResponse.json(
        failResponse(null, "Cannot delete room with active bookings", "HAS_ACTIVE_BOOKINGS"),
        { status: 400 }
      )
    }

    // Delete room (cascade will handle related records)
    await prisma.room.delete({
      where: { id },
    })

    return NextResponse.json(
      successResponse(null, "Room deleted successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Delete Room Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to delete room", "DELETE_ROOM_ERROR"), 
      { status: 500 }
    )
  }
}
