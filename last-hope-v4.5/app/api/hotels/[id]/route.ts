import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const checkInDate = req.nextUrl.searchParams.get("checkInDate")
    const checkOutDate = req.nextUrl.searchParams.get("checkOutDate")

    const hotel = await prisma.hotel.findUnique({
      where: { id },
      include: {
        rooms: {
          include: {
            inventory: {
              where:
                checkInDate && checkOutDate
                  ? {
                      date: {
                        gte: new Date(checkInDate),
                        lte: new Date(checkOutDate),
                      },
                    }
                  : undefined,
              orderBy: { date: "asc" },
              take: 30,
            },
          },
        },
        reviews: {
          include: {
            user: { 
              select: { 
                id: true, 
                firstName: true, 
                lastName: true,
                avatar: true,
              } 
            },
          },
          orderBy: { createdAt: "desc" },
          take: 10,
        },
        manager: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
          },
        },
        workingHours: true,
        _count: {
          select: {
            rooms: true,
            bookings: true,
            reviews: true,
          },
        },
      },
    })

    if (!hotel) {
      return NextResponse.json(failResponse(null, "Hotel not found", "HOTEL_NOT_FOUND"), { status: 404 })
    }

    // Calculate hotel statistics
    const roomPrices = hotel.rooms.map(r => r.basePrice)
    const ratings = hotel.reviews.map(r => r.rating)
    
    const enrichedHotel = {
      ...hotel,
      avgRating: ratings.length > 0 
        ? (ratings.reduce((sum, r) => sum + r, 0) / ratings.length).toFixed(1)
        : null,
      minPrice: roomPrices.length > 0 ? Math.min(...roomPrices) : 0,
      maxPrice: roomPrices.length > 0 ? Math.max(...roomPrices) : 0,
      totalRooms: hotel._count.rooms,
      totalBookings: hotel._count.bookings,
      totalReviews: hotel._count.reviews,
      // Clean up data
      rooms: hotel.rooms.map(room => ({
        ...room,
        availableToday: room.inventory.length > 0 ? 
          room.inventory[0]?.available || 0 : 0,
        nextAvailableDate: room.inventory.length > 0 ? 
          room.inventory[0]?.date : null,
      })),
      // Remove raw counts for cleaner response
      _count: undefined,
    }

    return NextResponse.json(successResponse(enrichedHotel, "Hotel details retrieved"))
  } catch (error: any) {
    console.error("[Get Hotel Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch hotel", "FETCH_HOTEL_ERROR"), 
      { status: 500 }
    )
  }
}

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!
  
  try {
    const { id } = await params
    const body = await req.json()
    
    // Check if hotel exists
    const existingHotel = await prisma.hotel.findUnique({
      where: { id },
      select: { managerId: true },
    })

    if (!existingHotel) {
      return NextResponse.json(
        failResponse(null, "Hotel not found", "HOTEL_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check permissions
    if (auth.payload.role !== 'ADMIN' && existingHotel.managerId !== auth.payload.userId) {
      return NextResponse.json(
        failResponse(null, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Partial validation - make all fields optional
    const updateData: any = {}
    
    if (body.name !== undefined) updateData.name = body.name
    if (body.description !== undefined) updateData.description = body.description
    if (body.address !== undefined) updateData.address = body.address
    if (body.city !== undefined) updateData.city = body.city
    if (body.state !== undefined) updateData.state = body.state
    if (body.country !== undefined) updateData.country = body.country
    if (body.latitude !== undefined) updateData.latitude = body.latitude
    if (body.longitude !== undefined) updateData.longitude = body.longitude
    if (body.phone !== undefined) updateData.phone = body.phone
    if (body.email !== undefined) updateData.email = body.email
    if (body.amenities !== undefined) updateData.amenities = body.amenities
    if (body.images !== undefined) updateData.images = body.images
    if (body.policies !== undefined) updateData.policies = body.policies
    if (body.checkInTime !== undefined) updateData.checkInTime = body.checkInTime
    if (body.checkOutTime !== undefined) updateData.checkOutTime = body.checkOutTime
    if (body.rating !== undefined) updateData.rating = body.rating

    // Update hotel
    const updatedHotel = await prisma.hotel.update({
      where: { id },
      data: updateData,
      include: {
        manager: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
          },
        },
        workingHours: true,
      },
    })

    return NextResponse.json(
      successResponse(updatedHotel, "Hotel updated successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Update Hotel Error]", error)
    
    if (error.code === 'P2002') {
      return NextResponse.json(
        failResponse(null, "Hotel with this email already exists", "HOTEL_EXISTS"),
        { status: 409 }
      )
    }
    
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update hotel", "UPDATE_HOTEL_ERROR"), 
      { status: 500 }
    )
  }
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!
  
  // Only admins can delete hotels
  if (auth.payload.role !== 'ADMIN') {
    return NextResponse.json(
      failResponse(null, "Only administrators can delete hotels", "INSUFFICIENT_PERMISSIONS"),
      { status: 403 }
    )
  }

  try {
    const { id } = await params

    // Check if hotel exists and has dependencies
    const hotel = await prisma.hotel.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            rooms: true,
            bookings: true,
            reviews: true,
          },
        },
      },
    })

    if (!hotel) {
      return NextResponse.json(
        failResponse(null, "Hotel not found", "HOTEL_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check for active bookings
    const activeBookings = await prisma.booking.count({
      where: {
        hotelId: id,
        status: {
          in: ['PENDING', 'CONFIRMED', 'CHECKED_IN'],
        },
      },
    })

    if (activeBookings > 0) {
      return NextResponse.json(
        failResponse(null, "Cannot delete hotel with active bookings", "HAS_ACTIVE_BOOKINGS"),
        { status: 400 }
      )
    }

    // Delete hotel (cascade will handle related records)
    await prisma.hotel.delete({
      where: { id },
    })

    return NextResponse.json(
      successResponse(null, "Hotel deleted successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Delete Hotel Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to delete hotel", "DELETE_HOTEL_ERROR"), 
      { status: 500 }
    )
  }
}
