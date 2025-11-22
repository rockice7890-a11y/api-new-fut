import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createHotelSchema, searchHotelsSchema } from "@/lib/validation"
import bcrypt from "bcryptjs"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    const searchParams = req.nextUrl.searchParams
    
    // Parse and validate search parameters
    const searchData = {
      city: searchParams.get("city") || undefined,
      country: searchParams.get("country") || undefined,
      minPrice: searchParams.get("minPrice") ? Number.parseFloat(searchParams.get("minPrice")!) : undefined,
      maxPrice: searchParams.get("maxPrice") ? Number.parseFloat(searchParams.get("maxPrice")!) : undefined,
      minRating: searchParams.get("minRating") ? Number.parseFloat(searchParams.get("minRating")!) : undefined,
      amenities: searchParams.get("amenities")?.split(',') || undefined,
      checkIn: searchParams.get("checkIn") || undefined,
      checkOut: searchParams.get("checkOut") || undefined,
      guests: searchParams.get("guests") ? Number.parseInt(searchParams.get("guests")!) : undefined,
      page: Number.parseInt(searchParams.get("page") || "1"),
      pageSize: Number.parseInt(searchParams.get("pageSize") || "10"),
    }

    // Validate using schema
    const validated = searchHotelsSchema.parse(searchData)

    const where: any = {}
    
    // Basic filters
    if (validated.city) where.city = { contains: validated.city, mode: "insensitive" }
    if (validated.country) where.country = { contains: validated.country, mode: "insensitive" }
    if (validated.amenities) {
      where.amenities = { hasSome: validated.amenities }
    }

    const hotels = await prisma.hotel.findMany({
      where,
      include: {
        rooms: {
          select: {
            id: true,
            basePrice: true,
            capacity: true,
            status: true,
          },
        },
        reviews: {
          select: {
            rating: true,
          },
        },
        _count: {
          select: {
            bookings: true,
          },
        },
      },
      skip: (validated.page - 1) * validated.pageSize,
      take: validated.pageSize,
      orderBy: { createdAt: "desc" },
    })

    const total = await prisma.hotel.count({ where })

    // Filter and enrich results
    const enrichedHotels = hotels.map((hotel) => {
      const roomPrices = hotel.rooms.map(r => r.basePrice)
      const ratings = hotel.reviews.map(r => r.rating)
      
      return {
        ...hotel,
        avgRating: ratings.length > 0 
          ? (ratings.reduce((sum, r) => sum + r, 0) / ratings.length).toFixed(1)
          : null,
        minPrice: roomPrices.length > 0 ? Math.min(...roomPrices) : 0,
        maxPrice: roomPrices.length > 0 ? Math.max(...roomPrices) : 0,
        totalRooms: hotel.rooms.length,
        availableRooms: hotel.rooms.filter(r => r.status === 'AVAILABLE').length,
        totalBookings: hotel._count.bookings,
        // Remove raw data for cleaner response
        rooms: undefined,
        reviews: undefined,
        _count: undefined,
      }
    })

    // Apply price and rating filters after enrichment
    let filtered = enrichedHotels
    if (validated.minPrice !== undefined || validated.maxPrice !== undefined) {
      filtered = filtered.filter(hotel => {
        if (validated.minPrice !== undefined && hotel.maxPrice < validated.minPrice) return false
        if (validated.maxPrice !== undefined && hotel.minPrice > validated.maxPrice) return false
        return true
      })
    }

    if (validated.minRating !== undefined) {
      filtered = filtered.filter(hotel => 
        hotel.avgRating && parseFloat(hotel.avgRating) >= validated.minRating!
      )
    }

    return NextResponse.json(
      successResponse(
        {
          hotels: filtered,
          total,
          page: validated.page,
          pageSize: validated.pageSize,
          hasMore: (validated.page * validated.pageSize) < total,
        },
        "Hotels retrieved successfully",
      ),
    )
  } catch (error: any) {
    console.error("[Get Hotels Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch hotels", "FETCH_HOTELS_ERROR"), 
      { status: 500 }
    )
  }
}

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
    const validated = createHotelSchema.parse(body)

    // Check if email is provided and unique
    if (validated.email) {
      const existingHotel = await prisma.hotel.findFirst({
        where: { email: validated.email }
      })
      
      if (existingHotel) {
        return NextResponse.json(
          failResponse(null, "Hotel with this email already exists", "HOTEL_EXISTS"),
          { status: 409 }
        )
      }
    }

    // Create hotel
    const hotel = await prisma.hotel.create({
      data: {
        ...validated,
        managerId: auth.payload.userId,
        amenities: validated.amenities || [],
        images: validated.images || [],
        policies: validated.policies || null,
      },
      include: {
        manager: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
          },
        },
      },
    })

    // Create default hotel settings
    await prisma.hotelSettings.create({
      data: {
        hotelId: hotel.id,
        checkInTime: "15:00",
        checkOutTime: "11:00",
        autoCheckoutEnabled: true,
        autoCheckoutTime: "12:00",
        gracePeriodMinutes: 60,
        realtimeUpdatesEnabled: true,
        autoSendInvoices: true,
        taxRate: 0.15,
        serviceFee: 0,
        currencyCode: "USD",
      },
    })

    // Create default working hours
    await prisma.hotelWorkingHours.create({
      data: {
        hotelId: hotel.id,
        monday: "08:00-23:00",
        tuesday: "08:00-23:00", 
        wednesday: "08:00-23:00",
        thursday: "08:00-23:00",
        friday: "08:00-23:00",
        saturday: "08:00-23:00",
        sunday: "08:00-23:00",
        timezone: "UTC",
      },
    })

    return NextResponse.json(
      successResponse(hotel, "Hotel created successfully"), 
      { status: 201 }
    )
  } catch (error: any) {
    console.error("[Create Hotel Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create hotel", "CREATE_HOTEL_ERROR"), 
      { status: 500 }
    )
  }
}
