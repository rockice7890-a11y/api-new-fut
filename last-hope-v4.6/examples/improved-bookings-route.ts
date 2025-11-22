import { type NextRequest, NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { createBookingSchema } from "@/lib/validation"
import { apiResponse, ErrorCodes, generateRequestId } from "@/lib/api-response-improved"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  const requestId = generateRequestId()
  const userId = auth.payload.userId

  console.log(`[BOOKING_CREATE_${requestId}] User ${userId} attempting to create booking`)

  try {
    const body = await req.json()
    const validated = createBookingSchema.parse(body)

    console.log(`[BOOKING_CREATE_${requestId}] Validated booking data:`, validated)

    // Check room availability
    const checkInDate = new Date(validated.checkInDate)
    const checkOutDate = new Date(validated.checkOutDate)

    // Validate dates
    if (checkInDate >= checkOutDate) {
      return apiResponse.badRequest(
        "Check-out date must be after check-in date",
        { 
          field: "dates",
          checkInDate: validated.checkInDate,
          checkOutDate: validated.checkOutDate 
        }
      )
    }

    // Check if check-in date is not in the past
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    if (checkInDate < today) {
      return apiResponse.badRequest(
        "Check-in date cannot be in the past",
        { 
          field: "checkInDate",
          checkInDate: validated.checkInDate,
          today: today.toISOString()
        }
      )
    }

    const inventory = await prisma.roomInventory.findMany({
      where: {
        roomId: validated.roomId,
        date: {
          gte: checkInDate,
          lt: checkOutDate,
        },
      },
      include: {
        room: {
          include: {
            hotel: true
          }
        },
      },
    })

    console.log(`[BOOKING_CREATE_${requestId}] Found ${inventory.length} inventory records`)

    // Verify all dates have sufficient availability
    const hasAvailability = inventory.every((inv) => inv.available > 0)
    if (!hasAvailability) {
      return apiResponse.conflict(
        "Room not available for selected dates",
        "HOTEL_002",
        { 
          requested: { checkInDate: validated.checkInDate, checkOutDate: validated.checkOutDate },
          unavailable: inventory.filter(inv => inv.available === 0).map(inv => inv.date.toISOString())
        }
      )
    }

    // Calculate total price
    const totalPrice = inventory.reduce((sum, inv) => sum + inv.price, 0)
    const room = inventory[0].room // Get room data to get basePrice
    
    // Generate booking reference
    const bookingReference = `BK${Date.now()}${Math.random().toString(36).substr(2, 4).toUpperCase()}`
    
    console.log(`[BOOKING_CREATE_${requestId}] Creating booking with reference: ${bookingReference}`)
    
    // Create booking
    const booking = await prisma.booking.create({
      data: {
        userId,
        roomId: validated.roomId,
        hotelId: room.hotelId,
        checkInDate,
        checkOutDate,
        guests: validated.guests,
        totalPrice,
        bookingReference,
        specialRequests: validated.specialRequests || null,
        status: "PENDING"
      },
      include: {
        room: {
          include: {
            hotel: true
          }
        },
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true
          }
        }
      }
    })

    // Update room inventory (decrement available count)
    const updatePromises = inventory.map(inv =>
      prisma.roomInventory.update({
        where: { id: inv.id },
        data: { available: inv.available - 1 }
      })
    )
    
    await Promise.all(updatePromises)

    console.log(`[BOOKING_CREATE_${requestId}] Booking created successfully: ${booking.id}`)

    // Prepare response data
    const responseData = {
      booking: {
        id: booking.id,
        bookingReference: booking.bookingReference,
        room: {
          id: booking.room.id,
          name: booking.room.name,
          type: booking.room.type,
          capacity: booking.room.capacity
        },
        hotel: {
          id: booking.room.hotel.id,
          name: booking.room.hotel.name,
          address: booking.room.hotel.address
        },
        dates: {
          checkIn: booking.checkInDate.toISOString(),
          checkOut: booking.checkOutDate.toISOString(),
          nights: Math.ceil((checkOutDate.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24))
        },
        guests: booking.guests,
        totalPrice: booking.totalPrice,
        status: booking.status,
        specialRequests: booking.specialRequests
      },
      payment: {
        required: true,
        amount: totalPrice,
        currency: "USD",
        dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours from now
      },
      nextSteps: [
        "Complete payment within 24 hours",
        "Check-in available after 3:00 PM",
        "Check-out required before 11:00 AM"
      ]
    }

    const response = apiResponse.success(
      responseData,
      "Booking created successfully. Please complete payment to confirm."
    )

    // Add custom headers
    response.headers.set("X-Request-ID", requestId)
    response.headers.set("X-Booking-Reference", bookingReference)

    return response

  } catch (error: any) {
    console.error(`[BOOKING_CREATE_${requestId}] Error:`, error)

    // Handle validation errors
    if (error.name === "ZodError") {
      return apiResponse.unprocessableEntity(
        "Invalid booking data",
        { 
          validationErrors: error.errors,
          field: error.errors[0]?.path?.[0] || "unknown"
        }
      )
    }

    // Handle database constraint errors
    if (error.code === "P2002") {
      return apiResponse.conflict(
        "Booking reference already exists",
        "BIZ_002"
      )
    }

    if (error.code === "P2003") {
      return apiResponse.badRequest(
        "Invalid room or hotel reference",
        { 
          field: "roomId",
          providedRoomId: error.meta?.constraint || "unknown"
        }
      )
    }

    // Handle foreign key constraint violations
    if (error.message.includes("Foreign key constraint")) {
      return apiResponse.badRequest(
        "Invalid room or user reference provided",
        { 
          constraint: error.message,
          field: error.message.includes("roomId") ? "roomId" : "userId"
        }
      )
    }

    // Generic error
    return apiResponse.internalError(
      "Failed to create booking. Please try again.",
      error
    )
  }
}

// GET endpoint example for retrieving bookings
export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  const requestId = generateRequestId()
  const userId = auth.payload.userId

  try {
    const searchParams = req.nextUrl.searchParams
    const page = Number(searchParams.get("page") || "1")
    const limit = Number(searchParams.get("limit") || "10")
    const status = searchParams.get("status") || undefined

    console.log(`[BOOKING_LIST_${requestId}] User ${userId} requesting bookings, page: ${page}`)

    const where: any = { userId }
    if (status) {
      where.status = status.toUpperCase()
    }

    const [bookings, total] = await Promise.all([
      prisma.booking.findMany({
        where,
        include: {
          room: {
            include: {
              hotel: true
            }
          }
        },
        orderBy: { createdAt: "desc" },
        skip: (page - 1) * limit,
        take: limit
      }),
      prisma.booking.count({ where })
    ])

    console.log(`[BOOKING_LIST_${requestId}] Found ${bookings.length} bookings (total: ${total})`)

    const responseData = {
      bookings: bookings.map(booking => ({
        id: booking.id,
        bookingReference: booking.bookingReference,
        room: {
          name: booking.room.name,
          type: booking.room.type
        },
        hotel: {
          name: booking.room.hotel.name
        },
        dates: {
          checkIn: booking.checkInDate.toISOString(),
          checkOut: booking.checkOutDate.toISOString()
        },
        status: booking.status,
        totalPrice: booking.totalPrice
      })),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    }

    const response = apiResponse.successPaginated(
      responseData,
      { page, limit, total },
      "Bookings retrieved successfully"
    )

    response.headers.set("X-Request-ID", requestId)

    return response

  } catch (error: any) {
    console.error(`[BOOKING_LIST_${requestId}] Error:`, error)
    return apiResponse.internalError("Failed to retrieve bookings", error)
  }
}