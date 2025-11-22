import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createBookingSchema } from "@/lib/validation"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = createBookingSchema.parse(body)

    // Check room availability
    const checkInDate = new Date(validated.checkInDate)
    const checkOutDate = new Date(validated.checkOutDate)

    const inventory = await prisma.roomInventory.findMany({
      where: {
        roomId: validated.roomId,
        date: {
          gte: checkInDate,
          lt: checkOutDate,
        },
      },
      include: {
        room: true,
      },
    })

    // Verify all dates have sufficient availability
    const hasAvailability = inventory.every((inv) => inv.available > 0)
    if (!hasAvailability) {
      return NextResponse.json(failResponse(null, "Room not available for selected dates", "NOT_AVAILABLE"), {
        status: 400,
      })
    }

    // Calculate total price
    const totalPrice = inventory.reduce((sum, inv) => sum + inv.price, 0)

    // Create booking
    const bookingReference = `BK${Date.now()}${Math.random().toString(36).substr(2, 4).toUpperCase()}`
    const room = inventory[0].room // Get room data to get basePrice
    
    const booking = await prisma.booking.create({
      data: {
        userId: auth.payload.userId,
        hotelId: validated.hotelId,
        roomId: validated.roomId,
        checkInDate,
        checkOutDate,
        guests: validated.guests,
        totalPrice,
        status: "PENDING",
        bookingReference,
        guestName: validated.guestName,
        guestEmail: validated.guestEmail,
        guestPhone: validated.guestPhone,
        basePrice: room.basePrice,
      },
      include: {
        room: true,
        hotel: true,
      },
    })

    // Create QR Code for booking confirmation
    const qrCodeData = {
      bookingId: booking.id,
      userId: auth.payload.userId,
      type: "BOOKING_CONFIRMATION",
      timestamp: Date.now(),
      hash: crypto.randomBytes(32).toString('hex')
    }

    const codeString = JSON.stringify(qrCodeData)
    const codeHash = crypto.createHash('sha256').update(codeString).digest('hex')
    const expiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)) // 7 days

    const qrCode = await prisma.qRCode.create({
      data: {
        bookingId: booking.id,
        userId: auth.payload.userId,
        type: "BOOKING_CONFIRMATION",
        code: codeHash,
        data: qrCodeData,
        expiresAt: expiresAt
      }
    })

    // Create notification
    await prisma.pushNotification.create({
      data: {
        userId: auth.payload.userId,
        title: "Booking Created",
        body: `Your booking at ${booking.hotel.name} has been created. Use QR code for quick check-in.`,
        type: "BOOKING_CONFIRMED",
        data: {
          bookingId: booking.id,
          bookingReference: booking.bookingReference,
          qrCodeId: qrCode.id
        }
      }
    })

    // Return booking with QR code info
    const responseData = {
      ...booking,
      qrCode: {
        id: qrCode.id,
        type: qrCode.type,
        code: qrCode.code,
        expiresAt: qrCode.expiresAt
      }
    }

    return NextResponse.json(successResponse(responseData, "Booking created successfully"), { status: 201 })
  } catch (error: any) {
    console.error("[Create Booking Error]", error)
    return NextResponse.json({ status: "error", message: error.message || "Booking failed" }, { status: 500 })
  }
}

export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const page = Number.parseInt(req.nextUrl.searchParams.get("page") || "1")
    const pageSize = Number.parseInt(req.nextUrl.searchParams.get("pageSize") || "10")

    const bookings = await prisma.booking.findMany({
      where: { userId: auth.payload.userId },
      include: {
        hotel: true,
        room: true,
        payment: true,
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.booking.count({ where: { userId: auth.payload.userId } })

    return NextResponse.json(successResponse({ bookings, total, page, pageSize }, "Bookings retrieved"))
  } catch (error: any) {
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
