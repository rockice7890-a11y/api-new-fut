import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Schema for generating QR codes
const generateQRCodeSchema = z.object({
  bookingId: z.string(),
  type: z.enum([
    "BOOKING_CONFIRMATION",
    "CHECK_IN", 
    "CHECK_OUT",
    "INVOICE",
    "ROOM_ACCESS",
    "PAYMENT_RECEIPT"
  ]),
  expiresIn: z.number().min(300).max(86400).default(3600) // 5 minutes to 24 hours
})

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = generateQRCodeSchema.parse(body)

    // Verify booking belongs to user
    const booking = await prisma.booking.findFirst({
      where: {
        id: validated.bookingId,
        userId: auth.payload.userId
      },
      include: {
        hotel: true,
        room: true,
        user: true
      }
    })

    if (!booking) {
      return NextResponse.json(
        failResponse(null, "Booking not found", "ERROR"),
        { status: 404 }
      )
    }

    // Generate unique QR code
    const qrCodeData = {
      bookingId: booking.id,
      userId: auth.payload.userId,
      type: validated.type,
      timestamp: Date.now(),
      hash: crypto.randomBytes(32).toString('hex')
    }

    const codeString = JSON.stringify(qrCodeData)
    const codeHash = crypto.createHash('sha256').update(codeString).digest('hex')
    
    // Calculate expiry
    const expiresAt = new Date(Date.now() + (validated.expiresIn * 1000))

    // Create QR code record
    const qrCode = await prisma.qRCode.create({
      data: {
        bookingId: booking.id,
        userId: auth.payload.userId,
        type: validated.type,
        code: codeHash,
        data: qrCodeData,
        expiresAt: expiresAt
      },
      include: {
        booking: {
          include: {
            hotel: true,
            room: true
          }
        }
      }
    })

    // Create notification for user
    await prisma.pushNotification.create({
      data: {
        userId: auth.payload.userId,
        title: "QR Code Generated",
        body: `Your ${validated.type.toLowerCase().replace('_', ' ')} QR code has been generated`,
        type: "SYSTEM_ALERT",
        data: {
          qrCodeId: qrCode.id,
          type: validated.type,
          bookingId: booking.id
        }
      }
    })

    return successResponse({
      qrCode: {
        id: qrCode.id,
        type: qrCode.type,
        code: qrCode.code,
        data: qrCode.data,
        expiresAt: qrCode.expiresAt,
        booking: {
          id: booking.id,
          bookingReference: booking.bookingReference,
          hotelName: booking.hotel.name,
          roomNumber: booking.room.roomNumber,
          checkInDate: booking.checkInDate,
          checkOutDate: booking.checkOutDate,
          status: booking.status
        }
      },
      message: "QR Code generated successfully"
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid input data: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("QR Code generation error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to generate QR code", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}