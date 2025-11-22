import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"
import crypto from "crypto"

export const dynamic = 'force-dynamic'

// Schema for scanning QR codes
const scanQRCodeSchema = z.object({
  code: z.string(),
  location: z.string().optional(),
  scannerType: z.enum(["employee", "guest", "system"]).default("guest")
})

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = scanQRCodeSchema.parse(body)

    // Hash the provided code for lookup
    const codeHash = crypto.createHash('sha256').update(validated.code).digest('hex')

    // Find QR code
    const qrCode = await prisma.qRCode.findUnique({
      where: {
        code: codeHash
      },
      include: {
        booking: {
          include: {
            hotel: true,
            room: true,
            user: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
                email: true,
                phone: true
              }
            }
          }
        },
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    })

    if (!qrCode) {
      return NextResponse.json(
        failResponse(null, "Invalid QR code", "ERROR"),
        { status: 404 }
      )
    }

    // Check if QR code has expired
    if (qrCode.expiresAt && new Date() > qrCode.expiresAt) {
      return NextResponse.json(
        failResponse(null, "QR code has expired", "ERROR"),
        { status: 410 }
      )
    }

    // Update scan count and create scan record
    const [updatedQRCode] = await Promise.all([
      prisma.qRCode.update({
        where: { id: qrCode.id },
        data: {
          usedCount: {
            increment: 1
          }
        },
        include: {
          booking: {
            include: {
              hotel: true,
              room: true,
              user: {
                select: {
                  id: true,
                firstName: true,
                lastName: true,
                email: true,
                phone: true
              }
            }
          }
        },
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    }),
      // Create scan record
      prisma.qRCodeScan.create({
        data: {
          qrCodeId: qrCode.id,
          location: validated.location,
          deviceInfo: req.headers.get('user-agent') || undefined
        }
      })
    ])

    // Handle different QR code types
    let actionResult = null
    let message = ""

    switch (qrCode.type) {
      case "CHECK_IN":
        // Check in the guest
        if (updatedQRCode.booking && updatedQRCode.booking.status === "CONFIRMED") {
          await prisma.booking.update({
            where: { id: updatedQRCode.bookingId! },
            data: { 
              status: "CHECKED_IN",
              updatedAt: new Date()
            }
          })
          
          // Create notification
          if (updatedQRCode.userId) {
            await prisma.pushNotification.create({
              data: {
                userId: updatedQRCode.userId,
                title: "Check-in Successful",
                body: `Welcome to ${updatedQRCode.booking.hotel.name}! You have been checked in.`,
                type: "CHECK_IN_REMINDER",
              data: {
                bookingId: updatedQRCode.bookingId,
                roomNumber: updatedQRCode.booking.room.roomNumber
              }
            }
          })
          }
          
          actionResult = { status: "checked_in", checkInTime: new Date() }
          message = "Check-in successful"
        } else {
          message = "Invalid booking status or booking not found for check-in"
        }
        break

      case "CHECK_OUT":
        // Check out the guest
        if (updatedQRCode.booking && updatedQRCode.booking.status === "CHECKED_IN") {
          await prisma.booking.update({
            where: { id: updatedQRCode.bookingId! },
            data: { 
              status: "CHECKED_OUT",
              updatedAt: new Date()
            }
          })
          
          actionResult = { status: "checked_out", checkOutTime: new Date() }
          message = "Check-out successful"
        } else {
          message = "Invalid booking status or booking not found for check-out"
        }
        break

      case "BOOKING_CONFIRMATION":
        actionResult = { status: "confirmed", bookingId: updatedQRCode.bookingId }
        message = "Booking confirmed"
        break

      case "INVOICE":
        // Generate invoice access
        if (updatedQRCode.booking) {
          actionResult = { 
            status: "invoice_access",
            invoiceUrl: `/api/invoices/${updatedQRCode.bookingId}`,
            booking: {
              id: updatedQRCode.booking.id,
              bookingReference: updatedQRCode.booking.bookingReference,
              totalPrice: updatedQRCode.booking.totalPrice,
              status: updatedQRCode.booking.status
            }
          }
          message = "Invoice access granted"
        } else {
          message = "Booking not found for invoice"
        }
        break

      case "ROOM_ACCESS":
        if (updatedQRCode.booking && updatedQRCode.booking.room) {
          actionResult = { 
            status: "room_access",
            room: {
              number: updatedQRCode.booking.room.roomNumber,
              type: updatedQRCode.booking.room.roomType
            },
            accessTime: new Date()
          }
          message = "Room access granted"
        } else {
          message = "Booking or room not found for access"
        }
        break

      case "PAYMENT_RECEIPT":
        if (updatedQRCode.booking) {
          actionResult = {
            status: "payment_confirmed",
            receiptUrl: `/api/payments/${updatedQRCode.bookingId}/receipt`,
            amount: updatedQRCode.booking.totalPrice
          }
          message = "Payment receipt verified"
        } else {
          message = "Booking not found for payment receipt"
        }
        break

      default:
        message = "QR code scanned"
    }

    return successResponse({
      qrCode: {
        id: updatedQRCode.id,
        type: updatedQRCode.type,
        usedCount: updatedQRCode.usedCount,
        maxUsage: updatedQRCode.maxUsage,
        isActive: updatedQRCode.isActive
      },
      booking: updatedQRCode.booking ? {
        id: updatedQRCode.booking.id,
        reference: updatedQRCode.booking.bookingReference,
        guestName: updatedQRCode.booking.user ? `${updatedQRCode.booking.user.firstName} ${updatedQRCode.booking.user.lastName}` : 'Unknown',
        hotelName: updatedQRCode.booking.hotel.name,
        roomNumber: updatedQRCode.booking.room.roomNumber || 'N/A',
        checkInDate: updatedQRCode.booking.checkInDate,
        checkOutDate: updatedQRCode.booking.checkOutDate,
        status: updatedQRCode.booking.status
      } : null,
      action: actionResult,
      message: message,
      timestamp: new Date()
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid input data: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("QR Code scan error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to scan QR code", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}