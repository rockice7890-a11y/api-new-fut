import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Schema for getting QR codes
const getQRCodesSchema = z.object({
  bookingId: z.string().optional(),
  type: z.enum([
    "BOOKING_CONFIRMATION",
    "CHECK_IN", 
    "CHECK_OUT",
    "INVOICE",
    "ROOM_ACCESS",
    "PAYMENT_RECEIPT"
  ]).optional(),
  includeExpired: z.boolean().default(false)
})

export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { searchParams } = new URL(req.url)
    const queryParams = {
      bookingId: searchParams.get("bookingId") || undefined,
      type: searchParams.get("type") || undefined,
      includeExpired: searchParams.get("includeExpired") === "true"
    }

    const validated = getQRCodesSchema.parse(queryParams)

    // Build where clause
    const where: any = {
      userId: auth.payload.userId
    }

    if (validated.bookingId) {
      where.bookingId = validated.bookingId
    }

    if (validated.type) {
      where.type = validated.type
    }

    if (!validated.includeExpired) {
      where.expiresAt = {
        gte: new Date()
      }
    }

    // Get QR codes
    const qrCodes = await prisma.qRCode.findMany({
      where,
      orderBy: {
        createdAt: 'desc'
      },
      include: {
        booking: {
          select: {
            id: true,
            bookingReference: true,
            status: true,
            checkInDate: true,
            checkOutDate: true,
            hotel: {
              select: {
                id: true,
                name: true
              }
            },
            room: {
              select: {
                id: true,
                roomNumber: true,
                roomType: true
              }
            }
          }
        }
      }
    })

    // Categorize QR codes
    const categorized = {
      active: qrCodes.filter(qr => qr.expiresAt && new Date() <= qr.expiresAt && qr.isActive && (qr.maxUsage === null || qr.usedCount < qr.maxUsage)),
      expired: qrCodes.filter(qr => qr.expiresAt && new Date() > qr.expiresAt),
      used: qrCodes.filter(qr => qr.maxUsage !== null && qr.usedCount >= qr.maxUsage),
      byType: {} as Record<string, any[]>
    }

    // Group by type
    qrCodes.forEach(qr => {
      if (!categorized.byType[qr.type]) {
        categorized.byType[qr.type] = []
      }
      categorized.byType[qr.type].push({
        id: qr.id,
        type: qr.type,
        code: qr.code,
        data: qr.data,
        expiresAt: qr.expiresAt,
        usedCount: qr.usedCount,
        maxUsage: qr.maxUsage,
        isActive: qr.isActive,
        createdAt: qr.createdAt,
        booking: qr.booking
      })
    })

    return successResponse({
      qrCodes: {
        summary: {
          total: qrCodes.length,
          active: categorized.active.length,
          expired: categorized.expired.length,
          used: categorized.used.length
        },
        categorized,
        all: qrCodes.map(qr => ({
          id: qr.id,
          type: qr.type,
          code: qr.code,
          data: qr.data,
          expiresAt: qr.expiresAt,
          usedCount: qr.usedCount,
          maxUsage: qr.maxUsage,
          isActive: qr.isActive,
          createdAt: qr.createdAt,
          booking: qr.booking
        }))
      }
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid query parameters: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("Get QR codes error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to get QR codes", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}