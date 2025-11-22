import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createPaymentSchema, updatePaymentSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = createPaymentSchema.parse(body)

    // Verify the booking exists and belongs to the user
    const booking = await prisma.booking.findFirst({
      where: {
        id: validated.bookingId,
        userId: auth.payload.userId,
      },
      include: {
        payment: true,
      },
    })

    if (!booking) {
      return NextResponse.json(
        failResponse(null, "Booking not found or access denied", "BOOKING_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check if payment already exists
    if (booking.payment) {
      return NextResponse.json(
        failResponse(null, "Payment already exists for this booking", "PAYMENT_EXISTS"),
        { status: 409 }
      )
    }

    // Create payment record
    const payment = await prisma.payment.create({
      data: {
        bookingId: validated.bookingId,
        amount: validated.amount,
        currency: validated.currency,
        status: 'pending',
        method: validated.method,
        stripeId: validated.stripeId,
      },
      include: {
        booking: {
          include: {
            hotel: {
              select: {
                name: true,
              },
            },
            room: {
              select: {
                roomType: true,
                roomNumber: true,
              },
            },
          },
        },
      },
    })

    // TODO: Integrate with actual payment processor (Stripe, PayPal, etc.)
    // For now, we'll simulate payment processing

    return NextResponse.json(
      successResponse(payment, "Payment created successfully"),
      { status: 201 }
    )
  } catch (error: any) {
    console.error("[Create Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create payment", "CREATE_PAYMENT_ERROR"), 
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const bookingId = searchParams.get("bookingId")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Number.parseInt(searchParams.get("pageSize") || "10")
    const status = searchParams.get("status")

    const where: any = {}

    // Filter by booking if specified
    if (bookingId) {
      where.bookingId = bookingId
    } else {
      // If no specific booking, only show payments for user's bookings
      const userBookings = await prisma.booking.findMany({
        where: { userId: auth.payload.userId },
        select: { id: true },
      })
      where.bookingId = { in: userBookings.map(b => b.id) }
    }

    // Filter by status if specified
    if (status) {
      where.status = status
    }

    const payments = await prisma.payment.findMany({
      where,
      include: {
        booking: {
          include: {
            hotel: {
              select: {
                name: true,
              },
            },
            room: {
              select: {
                roomType: true,
                roomNumber: true,
              },
            },
          },
        },
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.payment.count({ where })

    return NextResponse.json(
      successResponse(
        {
          payments,
          total,
          page,
          pageSize,
          hasMore: (page * pageSize) < total,
        },
        "Payments retrieved successfully"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Payments Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch payments", "FETCH_PAYMENTS_ERROR"), 
      { status: 500 }
    )
  }
}
