import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updatePaymentSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { id } = await params
    
    const payment = await prisma.payment.findUnique({
      where: { id },
      include: {
        booking: {
          include: {
            user: {
              select: {
                firstName: true,
                lastName: true,
                email: true,
              },
            },
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

    if (!payment) {
      return NextResponse.json(
        failResponse(null, "Payment not found", "PAYMENT_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check access permissions
    const isOwner = payment.booking.userId === auth.payload.userId
    const isAdmin = auth.payload.role === 'ADMIN'
    const isHotelManager = await prisma.hotel.findFirst({
      where: {
        id: payment.booking.hotelId,
        managerId: auth.payload.userId,
      },
    })

    if (!isOwner && !isAdmin && !isHotelManager) {
      return NextResponse.json(
        failResponse(null, "Access denied", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    return NextResponse.json(
      successResponse(payment, "Payment retrieved successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch payment", "FETCH_PAYMENT_ERROR"), 
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
    const validated = updatePaymentSchema.parse(body)

    // Find the payment
    const payment = await prisma.payment.findUnique({
      where: { id },
      include: {
        booking: {
          include: {
            hotel: {
              select: { managerId: true },
            },
          },
        },
      },
    })

    if (!payment) {
      return NextResponse.json(
        failResponse(null, "Payment not found", "PAYMENT_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check permissions
    const isHotelManager = payment.booking.hotel.managerId === auth.payload.userId
    const isAdmin = auth.payload.role === 'ADMIN'

    if (!isHotelManager && !isAdmin) {
      return NextResponse.json(
        failResponse(null, "Only hotel managers and admins can update payments", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Update payment
    const updateData: any = {}
    
    if (validated.status !== undefined) {
      updateData.status = validated.status
      
      // Set timestamps based on status
      if (validated.status === 'completed' && !payment.paidAt) {
        updateData.paidAt = new Date()
      } else if (validated.status === 'refunded' && !payment.refundedAt) {
        updateData.refundedAt = new Date()
      }
    }
    
    if (validated.transactionId !== undefined) updateData.transactionId = validated.transactionId
    if (validated.paidAt !== undefined) updateData.paidAt = new Date(validated.paidAt)
    if (validated.refundedAt !== undefined) updateData.refundedAt = new Date(validated.refundedAt)

    const updatedPayment = await prisma.payment.update({
      where: { id },
      data: updateData,
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

    // If payment is completed, update booking status
    if (validated.status === 'completed' && payment.booking.status === 'PENDING') {
      await prisma.booking.update({
        where: { id: payment.bookingId },
        data: { status: 'CONFIRMED' },
      })
    }

    // If payment is refunded, update booking status
    if (validated.status === 'refunded') {
      await prisma.booking.update({
        where: { id: payment.bookingId },
        data: { status: 'CANCELLED' },
      })
    }

    return NextResponse.json(
      successResponse(updatedPayment, "Payment updated successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Update Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update payment", "UPDATE_PAYMENT_ERROR"), 
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

    // Find the payment
    const payment = await prisma.payment.findUnique({
      where: { id },
      include: {
        booking: {
          include: {
            hotel: {
              select: { managerId: true },
            },
          },
        },
      },
    })

    if (!payment) {
      return NextResponse.json(
        failResponse(null, "Payment not found", "PAYMENT_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check permissions - only admins can delete payments
    if (auth.payload.role !== 'ADMIN') {
      return NextResponse.json(
        failResponse(null, "Only administrators can delete payments", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Cannot delete completed payments
    if (payment.status === 'completed') {
      return NextResponse.json(
        failResponse(null, "Cannot delete completed payments", "PAYMENT_COMPLETED"),
        { status: 400 }
      )
    }

    // Delete payment
    await prisma.payment.delete({
      where: { id },
    })

    return NextResponse.json(
      successResponse(null, "Payment deleted successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Delete Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to delete payment", "DELETE_PAYMENT_ERROR"), 
      { status: 500 }
    )
  }
}
