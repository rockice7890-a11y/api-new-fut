import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createReviewSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = createReviewSchema.parse(body)

    // Verify that the user has a completed booking at this hotel
    const completedBooking = await prisma.booking.findFirst({
      where: {
        userId: auth.payload.userId,
        hotelId: validated.hotelId,
        status: 'COMPLETED',
        ...(validated.bookingId && { id: validated.bookingId }),
      },
    })

    if (!completedBooking) {
      return NextResponse.json(
        failResponse(null, "You can only review hotels where you have completed a stay", "NO_COMPLETED_BOOKING"),
        { status: 400 }
      )
    }

    // Check if user already reviewed this hotel
    const existingReview = await prisma.review.findFirst({
      where: {
        userId: auth.payload.userId,
        hotelId: validated.hotelId,
      },
    })

    if (existingReview) {
      return NextResponse.json(
        failResponse(null, "You have already reviewed this hotel", "REVIEW_EXISTS"),
        { status: 409 }
      )
    }

    // Create the review
    const review = await prisma.review.create({
      data: {
        userId: auth.payload.userId,
        hotelId: validated.hotelId,
        rating: validated.rating,
        comment: validated.comment,
        cleanliness: validated.cleanliness,
        comfort: validated.comfort,
        service: validated.service,
        value: validated.value,
        verified: true, // Auto-verify since they have completed booking
      },
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
            avatar: true,
          },
        },
        hotel: {
          select: {
            name: true,
          },
        },
      },
    })

    // Update hotel's overall rating
    const allReviews = await prisma.review.findMany({
      where: { hotelId: validated.hotelId },
      select: { rating: true },
    })

    const newAverageRating = allReviews.reduce((sum, r) => sum + r.rating, 0) / allReviews.length

    await prisma.hotel.update({
      where: { id: validated.hotelId },
      data: {
        rating: Math.round(newAverageRating * 10) / 10, // Round to 1 decimal place
        totalReviews: allReviews.length,
      },
    })

    return NextResponse.json(
      successResponse(review, "Review created successfully"),
      { status: 201 }
    )
  } catch (error: any) {
    console.error("[Create Review Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create review", "CREATE_REVIEW_ERROR"), 
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  try {
    const searchParams = req.nextUrl.searchParams
    const hotelId = searchParams.get("hotelId")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Number.parseInt(searchParams.get("pageSize") || "10")
    const minRating = searchParams.get("minRating") ? Number.parseInt(searchParams.get("minRating")!) : undefined

    if (!hotelId) {
      return NextResponse.json(
        failResponse(null, "Hotel ID is required", "HOTEL_ID_REQUIRED"),
        { status: 400 }
      )
    }

    const where: any = { hotelId }
    if (minRating) {
      where.rating = { gte: minRating }
    }

    const reviews = await prisma.review.findMany({
      where,
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
            avatar: true,
          },
        },
        hotel: {
          select: {
            name: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.review.count({ where })

    // Calculate rating distribution
    const ratingStats = await prisma.review.groupBy({
      by: ['rating'],
      where: { hotelId },
      _count: {
        rating: true,
      },
    })

    const ratingDistribution = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 }
    ratingStats.forEach(stat => {
      ratingDistribution[stat.rating as keyof typeof ratingDistribution] = stat._count.rating
    })

    return NextResponse.json(
      successResponse(
        {
          reviews,
          total,
          page,
          pageSize,
          hasMore: (page * pageSize) < total,
          ratingDistribution,
        },
        "Reviews retrieved successfully"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Reviews Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch reviews", "FETCH_REVIEWS_ERROR"), 
      { status: 500 }
    )
  }
}
