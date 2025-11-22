import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updateReviewSchema } from "@/lib/validation"

export const dynamic = 'force-dynamic'

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    
    const review = await prisma.review.findUnique({
      where: { id },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            avatar: true,
          },
        },
        hotel: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    })

    if (!review) {
      return NextResponse.json(
        failResponse(null, "Review not found", "REVIEW_NOT_FOUND"),
        { status: 404 }
      )
    }

    return NextResponse.json(
      successResponse(review, "Review retrieved successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Review Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch review", "FETCH_REVIEW_ERROR"), 
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
    const validated = updateReviewSchema.parse(body)

    // Find the existing review
    const existingReview = await prisma.review.findUnique({
      where: { id },
      include: {
        hotel: {
          select: { rating: true, id: true },
        },
      },
    })

    if (!existingReview) {
      return NextResponse.json(
        failResponse(null, "Review not found", "REVIEW_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check permissions: user can only edit their own reviews
    if (existingReview.userId !== auth.payload.userId && auth.payload.role !== 'ADMIN') {
      return NextResponse.json(
        failResponse(null, "You can only edit your own reviews", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Update the review
    const updatedReview = await prisma.review.update({
      where: { id },
      data: validated,
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

    // If rating was updated, recalculate hotel's overall rating
    if (validated.rating !== undefined && validated.rating !== existingReview.rating) {
      const allReviews = await prisma.review.findMany({
        where: { hotelId: existingReview.hotelId },
        select: { rating: true },
      })

      const newAverageRating = allReviews.reduce((sum, r) => sum + r.rating, 0) / allReviews.length

      await prisma.hotel.update({
        where: { id: existingReview.hotelId },
        data: {
          rating: Math.round(newAverageRating * 10) / 10,
          totalReviews: allReviews.length,
        },
      })
    }

    return NextResponse.json(
      successResponse(updatedReview, "Review updated successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Update Review Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update review", "UPDATE_REVIEW_ERROR"), 
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

    // Find the existing review
    const existingReview = await prisma.review.findUnique({
      where: { id },
      select: {
        id: true,
        userId: true,
        hotelId: true,
        rating: true,
      },
    })

    if (!existingReview) {
      return NextResponse.json(
        failResponse(null, "Review not found", "REVIEW_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check permissions: user can delete their own reviews, admins can delete any
    if (existingReview.userId !== auth.payload.userId && auth.payload.role !== 'ADMIN') {
      return NextResponse.json(
        failResponse(null, "You can only delete your own reviews", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Delete the review
    await prisma.review.delete({
      where: { id },
    })

    // Recalculate hotel's overall rating
    const remainingReviews = await prisma.review.findMany({
      where: { hotelId: existingReview.hotelId },
      select: { rating: true },
    })

    if (remainingReviews.length > 0) {
      const newAverageRating = remainingReviews.reduce((sum, r) => sum + r.rating, 0) / remainingReviews.length
      
      await prisma.hotel.update({
        where: { id: existingReview.hotelId },
        data: {
          rating: Math.round(newAverageRating * 10) / 10,
          totalReviews: remainingReviews.length,
        },
      })
    } else {
      // No reviews left, reset rating
      await prisma.hotel.update({
        where: { id: existingReview.hotelId },
        data: {
          rating: 0,
          totalReviews: 0,
        },
      })
    }

    return NextResponse.json(
      successResponse(null, "Review deleted successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Delete Review Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to delete review", "DELETE_REVIEW_ERROR"), 
      { status: 500 }
    )
  }
}
