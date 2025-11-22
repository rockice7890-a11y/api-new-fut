import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const validatePromotionSchema = z.object({
  promoCode: z.string(),
  hotelId: z.string().optional(),
  bookingDetails: z.object({
    totalAmount: z.number().positive(),
    checkInDate: z.string().transform((str) => new Date(str)).optional(),
    checkOutDate: z.string().transform((str) => new Date(str)).optional(),
    nights: z.number().positive().optional(),
    userId: z.string(),
    bookingValue: z.number().positive()
  })
})

// POST /api/promotion-campaigns/validate - Validate and calculate promotion discount
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const validated = validatePromotionSchema.parse(body)

    // Find promotion by promo code
    const promotion = await prisma.promotionCampaign.findFirst({
      where: {
        promoCode: validated.promoCode,
        status: 'ACTIVE',
        validFrom: { lte: new Date() },
        validUntil: { gte: new Date() }
      },
      include: {
        hotel: {
          select: { id: true, name: true }
        }
      }
    })

    if (!promotion) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Invalid or expired promo code", "INVALID_PROMO_CODE"),
          { status: 400 }
        )
      )
    }

    // Check hotel-specific promotions
    if (validated.hotelId && promotion.hotelId && promotion.hotelId !== validated.hotelId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promo code not valid for this hotel", "INVALID_HOTEL"),
          { status: 400 }
        )
      )
    }

    // Check usage limits
    if (promotion.maxUses && promotion.totalUsed >= promotion.maxUses) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promo code usage limit reached", "USAGE_LIMIT_REACHED"),
          { status: 400 }
        )
      )
    }

    // Check user-specific usage
    if (promotion.maxUsesPerUser) {
      const userUsage = await prisma.promotionUsage.count({
        where: {
          campaignId: promotion.id,
          userId: validated.bookingDetails.userId
        }
      })
      
      if (userUsage >= promotion.maxUsesPerUser) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "You have reached the maximum uses for this promo code", "USER_USAGE_LIMIT_REACHED"),
            { status: 400 }
          )
        )
      }
    }

    // Check daily usage limit
    if (promotion.maxUsesPerDay) {
      const today = new Date()
      today.setHours(0, 0, 0, 0)
      const tomorrow = new Date(today)
      tomorrow.setDate(tomorrow.getDate() + 1)

      const dailyUsage = await prisma.promotionUsage.count({
        where: {
          campaignId: promotion.id,
          usedAt: {
            gte: today,
            lt: tomorrow
          }
        }
      })

      if (dailyUsage >= promotion.maxUsesPerDay) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Daily usage limit reached for this promo code", "DAILY_USAGE_LIMIT_REACHED"),
            { status: 400 }
          )
        )
      }
    }

    // Check booking value limits
    if (promotion.minBookingValue && validated.bookingDetails.bookingValue < promotion.minBookingValue) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Minimum booking value of ${promotion.minBookingValue} required`, "MIN_BOOKING_VALUE_NOT_MET"),
          { status: 400 }
        )
      )
    }

    if (promotion.maxBookingValue && validated.bookingDetails.bookingValue > promotion.maxBookingValue) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Maximum booking value of ${promotion.maxBookingValue} allowed`, "MAX_BOOKING_VALUE_EXCEEDED"),
          { status: 400 }
        )
      )
    }

    // Check nights limits
    if (promotion.minNights && validated.bookingDetails.nights && validated.bookingDetails.nights < promotion.minNights) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Minimum stay of ${promotion.minNights} nights required`, "MIN_NIGHTS_NOT_MET"),
          { status: 400 }
        )
      )
    }

    if (promotion.maxNights && validated.bookingDetails.nights && validated.bookingDetails.nights > promotion.maxNights) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, `Maximum stay of ${promotion.maxNights} nights allowed`, "MAX_NIGHTS_EXCEEDED"),
          { status: 400 }
        )
      )
    }

    // Calculate discount amount
    let discountAmount = 0
    let discountType = promotion.type

    switch (promotion.type) {
      case 'PERCENTAGE_OFF':
        discountAmount = (validated.bookingDetails.bookingValue * promotion.value) / 100
        if (promotion.maxDiscount && discountAmount > promotion.maxDiscount) {
          discountAmount = promotion.maxDiscount
        }
        break
      case 'FIXED_AMOUNT_OFF':
        discountAmount = Math.min(promotion.value, validated.bookingDetails.bookingValue)
        break
      case 'DISCOUNT':
        discountAmount = Math.min(promotion.value, validated.bookingDetails.bookingValue)
        break
      case 'FB_CREDIT':
      case 'SPA_CREDIT':
        discountAmount = promotion.value
        break
      default:
        discountAmount = 0
    }

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            promotion: {
              id: promotion.id,
              name: promotion.name,
              type: promotion.type,
              value: promotion.value,
              promoCode: promotion.promoCode
            },
            discountAmount,
            discountType,
            finalAmount: validated.bookingDetails.bookingValue - discountAmount,
            savings: discountAmount,
            isValid: true
          },
          "Promo code validated successfully"
        )
      )
    )
  } catch (error: any) {
    console.error("[Validate Promotion Campaign Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to validate promo code", "VALIDATION_ERROR"),
        { status: 500 }
      )
    )
  }
}
