import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Validation Schemas
const createPromotionSchema = z.object({
  hotelId: z.string().optional(),
  name: z.string().min(1).max(200),
  description: z.string().max(1000).optional(),
  type: z.enum([
    'DISCOUNT', 'BUY_GET_FREE', 'PERCENTAGE_OFF', 'FIXED_AMOUNT_OFF',
    'FREE_NIGHT', 'ROOM_UPGRADE', 'FB_CREDIT', 'SPA_CREDIT',
    'TRANSPORT', 'EARLY_CHECKIN', 'LATE_CHECKOUT', 'LOYALTY_MULTIPLIER'
  ]),
  target: z.enum([
    'ALL_USERS', 'NEW_USERS', 'LOYAL_CUSTOMERS', 'CORPORATE',
    'BIRTHDAY_USERS', 'REFERRALS', 'HIGH_VALUE', 'LOW_ACTIVITY',
    'SPECIFIC_USER', 'USER_SEGMENT'
  ]),
  targetCriteria: z.object({}).passthrough().optional(),
  value: z.number().positive(),
  maxDiscount: z.number().positive().optional(),
  minBookingValue: z.number().min(0).optional(),
  maxBookingValue: z.number().positive().optional(),
  validFrom: z.string().transform((str) => new Date(str)),
  validUntil: z.string().transform((str) => new Date(str)),
  maxUses: z.number().positive().optional(),
  maxUsesPerUser: z.number().positive().optional(),
  maxUsesPerDay: z.number().positive().optional(),
  maxUsesPerWeek: z.number().positive().optional(),
  canStackWithOther: z.boolean().default(false),
  stackablePromotions: z.array(z.string()).optional(),
  eligibleCountries: z.array(z.string()).optional(),
  minNights: z.number().positive().optional(),
  maxNights: z.number().positive().optional(),
  totalBudget: z.number().positive().optional(),
  promoCode: z.string().optional(),
  affiliateCode: z.string().optional(),
  bannerImage: z.string().url().optional(),
  termsConditions: z.string().max(2000).optional()
})

const updatePromotionSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().max(1000).optional(),
  status: z.enum(['DRAFT', 'SCHEDULED', 'ACTIVE', 'PAUSED', 'EXPIRED', 'CANCELLED']).optional(),
  value: z.number().positive().optional(),
  maxDiscount: z.number().positive().optional(),
  minBookingValue: z.number().min(0).optional(),
  maxBookingValue: z.number().positive().optional(),
  validFrom: z.string().transform((str) => new Date(str)).optional(),
  validUntil: z.string().transform((str) => new Date(str)).optional(),
  maxUses: z.number().positive().optional(),
  maxUsesPerUser: z.number().positive().optional(),
  maxUsesPerDay: z.number().positive().optional(),
  maxUsesPerWeek: z.number().positive().optional(),
  canStackWithOther: z.boolean().optional(),
  stackablePromotions: z.array(z.string()).optional(),
  eligibleCountries: z.array(z.string()).optional(),
  minNights: z.number().positive().optional(),
  maxNights: z.number().positive().optional(),
  totalBudget: z.number().positive().optional(),
  bannerImage: z.string().url().optional(),
  termsConditions: z.string().max(2000).optional()
})

// GET /api/promotion-campaigns - Get promotion campaigns
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    
    // Pagination
    const page = parseInt(searchParams.get('page') || '1')
    const pageSize = parseInt(searchParams.get('pageSize') || '20')
    
    // Filters
    const hotelId = searchParams.get('hotelId')
    const type = searchParams.get('type')
    const status = searchParams.get('status')
    const target = searchParams.get('target')
    
    // Date filters
    const activeOnly = searchParams.get('activeOnly') === 'true'
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    
    // Search
    const search = searchParams.get('search') // Search in name, description
    
    // Build where clause
    const where: any = {}
    
    // Role-based filtering
    if (auth.payload.role === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { managerId: auth.payload.userId },
        select: { id: true }
      })
      where.hotelId = { in: userHotels.map(h => h.id) }
    }
    
    if (hotelId) where.hotelId = hotelId
    if (type) where.type = type
    if (status) where.status = status
    if (target) where.target = target
    
    // Active campaigns only
    if (activeOnly) {
      const now = new Date()
      where.status = { in: ['ACTIVE', 'SCHEDULED'] }
      where.validFrom = { lte: now }
      where.validUntil = { gte: now }
    }
    
    // Date range filtering
    if (startDate || endDate) {
      where.OR = []
      if (startDate) {
        where.OR.push({
          AND: [
            { validFrom: { lte: new Date(startDate) } },
            { validUntil: { gte: new Date(startDate) } }
          ]
        })
      }
      if (endDate) {
        where.OR.push({
          AND: [
            { validFrom: { lte: new Date(endDate) } },
            { validUntil: { gte: new Date(endDate) } }
          ]
        })
      }
    }
    
    // Search in name and description
    if (search) {
      where.OR = [
        ...(where.OR || []),
        { name: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
        { promoCode: { contains: search, mode: 'insensitive' } }
      ]
    }

    const [promotions, total] = await Promise.all([
      prisma.promotionCampaign.findMany({
        where,
        include: {
          hotel: {
            select: { name: true, city: true }
          },
          _count: {
            select: {
              promotionUsages: true
            }
          }
        },
        orderBy: [
          { status: 'asc' },
          { createdAt: 'desc' }
        ],
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.promotionCampaign.count({ where })
    ])

    // Calculate summary statistics
    const summary = await prisma.promotionCampaign.groupBy({
      by: ['status'],
      where: {
        ...where,
        // Remove pagination for summary
      },
      _count: true,
      _sum: {
        totalUsed: true,
        spentBudget: true
      }
    })

    const totalCampaigns = total
    const activeCampaigns = summary.find(s => s.status === 'ACTIVE')?._count || 0
    const totalUsage = summary.reduce((sum, item) => sum + (item._sum.totalUsed || 0), 0)

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            promotions,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: {
              totalCampaigns,
              activeCampaigns,
              totalUsage
            }
          },
          "Promotion campaigns retrieved successfully"
        )
      )
    )
  } catch (error: any) {
    console.error("[Get Promotion Campaigns Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch promotion campaigns", "FETCH_PROMOTION_CAMPAIGNS_ERROR"),
        { status: 500 }
      )
    )
  }
}

// POST /api/promotion-campaigns - Create new promotion campaign
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`create_promotion:${clientIP}`, 50, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Too many promotion creation requests", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        )
      )
    }

    const body = await req.json()
    const validated = createPromotionSchema.parse(body)

    // Verify hotel access if hotelId provided
    if (validated.hotelId && auth.payload.role === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { 
          managerId: auth.payload.userId,
          id: validated.hotelId
        },
        select: { id: true }
      })
      
      if (userHotels.length === 0) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Access denied to this hotel", "ACCESS_DENIED"),
            { status: 403 }
          )
        )
      }
    }

    // Validate promo code uniqueness if provided
    if (validated.promoCode) {
      const existingPromotion = await prisma.promotionCampaign.findFirst({
        where: { promoCode: validated.promoCode }
      })
      
      if (existingPromotion) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Promo code already exists", "PROMO_CODE_EXISTS"),
            { status: 409 }
          )
        )
      }
    }

    // Validate date range
    if (validated.validFrom >= validated.validUntil) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Valid from date must be before valid until date", "INVALID_DATE_RANGE"),
          { status: 400 }
        )
      )
    }

    // Set initial status
    const now = new Date()
    let status: 'DRAFT' | 'ACTIVE' | 'SCHEDULED' = 'DRAFT'
    if (validated.validFrom <= now && validated.validUntil >= now) {
      status = 'ACTIVE'
    } else if (validated.validFrom > now) {
      status = 'SCHEDULED'
    }

    const promotion = await prisma.promotionCampaign.create({
      data: {
        ...validated,
        hotelId: validated.hotelId || null,
        status,
        costPerUse: validated.totalBudget && validated.maxUses ? 
          validated.totalBudget / validated.maxUses : 0,
        createdBy: auth.payload.userId
      },
      include: {
        hotel: {
          select: { name: true, city: true }
        }
      }
    })

    // Create audit log
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'CREATE',
        resource: 'PROMOTION_CAMPAIGN',
        resourceId: promotion.id,
        endpoint: '/api/promotion-campaigns',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          name: promotion.name,
          type: promotion.type,
          value: promotion.value,
          status: promotion.status
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(promotion, "Promotion campaign created successfully"),
        { status: 201 }
      )
    )
  } catch (error: any) {
    console.error("[Create Promotion Campaign Error]", error)
    
    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse({ errors: error.errors }, "Invalid promotion campaign data", "VALIDATION_ERROR"),
          { status: 400 }
        )
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to create promotion campaign", "CREATE_PROMOTION_CAMPAIGN_ERROR"),
        { status: 500 }
      )
    )
  }
}

// PUT /api/promotion-campaigns - Update promotion campaign
export async function PUT(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const promotionId = searchParams.get('id')
    
    if (!promotionId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promotion campaign ID is required", "MISSING_PROMOTION_CAMPAIGN_ID"),
          { status: 400 }
        )
      )
    }

    // Verify promotion exists and user has access
    const existingPromotion = await prisma.promotionCampaign.findUnique({
      where: { id: promotionId },
      include: { hotel: true }
    })

    if (!existingPromotion) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promotion campaign not found", "PROMOTION_CAMPAIGN_NOT_FOUND"),
          { status: 404 }
        )
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && 
        existingPromotion.hotel && 
        existingPromotion.hotel.managerId !== auth.payload.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this promotion campaign", "ACCESS_DENIED"),
          { status: 403 }
        )
      )
    }

    const body = await req.json()
    const validated = updatePromotionSchema.parse(body)

    // Prevent changes to locked campaigns
    if (['EXPIRED', 'CANCELLED'].includes(existingPromotion.status)) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Cannot update expired or cancelled promotion campaigns", "INVALID_OPERATION"),
          { status: 400 }
        )
      )
    }

    const updateData: any = { ...validated }

    // Auto-update status based on dates
    if (validated.validFrom || validated.validUntil) {
      const now = new Date()
      const validFrom = validated.validFrom || existingPromotion.validFrom
      const validUntil = validated.validUntil || existingPromotion.validUntil
      
      if (validFrom <= now && validUntil >= now) {
        updateData.status = 'ACTIVE'
      } else if (validFrom > now) {
        updateData.status = 'SCHEDULED'
      }
    }

    // Recalculate cost per use if budget or max uses changed
    if (validated.totalBudget || validated.maxUses) {
      const totalBudget = validated.totalBudget || existingPromotion.totalBudget
      const maxUses = validated.maxUses || existingPromotion.maxUses
      updateData.costPerUse = totalBudget && maxUses ? totalBudget / maxUses : 0
    }

    const updatedPromotion = await prisma.promotionCampaign.update({
      where: { id: promotionId },
      data: updateData,
      include: {
        hotel: {
          select: { name: true, city: true }
        }
      }
    })

    // Create audit log
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'UPDATE',
        resource: 'PROMOTION_CAMPAIGN',
        resourceId: promotionId,
        endpoint: '/api/promotion-campaigns',
        method: 'PUT',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          name: existingPromotion.name,
          status: existingPromotion.status,
          value: existingPromotion.value
        }),
        newValues: JSON.stringify({
          name: updatedPromotion.name,
          status: updatedPromotion.status,
          value: updatedPromotion.value
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(updatedPromotion, "Promotion campaign updated successfully")
      )
    )
  } catch (error: any) {
    console.error("[Update Promotion Campaign Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to update promotion campaign", "UPDATE_PROMOTION_CAMPAIGN_ERROR"),
        { status: 500 }
      )
    )
  }
}

// DELETE /api/promotion-campaigns - Cancel promotion campaign
export async function DELETE(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const promotionId = searchParams.get('id')
    
    if (!promotionId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promotion campaign ID is required", "MISSING_PROMOTION_CAMPAIGN_ID"),
          { status: 400 }
        )
      )
    }

    // Verify promotion exists and user has access
    const existingPromotion = await prisma.promotionCampaign.findUnique({
      where: { id: promotionId },
      include: { hotel: true }
    })

    if (!existingPromotion) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Promotion campaign not found", "PROMOTION_CAMPAIGN_NOT_FOUND"),
          { status: 404 }
        )
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && 
        existingPromotion.hotel && 
        existingPromotion.hotel.managerId !== auth.payload.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this promotion campaign", "ACCESS_DENIED"),
          { status: 403 }
        )
      )
    }

    // Cancel promotion instead of deleting
    await prisma.promotionCampaign.update({
      where: { id: promotionId },
      data: { 
        status: 'CANCELLED',
        updatedAt: new Date()
      }
    })

    // Create audit log
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'UPDATE',
        resource: 'PROMOTION_CAMPAIGN',
        resourceId: promotionId,
        endpoint: '/api/promotion-campaigns',
        method: 'DELETE',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          status: existingPromotion.status
        }),
        newValues: JSON.stringify({
          status: 'CANCELLED'
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(null, "Promotion campaign cancelled successfully")
      )
    )
  } catch (error: any) {
    console.error("[Cancel Promotion Campaign Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to cancel promotion campaign", "CANCEL_PROMOTION_CAMPAIGN_ERROR"),
        { status: 500 }
      )
    )
  }
}