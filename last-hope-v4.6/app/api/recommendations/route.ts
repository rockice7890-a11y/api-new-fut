import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const recommendationSchema = z.object({
  userId: z.string(),
  type: z.enum(['ROOM_UPGRADE', 'SERVICE', 'ACTIVITY', 'RESTAURANT', 'SPA', 'LOCAL_TOUR', 'LOYALTY_PROGRAM']),
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(1000),
  data: z.object({}).passthrough().optional(),
  confidence: z.number().min(0).max(1).default(0.5),
  algorithm: z.string().default('collaborative_filtering'),
  factors: z.object({}).passthrough().optional(),
  expiresAt: z.string().transform((str) => new Date(str)).optional(),
})

// GET /api/recommendations (Get recommendations for current user)
export async function GET(req: NextRequest) {
  try {
    const token = req.headers.get('authorization')?.replace('Bearer ', '')
    if (!token) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Authorization required" },
          { status: 401 }
        )
      )
    }

    const decoded = verifyToken(token)
    if (!decoded) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Invalid token" },
          { status: 401 }
        )
      )
    }

    const { searchParams } = new URL(req.url)
    const type = searchParams.get('type')
    const status = searchParams.get('status') // 'all', 'unviewed', 'accepted', 'viewed'
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '10')
    
    const skip = (page - 1) * limit

    let whereClause: any = { 
      userId: decoded.userId,
      OR: [
        { expiresAt: null },
        { expiresAt: { gte: new Date() } }
      ]
    }
    
    if (type) {
      whereClause.type = type
    }
    
    if (status) {
      switch (status) {
        case 'unviewed':
          whereClause.isViewed = false
          break
        case 'accepted':
          whereClause.isAccepted = true
          break
        case 'viewed':
          whereClause.isViewed = true
          break
        case 'declined':
          whereClause.isAccepted = false
          break
      }
    }

    const [recommendations, totalCount] = await Promise.all([
      prisma.recommendation.findMany({
        where: whereClause,
        orderBy: [
          { confidence: 'desc' },
          { createdAt: 'desc' }
        ],
        skip,
        take: limit,
      }),
      prisma.recommendation.count({ where: whereClause })
    ])

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: {
          recommendations,
          pagination: {
            page,
            limit,
            totalCount,
            totalPages: Math.ceil(totalCount / limit),
          }
        }
      })
    )
  } catch (error: any) {
    console.error("[Recommendations GET Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        { status: "error", message: "Failed to fetch recommendations" },
        { status: 500 }
      )
    )
  }
}

// POST /api/recommendations (Generate recommendations for user)
export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get('authorization')?.replace('Bearer ', '')
    if (!token) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Authorization required" },
          { status: 401 }
        )
      )
    }

    const decoded = verifyToken(token)
    if (!decoded || !['ADMIN', 'HOTEL_MANAGER'].includes(decoded.role)) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Insufficient permissions" },
          { status: 403 }
        )
      )
    }

    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`generate_recommendations:${clientIP}`, 20, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "Too many requests" }, { status: 429 })
      )
    }

    const body = await req.json()
    const validated = recommendationSchema.parse(body)

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id: validated.userId }
    })

    if (!user) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "User not found" },
          { status: 404 }
        )
      )
    }

    // Generate personalized recommendations based on user's data
    const personalizedRecommendations = await generatePersonalizedRecommendations(validated.userId)

    const recommendations = await Promise.all([
      // Create the specified recommendation
      prisma.recommendation.create({
        data: { ...validated }
      }),
      // Add personalized recommendations
      ...personalizedRecommendations.map(rec => 
        prisma.recommendation.create({
          data: rec
        })
      )
    ])

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { recommendations },
        message: `Generated ${recommendations.length} recommendations`
      }, { status: 201 })
    )
  } catch (error: any) {
    console.error("[Recommendations POST Error]", error)
    
    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json({
          status: "error",
          message: "Invalid data",
          errors: error.errors
        }, { status: 400 })
      )
    }

    return addSecurityHeaders(
      NextResponse.json({ status: "error", message: "Failed to generate recommendations" }, { status: 500 })
    )
  }
}

async function generatePersonalizedRecommendations(userId: string) {
  try {
    const recommendations = []

    // Get user data for personalization
    const [userBookings, loyaltyPoints, userReviews] = await Promise.all([
      prisma.booking.findMany({
        where: { userId },
        include: {
          room: {
            include: { hotel: true },
            select: { roomType: true, id: true }
          }
        },
        orderBy: { createdAt: 'desc' },
        take: 10
      }),
      prisma.loyaltyPoint.findUnique({ where: { userId } }),
      prisma.review.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: 5
      })
    ])

    // Room upgrade recommendations
    if (userBookings.length > 0) {
      const lastBooking = userBookings[0]
      const currentRoomType = lastBooking.room.roomType
      
      let upgradeRecommendation: any = null
      
      switch (currentRoomType) {
        case 'STANDARD':
          upgradeRecommendation = {
            userId,
            type: 'ROOM_UPGRADE',
            title: 'ترقية غرفة موصى بها',
            description: 'بناءً على إقاماتك السابقة، نوصيك بترقية غرفتك للحصول على تجربة أفضل',
            data: {
              currentRoomType,
              suggestedRoomType: 'DELUXE',
              savings: 200,
            },
            confidence: 0.8,
            algorithm: 'behavioral_analysis',
            factors: {
              bookingFrequency: userBookings.length,
              lastBookingDate: lastBooking.createdAt,
              loyaltyTier: loyaltyPoints?.tier || 'BRONZE'
            },
            expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
          }
          break
      }
      
      if (upgradeRecommendation) {
        recommendations.push(upgradeRecommendation)
      }
    }

    // Loyalty program recommendations
    if (loyaltyPoints && loyaltyPoints.points < 1000) {
      recommendations.push({
        userId,
        type: 'LOYALTY_PROGRAM',
        title: 'برنامج الولاء',
        description: 'اكسب المزيد من النقاط واستمتع بمزايا حصرية',
        data: {
          currentPoints: loyaltyPoints.points,
          pointsToNextTier: 1000 - loyaltyPoints.points,
          nextTier: 'SILVER',
          benefits: ['خصم 5%', 'ترقية مجانية', 'خدمة في الغرفة']
        },
        confidence: 0.9,
        algorithm: 'loyalty_optimization',
        factors: {
          currentTier: loyaltyPoints.tier,
          bookingHistory: userBookings.length
        },
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) // 90 days
      })
    }

    // Service recommendations based on reviews
    const servicePreferences = userReviews.reduce((acc: any, review) => {
      const serviceType = 'general' // serviceType field doesn't exist in Review model
      acc[serviceType] = (acc[serviceType] || 0) + 1
      return acc
    }, {})

    if (servicePreferences.spa > 0) {
      recommendations.push({
        userId,
        type: 'SPA',
        title: 'خدمات السبا المميزة',
        description: 'استمتع بتجربة استرخاء فريدة مع خدمات السبا المتقدمة',
        data: {
          recommendedServices: ['المساج', 'العلاج بالحرارة', 'العلاج البارد'],
          discount: 15,
          duration: '2-3 ساعات'
        },
        confidence: 0.7,
        algorithm: 'collaborative_filtering',
        factors: {
          servicePreferences,
          avgRating: userReviews.reduce((sum, r) => sum + r.rating, 0) / userReviews.length
        },
        expiresAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14 days
      })
    }

    return recommendations
  } catch (error) {
    console.error("Error generating personalized recommendations:", error)
    return []
  }
}
