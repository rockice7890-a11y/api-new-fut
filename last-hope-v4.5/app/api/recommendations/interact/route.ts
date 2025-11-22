import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const interactionSchema = z.object({
  recommendationId: z.string(),
  action: z.enum(['viewed', 'accepted', 'rejected', 'clicked']),
  metadata: z.object({}).passthrough().optional(),
})

// PATCH /api/recommendations/interact
export async function PATCH(req: NextRequest) {
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

    const body = await req.json()
    const validated = interactionSchema.parse(body)

    // Find the recommendation
    const recommendation = await prisma.recommendation.findUnique({
      where: { id: validated.recommendationId }
    })

    if (!recommendation) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Recommendation not found" },
          { status: 404 }
        )
      )
    }

    // Verify the recommendation belongs to the current user
    if (recommendation.userId !== decoded.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Unauthorized access to recommendation" },
          { status: 403 }
        )
      )
    }

    // Update recommendation based on action
    let updateData: any = {}
    let message = ''
    let awardPoints = false

    switch (validated.action) {
      case 'viewed':
        updateData = {
          isViewed: true,
          viewedAt: new Date(),
          isClicked: true
        }
        message = 'Recommendation marked as viewed'
        break

      case 'accepted':
        updateData = {
          isViewed: true,
          viewedAt: new Date(),
          isAccepted: true,
          acceptedAt: new Date()
        }
        message = 'Recommendation accepted'
        awardPoints = true
        break

      case 'rejected':
        updateData = {
          isViewed: true,
          viewedAt: new Date(),
          isAccepted: false,
          acceptedAt: new Date()
        }
        message = 'Recommendation rejected'
        break

      case 'clicked':
        updateData = {
          isClicked: true
        }
        message = 'Recommendation clicked'
        break
    }

    // Add interaction metadata
    if (validated.metadata) {
      const currentFactors = recommendation.factors && typeof recommendation.factors === 'object' 
        ? recommendation.factors as Record<string, any>
        : {}
      
      const currentInteractionHistory = currentFactors.interactionHistory && typeof currentFactors.interactionHistory === 'object'
        ? currentFactors.interactionHistory as Record<string, any>
        : {}

      updateData.factors = {
        ...currentFactors,
        ...validated.metadata,
        interactionHistory: {
          ...currentInteractionHistory,
          [validated.action]: new Date().toISOString()
        }
      }
    }

    const updatedRecommendation = await prisma.recommendation.update({
      where: { id: validated.recommendationId },
      data: updateData
    })

    // Award loyalty points for accepting recommendations
    let pointsEarned = 0
    if (awardPoints) {
      pointsEarned = await awardRecommendationPoints(decoded.userId, validated.recommendationId, recommendation.type)
    }

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { 
          recommendation: updatedRecommendation,
          pointsEarned,
          interaction: validated.action
        },
        message
      })
    )
  } catch (error: any) {
    console.error("[Recommendation Interaction Error]", error)
    
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
      NextResponse.json({ status: "error", message: "Failed to update recommendation" }, { status: 500 })
    )
  }
}

async function awardRecommendationPoints(userId: string, recommendationId: string, recommendationType: string): Promise<number> {
  try {
    // Calculate points based on recommendation type and engagement
    let points = 0
    
    switch (recommendationType) {
      case 'ROOM_UPGRADE':
        points = 25
        break
      case 'SERVICE':
        points = 15
        break
      case 'ACTIVITY':
        points = 10
        break
      case 'RESTAURANT':
        points = 12
        break
      case 'SPA':
        points = 20
        break
      case 'LOCAL_TOUR':
        points = 18
        break
      case 'LOYALTY_PROGRAM':
        points = 30
        break
      default:
        points = 5
    }

    // Add loyalty points transaction
    await prisma.loyaltyTransaction.create({
      data: {
        userId,
        action: 'GAME_WIN',
        points,
        description: `accepted_recommendation_${recommendationType}`,
        referenceId: recommendationId,
        multiplier: 1.0,
      }
    })

    // Update user's total loyalty points
    const updatedUser = await prisma.loyaltyPoint.upsert({
      where: { userId },
      update: {
        points: { increment: points }
      },
      create: {
        userId,
        points: points,
        tier: getLoyaltyTier(points),
      }
    })

    // Check for tier upgrade
    const currentTier = updatedUser.tier
    const newTier = getLoyaltyTier(updatedUser.points)
    
    if (currentTier !== newTier) {
      await prisma.loyaltyPoint.update({
        where: { userId },
        data: { tier: newTier }
      })

      // Send tier upgrade notification
      await prisma.notification.create({
        data: {
          userId,
          type: 'SPECIAL_OFFER',
          title: 'تهانينا! ترقية في برنامج الولاء',
          message: `لقد تمت ترقيتك إلى فئة ${newTier}`,
        }
      })
    }

    return points
  } catch (error) {
    console.error("Error awarding recommendation points:", error)
    return 0
  }
}

function getLoyaltyTier(points: number): string {
  if (points >= 15000) return 'PLATINUM'
  if (points >= 5000) return 'GOLD'
  if (points >= 1000) return 'SILVER'
  return 'BRONZE'
}
