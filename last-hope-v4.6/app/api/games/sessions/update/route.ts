import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const updateSessionSchema = z.object({
  sessionId: z.string(),
  score: z.number().min(0),
  maxScore: z.number().min(1),
  completed: z.boolean().default(false),
  progress: z.object({}).passthrough().optional(),
  attempts: z.number().min(1).default(1),
})

// PATCH /api/games/sessions/update
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
    const validated = updateSessionSchema.parse(body)

    // Find the game session
    const session = await prisma.gameSession.findUnique({
      where: { id: validated.sessionId },
      include: { game: true }
    })

    if (!session) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Game session not found" },
          { status: 404 }
        )
      )
    }

    // Verify the session belongs to the current user
    if (session.userId !== decoded.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Unauthorized access to game session" },
          { status: 403 }
        )
      )
    }

    // Update the session
    const updatedSession = await prisma.gameSession.update({
      where: { id: validated.sessionId },
      data: {
        score: validated.score,
        maxScore: validated.maxScore,
        completed: validated.completed,
        progress: validated.progress,
        attempts: validated.attempts,
        ...(validated.completed ? { completedAt: new Date() } : {}),
      }
    })

    // Award loyalty points if game completed successfully
    let pointsEarned = 0
    if (validated.completed && validated.score > 0) {
      const basePoints = session.game.pointsPerWin
      const performanceMultiplier = validated.score / validated.maxScore
      pointsEarned = Math.floor(basePoints * performanceMultiplier)
      
      if (pointsEarned > 0) {
        await awardGameLoyaltyPoints(decoded.userId, pointsEarned, `Game completion - ${session.game.title}`)
      }
    }

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { 
          session: updatedSession,
          pointsEarned,
          performance: {
            score: validated.score,
            maxScore: validated.maxScore,
            percentage: Math.round((validated.score / validated.maxScore) * 100)
          }
        },
        message: validated.completed ? "Game completed successfully" : "Game session updated"
      })
    )
  } catch (error: any) {
    console.error("[Game Session Update Error]", error)
    
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
      NextResponse.json({ status: "error", message: "Failed to update game session" }, { status: 500 })
    )
  }
}

async function awardGameLoyaltyPoints(userId: string, points: number, description: string) {
  try {
    // Add loyalty points transaction
    await prisma.loyaltyTransaction.create({
      data: {
        userId,
        action: 'GAME_WIN',
        points,
        description,
        multiplier: 1.0,
      }
    })

    // Update user's total loyalty points
    await prisma.loyaltyPoint.upsert({
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

    // Update user's loyalty tier if needed
    const userPoints = await prisma.loyaltyPoint.findUnique({
      where: { userId }
    })

    if (userPoints) {
      const newTier = getLoyaltyTier(userPoints.points)
      if (newTier !== userPoints.tier) {
        await prisma.loyaltyPoint.update({
          where: { userId },
          data: { tier: newTier }
        })

        // Send tier upgrade notification
        await prisma.notification.create({
          data: {
            userId,
            type: 'SPECIAL_OFFER',
            title: 'ترقية في برنامج الولاء!',
            message: `تهانينا! لقد تمت ترقيتك إلى فئة ${newTier}`,
          }
        })
      }
    }
  } catch (error) {
    console.error("Error awarding game loyalty points:", error)
  }
}

function getLoyaltyTier(points: number): string {
  if (points >= 15000) return 'PLATINUM'
  if (points >= 5000) return 'GOLD'
  if (points >= 1000) return 'SILVER'
  return 'BRONZE'
}
