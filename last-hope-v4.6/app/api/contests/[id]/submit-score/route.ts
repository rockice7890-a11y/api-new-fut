import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const submitScoreSchema = z.object({
  score: z.number().min(0),
  answers: z.array(z.object({
    questionId: z.string(),
    answer: z.string(),
    correct: z.boolean(),
  })).optional(),
})

// POST /api/contests/[id]/submit-score
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
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
    const validated = submitScoreSchema.parse(body)

    const { id: contestId } = await params

    // Find the contest
    const contest = await prisma.contest.findUnique({
      where: { id: contestId }
    })

    if (!contest) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Contest not found" },
          { status: 404 }
        )
      )
    }

    // Find the participation record
    const participation = await prisma.contestParticipant.findUnique({
      where: {
        contestId_userId: {
          contestId,
          userId: decoded.userId
        }
      }
    })

    if (!participation) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Not participating in this contest" },
          { status: 400 }
        )
      )
    }

    if (participation.completed) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Already submitted score for this contest" },
          { status: 400 }
        )
      )
    }

    // Update the participation with score
    const updatedParticipation = await prisma.contestParticipant.update({
      where: {
        contestId_userId: {
          contestId,
          userId: decoded.userId
        }
      },
      data: {
        score: validated.score,
        completed: true,
        completedAt: new Date()
      }
    })

    // Check if user qualifies for prize (if contest ended)
    const now = new Date()
    if (now > contest.endDate) {
      await checkAndAwardPrizes(contestId)
    }

    // Award loyalty points for participation
    const pointsEarned = Math.floor(validated.score / 10) // 1 point per 10 score points
    if (pointsEarned > 0) {
      await awardLoyaltyPoints(decoded.userId, pointsEarned, `Contest participation - ${contest.title}`)
    }

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { 
          participation: updatedParticipation,
          pointsEarned 
        },
        message: "Score submitted successfully"
      })
    )
  } catch (error: any) {
    console.error("[Contest Submit Score Error]", error)
    
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
      NextResponse.json({ status: "error", message: "Failed to submit score" }, { status: 500 })
    )
  }
}

async function checkAndAwardPrizes(contestId: string) {
  try {
    // Get contest details
    const contest = await prisma.contest.findUnique({
      where: { id: contestId },
      include: {
        participants: {
          orderBy: { score: 'desc' },
          include: { user: true }
        }
      }
    })

    if (!contest) return

    // Award prizes to top performers (if prize exists)
    if (contest.rewardType && contest.rewardValue) {
      const topParticipants = contest.participants.slice(0, 3) // Top 3
      
      for (let i = 0; i < topParticipants.length; i++) {
        const participant = topParticipants[i]
        
        // Check if already awarded
        const existingWinner = await prisma.contestWinner.findFirst({
          where: {
            contestId,
            userId: participant.userId
          }
        })

        if (!existingWinner) {
          await prisma.contestWinner.create({
            data: {
              contestId,
              userId: participant.userId,
              prizeAwarded: false, // User needs to claim
            }
          })

          // Also create a notification for the winner
          await prisma.notification.create({
            data: {
              userId: participant.userId,
              type: 'SPECIAL_OFFER',
              title: `تهانينا! فوز في مسابقة ${contest.title}`,
              message: `حصلت على المركز ${i + 1} وحققت ${participant.score} نقطة. يرجى المطالبة بجائزتك.`,
            }
          })
        }
      }
    }
  } catch (error) {
    console.error("Error awarding prizes:", error)
  }
}

async function awardLoyaltyPoints(userId: string, points: number, description: string) {
  try {
    // Add loyalty points transaction
    await prisma.loyaltyTransaction.create({
      data: {
        userId,
        action: 'CONTEST_WIN',
        points,
        description,
        multiplier: 1.0,
      }
    })

    // Update user's total loyalty points
    await prisma.loyaltyPoint.update({
      where: { userId },
      data: {
        points: { increment: points }
      }
    })
  } catch (error) {
    console.error("Error awarding loyalty points:", error)
  }
}
