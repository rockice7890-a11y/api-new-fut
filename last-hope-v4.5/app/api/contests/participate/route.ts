import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const participateSchema = z.object({
  contestId: z.string(),
})

const submitScoreSchema = z.object({
  contestId: z.string(),
  score: z.number().min(0),
})

// POST /api/contests/participate
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
    if (!decoded) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Invalid token" },
          { status: 401 }
        )
      )
    }

    const body = await req.json()
    const validated = participateSchema.parse(body)

    // Check if contest exists and is active
    const contest = await prisma.contest.findUnique({
      where: { id: validated.contestId }
    })

    if (!contest) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Contest not found" },
          { status: 404 }
        )
      )
    }

    if (!contest.isActive) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Contest is not active" },
          { status: 400 }
        )
      )
    }

    const now = new Date()
    if (now < contest.startDate) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Contest has not started yet" },
          { status: 400 }
        )
      )
    }

    if (now > contest.endDate) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Contest has ended" },
          { status: 400 }
        )
      )
    }

    // Check if already participating
    const existingParticipation = await prisma.contestParticipant.findUnique({
      where: {
        contestId_userId: {
          contestId: validated.contestId,
          userId: decoded.userId
        }
      }
    })

    if (existingParticipation) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Already participating in this contest" },
          { status: 400 }
        )
      )
    }

    // Check max participants limit
    if (contest.maxParticipants) {
      const participantCount = await prisma.contestParticipant.count({
        where: { contestId: validated.contestId }
      })

      if (participantCount >= contest.maxParticipants) {
        return addSecurityHeaders(
          NextResponse.json(
            { status: "error", message: "Contest has reached maximum participants" },
            { status: 400 }
          )
        )
      }
    }

    // Check minimum loyalty points requirement
    if (contest.minPointsToJoin) {
      const userLoyalty = await prisma.loyaltyPoint.findUnique({
        where: { userId: decoded.userId }
      })

      if (!userLoyalty || userLoyalty.points < contest.minPointsToJoin) {
        return addSecurityHeaders(
          NextResponse.json(
            { status: "error", message: "Insufficient loyalty points to join this contest" },
            { status: 400 }
          )
        )
      }
    }

    // Create participation
    const participation = await prisma.contestParticipant.create({
      data: {
        contestId: validated.contestId,
        userId: decoded.userId,
      }
    })

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { participation },
        message: "Successfully joined the contest"
      }, { status: 201 })
    )
  } catch (error: any) {
    console.error("[Contests Participate Error]", error)
    
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
      NextResponse.json({ status: "error", message: "Failed to join contest" }, { status: 500 })
    )
  }
}
