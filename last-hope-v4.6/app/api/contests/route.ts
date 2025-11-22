import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const contestSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().optional(),
  type: z.enum(['QUIZ', 'TRIVIA', 'PHOTO', 'REVIEW', 'LOYALTY', 'SEASONAL', 'DAILY', 'WEEKLY', 'MONTHLY']),
  rules: z.string().optional(),
  rewardType: z.enum(['POINTS', 'DISCOUNT', 'FREE_STAY', 'ROOM_UPGRADE', 'SPA_SERVICE', 'RESTAURANT', 'GIFT_CARD', 'CASH']).optional(),
  rewardValue: z.number().optional(),
  rewardDescription: z.string().optional(),
  startDate: z.string().transform((str) => new Date(str)),
  endDate: z.string().transform((str) => new Date(str)),
  maxParticipants: z.number().optional(),
  minPointsToJoin: z.number().optional(),
  imageUrl: z.string().url().optional(),
  terms: z.string().optional(),
})

const participateSchema = z.object({
  contestId: z.string(),
})

// GET /api/contests
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '10')
    const type = searchParams.get('type')
    const status = searchParams.get('status') // 'active', 'ended', 'upcoming'
    
    const skip = (page - 1) * limit

    let whereClause: any = {}
    
    if (type) {
      whereClause.type = type
    }
    
    if (status) {
      const now = new Date()
      switch (status) {
        case 'active':
          whereClause = {
            ...whereClause,
            isActive: true,
            startDate: { lte: now },
            endDate: { gte: now }
          }
          break
        case 'ended':
          whereClause = {
            ...whereClause,
            endDate: { lt: now }
          }
          break
        case 'upcoming':
          whereClause = {
            ...whereClause,
            isActive: true,
            startDate: { gt: now }
          }
          break
      }
    }

    const [contests, totalCount] = await Promise.all([
      prisma.contest.findMany({
        where: whereClause,
        include: {
          participants: {
            select: {
              id: true,
              userId: true,
              score: true,
              completed: true,
            }
          },
          winners: {
            select: {
              id: true,
              userId: true,
              prizeAwarded: true,
            }
          }
        },
        orderBy: [
          { startDate: 'desc' }
        ],
        skip,
        take: limit,
      }),
      prisma.contest.count({ where: whereClause })
    ])

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: {
          contests,
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
    console.error("[Contests GET Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        { status: "error", message: "Failed to fetch contests" },
        { status: 500 }
      )
    )
  }
}

// POST /api/contests (Create contest - Admin only)
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
    const rateLimitCheck = rateLimit(`create_contest:${clientIP}`, 10, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "Too many requests" }, { status: 429 })
      )
    }

    const body = await req.json()
    const validated = contestSchema.parse(body)

    // Validate date range
    if (validated.startDate >= validated.endDate) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "End date must be after start date" },
          { status: 400 }
        )
      )
    }

    const contest = await prisma.contest.create({
      data: {
        ...validated,
      }
    })

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { contest },
        message: "Contest created successfully"
      }, { status: 201 })
    )
  } catch (error: any) {
    console.error("[Contests POST Error]", error)
    
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
      NextResponse.json({ status: "error", message: "Failed to create contest" }, { status: 500 })
    )
  }
}
