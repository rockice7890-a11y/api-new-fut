import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const gameSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().optional(),
  type: z.enum(['WORD_PUZZLE', 'MEMORY', 'MATCHING', 'QUIZ', 'WORD_SEARCH', 'CROSSWORD']),
  instructions: z.string().optional(),
  difficulty: z.enum(['easy', 'medium', 'hard']).default('easy'),
  estimatedTime: z.number().optional(),
  maxScore: z.number().min(1).max(1000).default(100),
  content: z.string().optional(),
  rewards: z.object({}).passthrough().optional(),
  pointsPerWin: z.number().min(1).max(100).default(10),
  imageUrl: z.string().url().optional(),
  videoUrl: z.string().url().optional(),
})

const sessionSchema = z.object({
  gameId: z.string(),
  score: z.number().min(0),
  maxScore: z.number().min(1),
  completed: z.boolean().default(false),
  progress: z.object({}).passthrough().optional(),
  attempts: z.number().min(1).default(1),
})

// GET /api/games
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '10')
    const type = searchParams.get('type')
    const difficulty = searchParams.get('difficulty')
    
    const skip = (page - 1) * limit

    let whereClause: any = { isActive: true }
    
    if (type) {
      whereClause.type = type
    }
    
    if (difficulty) {
      whereClause.difficulty = difficulty
    }

    const [games, totalCount] = await Promise.all([
      prisma.game.findMany({
        where: whereClause,
        include: {
          gameSessions: {
            where: {
              completed: true
            },
            select: {
              id: true,
              score: true,
              userId: true,
              completedAt: true,
            },
            orderBy: { score: 'desc' },
            take: 5, // Top 5 scores
          }
        },
        orderBy: [
          { difficulty: 'asc' },
          { title: 'asc' }
        ],
        skip,
        take: limit,
      }),
      prisma.game.count({ where: whereClause })
    ])

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: {
          games,
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
    console.error("[Games GET Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        { status: "error", message: "Failed to fetch games" },
        { status: 500 }
      )
    )
  }
}

// POST /api/games (Create game - Admin only)
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
    const rateLimitCheck = rateLimit(`create_game:${clientIP}`, 10, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "Too many requests" }, { status: 429 })
      )
    }

    const body = await req.json()
    const validated = gameSchema.parse(body)

    const game = await prisma.game.create({
      data: {
        ...validated,
      }
    })

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { game },
        message: "Game created successfully"
      }, { status: 201 })
    )
  } catch (error: any) {
    console.error("[Games POST Error]", error)
    
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
      NextResponse.json({ status: "error", message: "Failed to create game" }, { status: 500 })
    )
  }
}
