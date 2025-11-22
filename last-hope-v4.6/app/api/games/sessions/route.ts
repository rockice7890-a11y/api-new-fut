import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { verifyToken } from "@/lib/auth"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const createSessionSchema = z.object({
  gameId: z.string(),
})

const updateSessionSchema = z.object({
  sessionId: z.string(),
  score: z.number().min(0),
  maxScore: z.number().min(1),
  completed: z.boolean().default(false),
  progress: z.object({}).passthrough().optional(),
  attempts: z.number().min(1).default(1),
})

// GET /api/games/sessions (User's game sessions)
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
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '10')
    const gameId = searchParams.get('gameId')
    
    const skip = (page - 1) * limit

    let whereClause: any = { userId: decoded.userId }
    
    if (gameId) {
      whereClause.gameId = gameId
    }

    const [sessions, totalCount] = await Promise.all([
      prisma.gameSession.findMany({
        where: whereClause,
        include: {
          game: {
            select: {
              id: true,
              title: true,
              type: true,
              difficulty: true,
              imageUrl: true,
            }
          }
        },
        orderBy: [
          { completedAt: 'desc' }
        ],
        skip,
        take: limit,
      }),
      prisma.gameSession.count({ where: whereClause })
    ])

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: {
          sessions,
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
    console.error("[Game Sessions GET Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        { status: "error", message: "Failed to fetch game sessions" },
        { status: 500 }
      )
    )
  }
}

// POST /api/games/sessions (Start a new game session)
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

    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`start_game:${decoded.userId}`, 50, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "Too many requests" }, { status: 429 })
      )
    }

    const body = await req.json()
    const validated = createSessionSchema.parse(body)

    // Check if game exists and is active
    const game = await prisma.game.findUnique({
      where: { id: validated.gameId, isActive: true }
    })

    if (!game) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Game not found or inactive" },
          { status: 404 }
        )
      )
    }

    // Create new game session
    const session = await prisma.gameSession.create({
      data: {
        gameId: validated.gameId,
        userId: decoded.userId,
        score: 0,
        maxScore: game.maxScore,
        completed: false,
        attempts: 1,
      }
    })

    return addSecurityHeaders(
      NextResponse.json({
        status: "success",
        data: { session, game },
        message: "Game session started successfully"
      }, { status: 201 })
    )
  } catch (error: any) {
    console.error("[Game Sessions POST Error]", error)
    
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
      NextResponse.json({ status: "error", message: "Failed to start game session" }, { status: 500 })
    )
  }
}
