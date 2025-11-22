import { type NextRequest, NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import { prisma } from "@/lib/prisma"
import { generateToken, generateRefreshToken } from "@/lib/auth"
import { registerSchema } from "@/lib/validation"
import { rateLimit } from "@/lib/rate-limit"
import { addSecurityHeaders } from "@/lib/security"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`register:${clientIP}`, 5, 15 * 60 * 1000) // 5 attempts per 15 min
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          { status: "error", message: "Too many registration attempts. Try again later." },
          { status: 429 },
        ),
      )
    }

    const body = await req.json()
    const validated = registerSchema.parse(body)

    const existingUser = await prisma.user.findUnique({
      where: { email: validated.email.toLowerCase() }, // Ensure email is lowercase
    })

    if (existingUser) {
      await logAuditEvent(
        AuditAction.FAILED_AUTH,
        null,
        { reason: "User already exists", email: validated.email },
        clientIP,
      )
      return addSecurityHeaders(
        NextResponse.json({ status: "error", message: "User already exists", code: "USER_EXISTS" }, { status: 400 }),
      )
    }

    const hashedPassword = await bcrypt.hash(validated.password, 12) // Increased rounds for security

    const user = await prisma.user.create({
      data: {
        email: validated.email.toLowerCase(),
        password: hashedPassword,
        firstName: validated.firstName,
        lastName: validated.lastName,
        role: "USER",
      },
      select: { id: true, email: true, role: true },
    })

    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    })

    const refreshToken = generateRefreshToken(user.id)

    await logAuditEvent(AuditAction.USER_REGISTER, user.id, { email: user.email }, clientIP)

    const response = addSecurityHeaders(
      NextResponse.json(
        {
          status: "success",
          data: { user, token, refreshToken },
          message: "User registered successfully",
        },
        { status: 201 },
      ),
    )

    response.cookies.set("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60, // 7 days
    })

    return response
  } catch (error: any) {
    console.error("[Register Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        {
          status: "error",
          message: error.message?.includes("validation") ? "Invalid input" : "Registration failed",
        },
        { status: 500 },
      ),
    )
  }
}
