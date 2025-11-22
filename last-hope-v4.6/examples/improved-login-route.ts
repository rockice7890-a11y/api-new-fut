import { type NextRequest, NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import { prisma } from "@/lib/prisma"
import { generateToken, generateRefreshToken } from "@/lib/auth"
import { loginSchema } from "@/lib/validation"
import { rateLimit } from "@/lib/rate-limit"
import { logAuditEvent, AuditAction } from "@/lib/audit-logger"
import { apiResponse, ErrorCodes, generateRequestId } from "@/lib/api-response-improved"
import { addSecurityHeaders } from "@/lib/security"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const requestId = generateRequestId()
    
    console.log(`[LOGIN_${requestId}] Attempt from IP: ${clientIP}`)

    // Rate limiting check
    const rateLimitCheck = rateLimit(`login:${clientIP}`, 10, 3 * 60 * 1000)
    if (!rateLimitCheck.success) {
      console.warn(`[LOGIN_${requestId}] Rate limit exceeded for IP: ${clientIP}`)
      return apiResponse.tooManyRequests("Too many login attempts. Please wait 3 minutes before trying again.")
    }

    const body = await req.json()
    const validated = loginSchema.parse(body)

    console.log(`[LOGIN_${requestId}] Validated login request for: ${validated.email}`)

    const user = await prisma.user.findUnique({
      where: { email: validated.email.toLowerCase() },
    })

    if (!user) {
      await logAuditEvent(AuditAction.FAILED_AUTH, null, { 
        reason: "User not found",
        requestId 
      }, clientIP)
      
      console.warn(`[LOGIN_${requestId}] Login failed - user not found: ${validated.email}`)
      return apiResponse.unauthorized("Invalid credentials")
    }

    // Check if user is blocked
    if (user.blockInfo && user.blockInfo.isBlocked) {
      await logAuditEvent(AuditAction.FAILED_AUTH, user.id, {
        reason: "User blocked",
        blockReason: user.blockInfo.reason,
        requestId
      }, clientIP)
      
      console.warn(`[LOGIN_${requestId}] Login failed - user blocked: ${user.id}`)
      return apiResponse.forbidden("Account is blocked. Please contact support.")
    }

    const isPasswordValid = await bcrypt.compare(validated.password, user.password)
    if (!isPasswordValid) {
      await logAuditEvent(AuditAction.FAILED_AUTH, user.id, {
        reason: "Invalid password",
        requestId
      }, clientIP)
      
      console.warn(`[LOGIN_${requestId}] Login failed - invalid password for user: ${user.id}`)
      return apiResponse.unauthorized("Invalid credentials")
    }

    // Generate tokens
    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    })

    const refreshToken = generateRefreshToken(user.id)

    // Update last login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    })

    await logAuditEvent(AuditAction.USER_LOGIN, user.id, {
      email: user.email,
      requestId,
      timestamp: new Date().toISOString()
    }, clientIP)

    console.log(`[LOGIN_${requestId}] Successful login for user: ${user.id}`)

    // Remove sensitive data
    const { password, ...userWithoutPassword } = user

    // Prepare response data
    const responseData = {
      user: {
        ...userWithoutPassword,
        lastLoginAt: new Date().toISOString()
      },
      tokens: {
        accessToken: token,
        refreshToken,
        expiresIn: "24h"
      },
      session: {
        requestId,
        loginTime: new Date().toISOString(),
        ipAddress: clientIP
      }
    }

    const response = apiResponse.success(
      responseData,
      "Login successful"
    )

    // Set refresh token cookie
    response.cookies.set("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60,
      path: "/api/auth"
    })

    // Add custom headers
    response.headers.set("X-Request-ID", requestId)
    response.headers.set("X-Rate-Limit-Remaining", rateLimitCheck.remaining.toString())

    return response

  } catch (error: any) {
    console.error(`[LOGIN_ERROR]`, {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    })

    // Handle validation errors specifically
    if (error.name === "ZodError") {
      return apiResponse.badRequest(
        "Invalid input data",
        { validationErrors: error.errors }
      )
    }

    // Handle database errors
    if (error.code === "P2002") {
      return apiResponse.conflict(
        "User already exists",
        "BIZ_002"
      )
    }

    // Generic error response
    return apiResponse.internalError(
      "Login process failed. Please try again.",
      error
    )
  }
}