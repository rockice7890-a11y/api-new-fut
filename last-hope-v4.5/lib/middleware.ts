import { type NextRequest, NextResponse } from "next/server"
import { extractToken, verifyToken } from "./auth"
import type { UserRole } from "@prisma/client"

export async function withAuth(
  req: NextRequest,
  requiredRoles?: UserRole[],
): Promise<{ isValid: boolean; payload?: any; response?: NextResponse }> {
  const token = extractToken(req.headers.get("authorization") || undefined)

  if (!token) {
    return {
      isValid: false,
      response: NextResponse.json({ status: "error", message: "Unauthorized: Missing token" }, { status: 401 }),
    }
  }

  const payload = verifyToken(token)
  if (!payload) {
    return {
      isValid: false,
      response: NextResponse.json({ status: "error", message: "Unauthorized: Invalid token" }, { status: 401 }),
    }
  }

  if (requiredRoles && !requiredRoles.includes(payload.role)) {
    return {
      isValid: false,
      response: NextResponse.json({ status: "error", message: "Forbidden: Insufficient permissions" }, { status: 403 }),
    }
  }

  return { isValid: true, payload }
}

export async function authenticate(req: any): Promise<any> {
  const token = extractToken(req.headers.get("authorization") || undefined)

  if (!token) {
    return null
  }

  const payload = verifyToken(token)
  if (!payload) {
    return null
  }

  return payload
}

export async function authenticateRequest(req: any): Promise<any> {
  return authenticate(req)
}

export async function requireAuth(req: NextRequest): Promise<any> {
  const result = await withAuth(req)
  if (!result.isValid || result.response) {
    throw result.response || new Error("Unauthorized")
  }
  return result.payload
}

export async function requireRole(req: NextRequest, roles: string[]): Promise<void> {
  const result = await withAuth(req, roles as any)
  if (!result.isValid || result.response) {
    throw result.response || new Error("Insufficient permissions")
  }
}
