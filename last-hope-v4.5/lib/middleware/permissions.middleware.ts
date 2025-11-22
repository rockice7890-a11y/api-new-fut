import { type NextRequest, NextResponse } from "next/server"
import { PermissionsService } from "@/lib/services/permissions.service"
import { verifyToken } from "@/lib/auth"

export async function checkPagePermission(req: NextRequest) {
  try {
    const pathname = req.nextUrl.pathname
    const token = req.headers.get("authorization")?.replace("Bearer ", "")

    if (!token) {
      // Check if page is blocked for unauthenticated users
      const blockStatus = await PermissionsService.isPageBlocked(pathname, "GUEST" as any)
      if (blockStatus.blocked) {
        return NextResponse.json(
          {
            status: "error",
            code: "PAGE_BLOCKED",
            message: blockStatus.message || "This page is currently blocked",
            reason: blockStatus.reason,
          },
          { status: 403 },
        )
      }
      return null // No permission issue
    }

    const decoded = verifyToken(token)
    if (!decoded) {
      return NextResponse.json({ status: "error", message: "Invalid token" }, { status: 401 })
    }

    const blockStatus = await PermissionsService.isPageBlocked(pathname, decoded.role)
    if (blockStatus.blocked) {
      return NextResponse.json(
        {
          status: "error",
          code: "PAGE_BLOCKED",
          message: blockStatus.message || "This page is currently blocked",
          reason: blockStatus.reason,
        },
        { status: 403 },
      )
    }

    return null // No permission issue
  } catch (error) {
    console.error("Permission check error:", error)
    return null
  }
}

export async function checkFeatureAccess(featureName: string, userRole: string) {
  try {
    const isEnabled = await PermissionsService.isFeatureEnabled(featureName, userRole as any)
    return isEnabled
  } catch (error) {
    console.error("Feature check error:", error)
    return false
  }
}

export async function authorize(userId: string, requiredRole: string) {
  // Basic authorization check - can be expanded based on your needs
  return true
}
