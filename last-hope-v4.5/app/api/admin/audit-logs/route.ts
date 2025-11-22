import { type NextRequest, NextResponse } from "next/server"
import { requireAuth, requireRole } from "@/lib/middleware"
import { PermissionsService } from "@/lib/services/permissions.service"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const { searchParams } = new URL(req.url)
    const action = searchParams.get("action") || undefined
    const resource = searchParams.get("resource") || undefined
    const limit = Number.parseInt(searchParams.get("limit") || "100")

    const logs = await PermissionsService.getAuditLogs(action || undefined, resource || undefined, limit)

    return NextResponse.json({ status: "success", data: logs })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to fetch audit logs" },
      { status: 400 },
    )
  }
}
