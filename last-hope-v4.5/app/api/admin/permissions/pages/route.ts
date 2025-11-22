import { type NextRequest, NextResponse } from "next/server"
import { requireAuth, requireRole } from "@/lib/middleware"
import { PermissionsService } from "@/lib/services/permissions.service"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const blockPageSchema = z.object({
  pagePath: z.string(),
  reason: z.enum(["MAINTENANCE", "SYSTEM_DOWN", "UPGRADE", "CUSTOM"]),
  message: z.string(),
  unblockAt: z.date().optional(),
})

export async function POST(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const data = blockPageSchema.parse(await req.json())

    const blocked = await PermissionsService.blockPage(
      data.pagePath,
      data.reason,
      data.message,
      user.id,
      data.unblockAt,
    )

    return NextResponse.json({ status: "success", data: blocked }, { status: 201 })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to block page" },
      { status: 400 },
    )
  }
}

export async function PUT(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const { pagePath } = await req.json()

    const unblocked = await PermissionsService.unblockPage(pagePath)

    return NextResponse.json({ status: "success", data: unblocked })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to unblock page" },
      { status: 400 },
    )
  }
}
