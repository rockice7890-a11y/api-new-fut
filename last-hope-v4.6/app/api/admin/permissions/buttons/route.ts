import { type NextRequest, NextResponse } from "next/server"
import { requireAuth, requireRole } from "@/lib/middleware"
import { PermissionsService } from "@/lib/services/permissions.service"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const buttonPermissionSchema = z.object({
  buttonName: z.string(),
  isHidden: z.boolean().optional(),
  isDisabled: z.boolean().optional(),
  message: z.string().optional(),
})

export async function POST(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const data = buttonPermissionSchema.parse(await req.json())

    const permission = await PermissionsService.setButtonPermission(
      data.buttonName,
      data.isHidden || false,
      data.isDisabled || false,
      data.message,
    )

    return NextResponse.json({ status: "success", data: permission }, { status: 201 })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to set button permission" },
      { status: 400 },
    )
  }
}

export async function GET(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const buttons = await PermissionsService.getAllButtonPermissions()

    return NextResponse.json({ status: "success", data: buttons })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to fetch button permissions" },
      { status: 400 },
    )
  }
}
