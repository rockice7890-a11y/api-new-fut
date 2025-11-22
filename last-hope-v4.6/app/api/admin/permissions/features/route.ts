import { type NextRequest, NextResponse } from "next/server"
import { requireAuth, requireRole } from "@/lib/middleware"
import { PermissionsService } from "@/lib/services/permissions.service"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const featureToggleSchema = z.object({
  featureName: z.string(),
  isEnabled: z.boolean(),
  description: z.string().optional(),
})

export async function POST(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const data = featureToggleSchema.parse(await req.json())

    const feature = await PermissionsService.toggleFeature(data.featureName, data.isEnabled, user.id)

    return NextResponse.json({ status: "success", data: feature }, { status: 201 })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to toggle feature" },
      { status: 400 },
    )
  }
}
