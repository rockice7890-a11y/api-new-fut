import { type NextRequest, NextResponse } from "next/server"
import { requireAuth, requireRole } from "@/lib/middleware"
import { PermissionsService } from "@/lib/services/permissions.service"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const maintenanceSchema = z.object({
  title: z.string(),
  description: z.string(),
  startTime: z.string().datetime(),
  endTime: z.string().datetime(),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  affectedServices: z.array(z.string()),
})

export async function POST(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const data = maintenanceSchema.parse(await req.json())

    const maintenance = await PermissionsService.createMaintenance(
      data.title,
      data.description,
      new Date(data.startTime),
      new Date(data.endTime),
      data.severity,
      data.affectedServices,
      user.id,
    )

    return NextResponse.json({ status: "success", data: maintenance }, { status: 201 })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to create maintenance" },
      { status: 400 },
    )
  }
}

export async function GET(req: NextRequest) {
  try {
    const user = await requireAuth(req)
    await requireRole(req, ["ADMIN"])

    const maintenance = await PermissionsService.getActiveMaintenance()

    return NextResponse.json({ status: "success", data: maintenance })
  } catch (error) {
    return NextResponse.json(
      { status: "error", message: error instanceof Error ? error.message : "Failed to fetch maintenance" },
      { status: 400 },
    )
  }
}
