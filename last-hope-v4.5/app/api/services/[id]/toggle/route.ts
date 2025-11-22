import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { serviceService } from "@/lib/services/service.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const { id } = await params
    const service = await serviceService.toggleService(id)
    return apiResponse.success(service, "Service status toggled successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to toggle service: ${errorMessage}`)
  }
}
