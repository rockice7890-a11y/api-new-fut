import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { organizationService } from "@/lib/services/organization.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const { id } = await params
    const organization = await organizationService.toggleOrganization(id)
    return apiResponse.success(organization, "Organization status toggled successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to toggle organization: ${errorMessage}`)
  }
}
