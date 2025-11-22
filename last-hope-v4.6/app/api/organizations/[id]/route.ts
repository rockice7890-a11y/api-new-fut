import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { organizationService } from "@/lib/services/organization.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const organization = await organizationService.getOrganizationById(id)
    if (!organization) return apiResponse.notFound("Organization not found")
    return apiResponse.success(organization, "Organization retrieved successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to retrieve organization: ${errorMessage}`)
  }
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const data = await request.json()
    const { id } = await params
    const organization = await organizationService.updateOrganization(id, data)
    return apiResponse.success(organization, "Organization updated successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to update organization: ${errorMessage}`)
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const { id } = await params
    await organizationService.deleteOrganization(id)
    return apiResponse.success(null, "Organization deleted successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to delete organization: ${errorMessage}`)
  }
}
