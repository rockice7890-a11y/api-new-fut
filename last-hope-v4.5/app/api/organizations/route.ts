import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { organizationService } from "@/lib/services/organization.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const data = await request.json()

    if (!data.name) {
      return apiResponse.badRequest("Organization name is required")
    }

    const organization = await organizationService.createOrganization(data)
    return apiResponse.success(organization, "Organization created successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to create organization: ${errorMessage}`)
  }
}

export async function GET(request: NextRequest) {
  try {
    const hotelId = request.nextUrl.searchParams.get("hotelId")
    const organizations = await organizationService.getAllOrganizations(hotelId || undefined)
    return apiResponse.success(organizations, "Organizations retrieved successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to retrieve organizations: ${errorMessage}`)
  }
}
