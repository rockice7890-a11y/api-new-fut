import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { serviceService } from "@/lib/services/service.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const service = await serviceService.getServiceById(id)
    if (!service) return apiResponse.notFound("Service not found")
    return apiResponse.success(service, "Service retrieved successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to retrieve service: ${errorMessage}`)
  }
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const data = await request.json()
    const { id } = await params
    const service = await serviceService.updateService(id, data)
    return apiResponse.success(service, "Service updated successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to update service: ${errorMessage}`)
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const { id } = await params
    await serviceService.deleteService(id)
    return apiResponse.success(null, "Service deleted successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to delete service: ${errorMessage}`)
  }
}
