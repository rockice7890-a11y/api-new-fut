import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { serviceService } from "@/lib/services/service.service"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const { hotelId, name, description, price, icon } = await request.json()

    if (!hotelId || !name || price === undefined) {
      return apiResponse.badRequest("Missing required fields")
    }

    const service = await serviceService.createService(hotelId, {
      name,
      description,
      price,
      icon,
    })

    return apiResponse.success(service, "Service created successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to create service: ${errorMessage}`)
  }
}

export async function GET(request: NextRequest) {
  try {
    const hotelId = request.nextUrl.searchParams.get("hotelId")
    const onlyActive = request.nextUrl.searchParams.get("onlyActive") === "true"

    if (!hotelId) {
      return apiResponse.badRequest("Hotel ID is required")
    }

    const services = await serviceService.getHotelServices(hotelId, onlyActive)
    return apiResponse.success(services, "Services retrieved successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to retrieve services: ${errorMessage}`)
  }
}
