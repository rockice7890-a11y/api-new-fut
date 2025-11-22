import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { prisma } from "@/lib/prisma"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const { bookingId, serviceId, quantity = 1 } = await request.json()

    if (!bookingId || !serviceId) {
      return apiResponse.badRequest("Missing required fields")
    }

    // الحصول على سعر الخدمة
    const service = await prisma.service.findUnique({
      where: { id: serviceId },
    })

    if (!service) {
      return apiResponse.notFound("Service not found")
    }

    const bookingService = await prisma.bookingService.create({
      data: {
        bookingId,
        serviceId,
        quantity,
        price: service.price,
      },
    })

    return apiResponse.success(bookingService, "Service added to booking successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to add service to booking: ${errorMessage}`)
  }
}

export async function GET(request: NextRequest) {
  try {
    const bookingId = request.nextUrl.searchParams.get("bookingId")

    if (!bookingId) {
      return apiResponse.badRequest("Booking ID is required")
    }

    const services = await prisma.bookingService.findMany({
      where: { bookingId },
      include: { service: true },
    })

    return apiResponse.success(services, "Booking services retrieved successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to retrieve booking services: ${errorMessage}`)
  }
}
