import type { NextRequest } from "next/server"
import { apiResponse } from "@/lib/api-response"
import { prisma } from "@/lib/prisma"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams

    const query = searchParams.get("query") || ""
    const city = searchParams.get("city")
    const country = searchParams.get("country")
    const minPrice = searchParams.get("minPrice")
    const maxPrice = searchParams.get("maxPrice")
    const rating = searchParams.get("rating")
    const amenities = searchParams.getAll("amenities")
    const checkIn = searchParams.get("checkIn")
    const checkOut = searchParams.get("checkOut")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const limit = Math.min(Number.parseInt(searchParams.get("limit") || "20"), 100)

    // Build complex filter
    const where: any = {}

    if (query) {
      where.OR = [
        { name: { contains: query, mode: "insensitive" } },
        { description: { contains: query, mode: "insensitive" } },
        { city: { contains: query, mode: "insensitive" } },
      ]
    }

    if (city) where.city = { contains: city, mode: "insensitive" }
    if (country) where.country = { contains: country, mode: "insensitive" }
    if (rating) where.rating = { gte: Number.parseFloat(rating) }

    const hotels = await prisma.hotel.findMany({
      where,
      include: {
        rooms: {
          include: {
            inventory: {
              where: {
                ...(checkIn &&
                  checkOut && {
                    date: {
                      gte: new Date(checkIn),
                      lte: new Date(checkOut),
                    },
                  }),
              },
            },
          },
        },
        _count: { select: { reviews: true } },
      },
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { rating: "desc" },
    })

    // Filter by price and availability
    const filtered = hotels.filter((hotel) => {
      const prices = hotel.rooms.flatMap((r) => r.inventory.map((inv) => inv.price))
      const minHotelPrice = Math.min(...prices)
      const maxHotelPrice = Math.max(...prices)
      const available = hotel.rooms.some((r) => r.inventory.some((inv) => inv.available > 0))

      const meetsPrice =
        (!minPrice || minHotelPrice >= Number.parseFloat(minPrice)) &&
        (!maxPrice || maxHotelPrice <= Number.parseFloat(maxPrice))
      const meetsAmenities = amenities.length === 0 || amenities.some((a) => hotel.amenities.includes(a))

      return meetsPrice && meetsAmenities && available
    })

    return apiResponse.success(
      {
        data: filtered,
        pagination: {
          page,
          limit,
          total: filtered.length,
        },
      },
      "Hotels retrieved",
    )
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(errorMessage)
  }
}
