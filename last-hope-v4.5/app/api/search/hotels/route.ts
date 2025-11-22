import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

const searchSchema = z.object({
  query: z.string().min(1),
  location: z.string().optional(),
  checkIn: z.string().datetime().optional(),
  checkOut: z.string().datetime().optional(),
  guests: z.number().int().min(1).optional(),
  minPrice: z.number().min(0).optional(),
  maxPrice: z.number().min(0).optional(),
  rating: z.number().min(1).max(5).optional(),
  amenities: z.array(z.string()).optional(),
  sortBy: z.enum(['price', 'rating', 'name', 'distance']).optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  page: z.number().int().min(1).default(1),
  pageSize: z.number().int().min(1).max(100).default(20),
})

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    
    // Convert search params to object
    const searchData: any = {
      query: searchParams.get('query'),
      location: searchParams.get('location'),
      checkIn: searchParams.get('checkIn'),
      checkOut: searchParams.get('checkOut'),
      guests: searchParams.get('guests') ? parseInt(searchParams.get('guests')!) : undefined,
      minPrice: searchParams.get('minPrice') ? parseFloat(searchParams.get('minPrice')!) : undefined,
      maxPrice: searchParams.get('maxPrice') ? parseFloat(searchParams.get('maxPrice')!) : undefined,
      rating: searchParams.get('rating') ? parseFloat(searchParams.get('rating')!) : undefined,
      amenities: searchParams.get('amenities')?.split(','),
      sortBy: searchParams.get('sortBy') as any,
      sortOrder: searchParams.get('sortOrder') as any,
      page: searchParams.get('page') ? parseInt(searchParams.get('page')!) : 1,
      pageSize: searchParams.get('pageSize') ? parseInt(searchParams.get('pageSize')!) : 20,
    }

    // Validate input
    const validated = searchSchema.parse(searchData)

    // Build where conditions
    const whereConditions: any = {
      AND: [],
    }

    // Text search
    if (validated.query) {
      whereConditions.AND.push({
        OR: [
          { name: { contains: validated.query, mode: 'insensitive' } },
          { description: { contains: validated.query, mode: 'insensitive' } },
          { city: { contains: validated.query, mode: 'insensitive' } },
          { country: { contains: validated.query, mode: 'insensitive' } },
        ],
      })
    }

    // Location search
    if (validated.location) {
      whereConditions.AND.push({
        OR: [
          { city: { contains: validated.location, mode: 'insensitive' } },
          { country: { contains: validated.location, mode: 'insensitive' } },
          { address: { contains: validated.location, mode: 'insensitive' } },
        ],
      })
    }

    // Rating filter
    if (validated.rating) {
      whereConditions.AND.push({
        rating: { gte: validated.rating },
      })
    }

    // Price filter (based on room prices)
    if (validated.minPrice || validated.maxPrice) {
      whereConditions.AND.push({
        rooms: {
          some: {
            AND: [
              validated.minPrice ? { basePrice: { gte: validated.minPrice } } : {},
              validated.maxPrice ? { basePrice: { lte: validated.maxPrice } } : {},
            ],
          },
        },
      })
    }

    // Amenities filter
    if (validated.amenities && validated.amenities.length > 0) {
      whereConditions.AND.push({
        amenities: { hasSome: validated.amenities },
      })
    }

    // Build order by
    let orderBy: any = []
    if (validated.sortBy && validated.sortOrder) {
      if (validated.sortBy === 'distance' && validated.location) {
        // For distance sorting, we'll implement basic geolocation
        orderBy.push({ rating: 'desc' }) // Fallback to rating if distance calculation needed
      } else {
        orderBy.push({ [validated.sortBy]: validated.sortOrder })
      }
    } else {
      orderBy = [
        { rating: 'desc' },
        { totalReviews: 'desc' },
      ]
    }

    // Perform search
    const [hotels, totalCount] = await Promise.all([
      prisma.hotel.findMany({
        where: whereConditions,
        include: {
          rooms: {
            select: {
              id: true,
              basePrice: true,
              status: true,
              capacity: true,
            },
            where: {
              status: 'AVAILABLE',
              ...(validated.guests && { capacity: { gte: validated.guests } }),
            },
          },
          reviews: {
            select: {
              rating: true,
            },
          },
          _count: {
            select: {
              rooms: true,
              reviews: true,
              bookings: {
                where: {
                  status: { in: ['CONFIRMED', 'CHECKED_IN', 'CHECKED_OUT'] },
                },
              },
            },
          },
        },
        orderBy,
        skip: (validated.page - 1) * validated.pageSize,
        take: validated.pageSize,
      }),
      prisma.hotel.count({ where: whereConditions }),
    ])

    // Enhance results with calculated fields
    const enhancedHotels = hotels.map(hotel => {
      const availableRooms = hotel.rooms.filter(room => room.status === 'AVAILABLE')
      const minPrice = availableRooms.length > 0 
        ? Math.min(...availableRooms.map(room => room.basePrice))
        : 0
      const maxPrice = availableRooms.length > 0
        ? Math.max(...availableRooms.map(room => room.basePrice))
        : 0

      return {
        ...hotel,
        priceRange: minPrice > 0 ? { min: minPrice, max: maxPrice } : null,
        availableRooms: availableRooms.length,
        occupancyRate: hotel._count.bookings / Math.max(hotel._count.rooms, 1),
        isAvailable: availableRooms.length > 0,
      }
    })

    // Calculate facets for filtering
    const facets = {
      cities: await prisma.hotel.groupBy({
        by: ['city'],
        _count: { city: true },
        orderBy: { _count: { city: 'desc' } },
        take: 20,
      }),
      countries: await prisma.hotel.groupBy({
        by: ['country'],
        _count: { country: true },
        orderBy: { _count: { country: 'desc' } },
        take: 20,
      }),
      amenities: await prisma.hotel.findMany({
        select: { amenities: true },
        distinct: ['amenities'],
      }).then(results => {
        const allAmenities = results.flatMap(hotel => hotel.amenities)
        const amenityCounts = allAmenities.reduce((acc, amenity) => {
          acc[amenity] = (acc[amenity] || 0) + 1
          return acc
        }, {} as Record<string, number>)
        
        return Object.entries(amenityCounts)
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 20)
      }),
      priceRanges: {
        budget: { min: 0, max: 100, count: 0 },
        mid: { min: 100, max: 300, count: 0 },
        luxury: { min: 300, max: 1000, count: 0 },
        ultra: { min: 1000, max: Number.MAX_SAFE_INTEGER, count: 0 },
      },
    }

    // Calculate price range counts
    enhancedHotels.forEach(hotel => {
      if (hotel.priceRange) {
        const price = hotel.priceRange.min
        if (price < 100) facets.priceRanges.budget.count++
        else if (price < 300) facets.priceRanges.mid.count++
        else if (price < 1000) facets.priceRanges.luxury.count++
        else facets.priceRanges.ultra.count++
      }
    })

    return NextResponse.json(
      successResponse({
        hotels: enhancedHotels,
        pagination: {
          page: validated.page,
          pageSize: validated.pageSize,
          totalCount,
          totalPages: Math.ceil(totalCount / validated.pageSize),
          hasNext: validated.page * validated.pageSize < totalCount,
          hasPrev: validated.page > 1,
        },
        facets,
        searchMeta: {
          query: validated.query,
          location: validated.location,
          appliedFilters: {
            priceRange: validated.minPrice || validated.maxPrice ? {
              min: validated.minPrice,
              max: validated.maxPrice,
            } : null,
            rating: validated.rating,
            amenities: validated.amenities,
            guests: validated.guests,
          },
          sortBy: validated.sortBy,
          sortOrder: validated.sortOrder,
        },
      }),
      { status: 200 }
    )

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid search parameters", "VALIDATION_ERROR"),
        { status: 400 }
      )
    }

    console.error("Search error:", error)
    return NextResponse.json(
      failResponse(null, "Internal server error", "SEARCH_ERROR"),
      { status: 500 }
    )
  }
}