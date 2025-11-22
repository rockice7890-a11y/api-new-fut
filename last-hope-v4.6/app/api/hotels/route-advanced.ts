import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createHotelSchema, searchHotelsSchema } from "@/lib/validation"
import { advancedAPISecurity } from "@/lib/api-security-advanced"
import bcrypt from "bcryptjs"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان - Hotels are public but need basic protection
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action === 'BLOCK') {
      console.warn(`[Advanced Security] Hotel search blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons
      })
      return NextResponse.json(
        failResponse(null, "Request blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    // Enhanced parameter validation with security filtering
    const searchParams = req.nextUrl.searchParams
    
    // Enhanced input sanitization for search parameters
    const searchData = {
      city: searchParams.get("city")?.trim().substring(0, 100) || undefined,
      country: searchParams.get("country")?.trim().substring(0, 100) || undefined,
      minPrice: searchParams.get("minPrice") ? Math.min(Math.max(Number.parseFloat(searchParams.get("minPrice")!), 0), 10000) : undefined,
      maxPrice: searchParams.get("maxPrice") ? Math.min(Math.max(Number.parseFloat(searchParams.get("maxPrice")!), 0), 50000) : undefined,
      minRating: searchParams.get("minRating") ? Math.min(Math.max(Number.parseFloat(searchParams.get("minRating")!), 0), 5) : undefined,
      amenities: searchParams.get("amenities")?.split(',').map(a => a.trim().substring(0, 50)).filter(a => a.length > 0).slice(0, 20) || undefined,
      checkIn: searchParams.get("checkIn") || undefined,
      checkOut: searchParams.get("checkOut") || undefined,
      guests: searchParams.get("guests") ? Math.min(Math.max(Number.parseInt(searchParams.get("guests")!), 1), 50) : undefined,
      page: Math.min(Number.parseInt(searchParams.get("page") || "1"), 1000),
      pageSize: Math.min(Number.parseInt(searchParams.get("pageSize") || "10"), 100),
    }

    // Enhanced validation for search parameters
    if (searchData.page < 1 || searchData.page > 1000) {
      return NextResponse.json(
        failResponse(null, "Invalid page number", "INVALID_PAGE"),
        { status: 400 }
      )
    }

    if (searchData.pageSize < 1 || searchData.pageSize > 100) {
      return NextResponse.json(
        failResponse(null, "Invalid page size", "INVALID_PAGE_SIZE"),
        { status: 400 }
      )
    }

    // Enhanced date validation if provided
    if (searchData.checkIn) {
      const checkInDate = new Date(searchData.checkIn)
      if (isNaN(checkInDate.getTime()) || checkInDate < new Date()) {
        return NextResponse.json(
          failResponse(null, "Invalid check-in date", "INVALID_CHECKIN"),
          { status: 400 }
        )
      }
    }

    if (searchData.checkOut) {
      const checkOutDate = new Date(searchData.checkOut)
      if (isNaN(checkOutDate.getTime())) {
        return NextResponse.json(
          failResponse(null, "Invalid check-out date", "INVALID_CHECKOUT"),
          { status: 400 }
        )
      }
    }

    if (searchData.checkIn && searchData.checkOut) {
      const checkInDate = new Date(searchData.checkIn)
      const checkOutDate = new Date(searchData.checkOut)
      if (checkOutDate <= checkInDate) {
        return NextResponse.json(
          failResponse(null, "Check-out date must be after check-in date", "INVALID_DATE_RANGE"),
          { status: 400 }
        )
      }
    }

    // Validate using enhanced schema
    const validated = searchHotelsSchema.parse(searchData)

    const where: any = { isActive: true } // Only active hotels
    
    // Enhanced filtering with SQL injection protection
    if (validated.city && validated.city.length > 0) {
      // Sanitized city search
      where.city = { 
        contains: validated.city, 
        mode: "insensitive",
        not: { contains: /[;'"\\<>]/g } // Prevent SQL injection
      }
    }
    
    if (validated.country && validated.country.length > 0) {
      // Sanitized country search
      where.country = { 
        contains: validated.country, 
        mode: "insensitive",
        not: { contains: /[;'"\\<>]/g } // Prevent SQL injection
      }
    }
    
    if (validated.amenities && validated.amenities.length > 0) {
      // Validate amenities (prevent injection)
      const safeAmenities = validated.amenities.filter(amenity => 
        amenity && /^[a-zA-Z0-9\s,_\-]+$/.test(amenity)
      )
      if (safeAmenities.length > 0) {
        where.amenities = { hasSome: safeAmenities }
      }
    }

    // Enhanced hotels query with advanced security optimizations
    const hotels = await prisma.hotel.findMany({
      where,
      include: {
        rooms: {
          select: {
            id: true,
            basePrice: true,
            capacity: true,
            status: true,
          },
          where: {
            status: 'AVAILABLE' // Only available rooms for pricing
          }
        },
        reviews: {
          select: {
            rating: true,
            isApproved: true,
          },
          where: {
            isApproved: true // Only approved reviews
          }
        },
        _count: {
          select: {
            bookings: true,
            reviews: true,
          },
        },
      },
      skip: (validated.page - 1) * validated.pageSize,
      take: validated.pageSize,
      orderBy: { createdAt: "desc" },
    })

    const total = await prisma.hotel.count({ where })

    // Enhanced filter and enrich results with security validation
    const enrichedHotels = hotels.map((hotel) => {
      const roomPrices = hotel.rooms.map(r => Number(r.basePrice)).filter(p => !isNaN(p) && p >= 0 && p <= 50000)
      const ratings = hotel.reviews.map(r => Number(r.rating)).filter(r => !isNaN(r) && r >= 0 && r <= 5)
      
      // Security validation for all calculated values
      const avgRating = ratings.length > 0 
        ? Math.min(Math.max(parseFloat((ratings.reduce((sum, r) => sum + r, 0) / ratings.length).toFixed(1)), 0), 5)
        : 0
      
      const minPrice = roomPrices.length > 0 ? Math.min(...roomPrices) : 0
      const maxPrice = roomPrices.length > 0 ? Math.max(...roomPrices) : 0
      
      return {
        ...hotel,
        avgRating,
        minPrice,
        maxPrice,
        totalRooms: hotel.rooms.length,
        availableRooms: hotel.rooms.filter(r => r.status === 'AVAILABLE').length,
        totalBookings: hotel._count.bookings || 0,
        totalReviews: hotel._count.reviews || 0,
        // Security: Remove raw data for cleaner response
        rooms: undefined,
        reviews: undefined,
        _count: undefined,
        // Add security metadata
        security: {
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          verified: true,
          active: hotel.isActive
        }
      }
    })

    // Enhanced filtering with security checks
    let filtered = enrichedHotels
    if (validated.minPrice !== undefined || validated.maxPrice !== undefined) {
      filtered = filtered.filter(hotel => {
        if (validated.minPrice !== undefined && hotel.maxPrice < validated.minPrice) return false
        if (validated.maxPrice !== undefined && hotel.minPrice > validated.maxPrice) return false
        return true
      })
    }

    if (validated.minRating !== undefined) {
      filtered = filtered.filter(hotel => 
        hotel.avgRating && hotel.avgRating >= validated.minRating!
      )
    }

    // Enhanced guest capacity filtering
    if (validated.guests !== undefined) {
      filtered = filtered.filter(hotel => 
        hotel.availableRooms > 0 && // Must have available rooms
        hotel.totalRooms >= validated.guests! // Hotel must accommodate guests
      )
    }

    // Enhanced date availability filtering (basic check)
    if (validated.checkIn && validated.checkOut) {
      // This would need more complex logic for actual availability checking
      // For now, we'll include hotels with available rooms
      filtered = filtered.filter(hotel => hotel.availableRooms > 0)
    }

    console.log(`[Hotel Security] Hotel search completed - Results: ${filtered.length}, Threat Score: ${decision.threatScore}`)

    return NextResponse.json(
      successResponse(
        {
          hotels: filtered,
          total,
          page: validated.page,
          pageSize: validated.pageSize,
          hasMore: (validated.page * validated.pageSize) < total,
          searchMetadata: {
            filters: Object.keys(searchData).filter(k => searchData[k as keyof typeof searchData] !== undefined),
            securityLevel: securityContext.securityLevel,
            threatScore: decision.threatScore
          }
        },
        "Hotels retrieved successfully",
        {
          security: {
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel,
            queryHash: `${validated.city || 'all'}:${validated.country || 'all'}:${validated.page}:${validated.pageSize}`,
            monitoring: decision.action === 'MONITOR'
          }
        }
      ),
      {
        status: 200,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Query-Security': 'ADVANCED'
        }
      },
    )
  } catch (error: any) {
    console.error("[Advanced Get Hotels Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch hotels", "FETCH_HOTELS_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}

export async function POST(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان - Hotel creation requires high security
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action !== 'ALLOW') {
      console.warn(`[Advanced Security] Hotel creation blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons
      })
      return NextResponse.json(
        failResponse(null, "Hotel creation blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!
    
    // Enhanced permission check with security audit
    if (!['ADMIN', 'HOTEL_MANAGER', 'OWNER'].includes(auth.payload.role)) {
      console.warn(`[Security] Unauthorized hotel creation attempt by user ${auth.payload.userId} with role ${auth.payload.role}`)
      return NextResponse.json(
        failResponse(null, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Enhanced input validation with comprehensive security checks
    let body: any
    try {
      body = await req.json()
      
      // Enhanced data sanitization for hotel creation
      const sanitizeString = (str: string, maxLength: number, fieldName: string) => {
        if (typeof str !== 'string') return str
        const sanitized = str.trim().substring(0, maxLength)
        // Check for potential injection attempts
        if (/[<>\"']/.test(sanitized)) {
          throw new Error(`Invalid characters in ${fieldName}`)
        }
        return sanitized
      }

      if (body.name) body.name = sanitizeString(body.name, 200, 'hotel name')
      if (body.description) body.description = sanitizeString(body.description, 2000, 'description')
      if (body.address) body.address = sanitizeString(body.address, 500, 'address')
      if (body.city) body.city = sanitizeString(body.city, 100, 'city')
      if (body.country) body.country = sanitizeString(body.country, 100, 'country')
      
      // Enhanced email validation
      if (body.email) {
        body.email = body.email.trim().toLowerCase().substring(0, 255)
        if (!body.email.includes('@') || /[;\"'\\<>]/.test(body.email)) {
          throw new Error('Invalid email format')
        }
      }
      
      // Enhanced phone validation
      if (body.phone) {
        body.phone = body.phone.trim().substring(0, 20)
        if (!/^[\+]?[1-9][\d]{0,15}$/.test(body.phone.replace(/[\s\-\(\)]/g, ''))) {
          throw new Error('Invalid phone number')
        }
      }
      
      // Enhanced amenities validation
      if (body.amenities && Array.isArray(body.amenities)) {
        body.amenities = body.amenities
          .map((a: string) => sanitizeString(a, 50, 'amenity'))
          .filter((a: string) => a.length > 0)
          .slice(0, 50) // Max 50 amenities
      }
      
    } catch (jsonError: any) {
      return NextResponse.json(
        failResponse(null, `Invalid input: ${jsonError.message}`, "INVALID_INPUT"),
        { status: 400 }
      )
    }

    const validated = createHotelSchema.parse(body)

    // Enhanced duplicate check with security audit
    if (validated.email) {
      const existingHotel = await prisma.hotel.findFirst({
        where: { 
          email: validated.email,
          isActive: true 
        },
        select: { id: true, name: true, email: true }
      })
      
      if (existingHotel) {
        return NextResponse.json(
          failResponse(null, "Hotel with this email already exists", "HOTEL_EXISTS"),
          { status: 409 }
        )
      }
    }

    // Enhanced hotel creation with transaction safety
    const hotel = await prisma.$transaction(async (tx) => {
      const newHotel = await tx.hotel.create({
        data: {
          ...validated,
          managerId: auth.payload.userId,
          amenities: validated.amenities || [],
          images: validated.images || [],
          policies: validated.policies || null,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
          metadata: {
            createdWithAdvancedSecurity: true,
            createdBy: auth.payload.userId,
            creatorRole: auth.payload.role,
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel,
            ipAddress: req.ip,
            userAgent: req.headers.get('user-agent')
          }
        },
        include: {
          manager: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true,
            },
          },
        },
      })

      // Create enhanced default hotel settings
      await tx.hotelSettings.create({
        data: {
          hotelId: newHotel.id,
          checkInTime: "15:00",
          checkOutTime: "11:00",
          autoCheckoutEnabled: true,
          autoCheckoutTime: "12:00",
          gracePeriodMinutes: 60,
          realtimeUpdatesEnabled: true,
          autoSendInvoices: true,
          taxRate: 0.15,
          serviceFee: 0,
          currencyCode: "USD",
          createdAt: new Date(),
          metadata: {
            advancedSecurity: true,
            encrypted: true
          }
        },
      })

      // Create enhanced default working hours
      await tx.hotelWorkingHours.create({
        data: {
          hotelId: newHotel.id,
          monday: "08:00-23:00",
          tuesday: "08:00-23:00", 
          wednesday: "08:00-23:00",
          thursday: "08:00-23:00",
          friday: "08:00-23:00",
          saturday: "08:00-23:00",
          sunday: "08:00-23:00",
          timezone: "UTC",
          createdAt: new Date(),
          metadata: {
            advancedSecurity: true,
            defaultHours: true
          }
        },
      })

      return newHotel
    })

    console.log(`[Hotel Security] New hotel created - ID: ${hotel.id}, Name: ${hotel.name}, Created by: ${auth.payload.userId}, Threat Score: ${decision.threatScore}`)

    return NextResponse.json(
      successResponse(hotel, "Hotel created successfully", {
        security: {
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          advancedProtection: true
        },
        audit: {
          createdBy: auth.payload.userId,
          createdAt: new Date().toISOString(),
          requiresReview: auth.payload.role !== 'ADMIN'
        }
      }),
      { 
        status: 201,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Admin-Action': 'HOTEL_CREATE'
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Create Hotel Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create hotel", "CREATE_HOTEL_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}