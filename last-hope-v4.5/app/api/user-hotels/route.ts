import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

// GET - Get available hotels for current user
export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    // Check user role first
    const user = await prisma.user.findUnique({
      where: { id: auth.payload.userId },
      select: { 
        role: true,
        isActive: true
      }
    })

    if (!user || !user.isActive) {
      return NextResponse.json(
        failResponse(null, "حساب المستخدم غير مفعل", "ERROR"),
        { status: 400 }
      )
    }

    // Get hotels based on user role
    let hotels: any[] = []

    if (user.role === 'HOTEL_MANAGER') {
      // Manager - get hotels owned by this manager
      hotels = await prisma.hotel.findMany({
        where: { 
          managerId: auth.payload.userId,
          isActive: true
        },
        select: {
          id: true,
          name: true,
          address: true,
          city: true,
          country: true,
          phone: true,
          email: true,
          rating: true,
          managerId: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
          images: true,
          // Include basic stats
          _count: {
            select: {
              rooms: true,
              bookings: true,
            }
          }
        },
        orderBy: {
          createdAt: 'desc'
        }
      })
    } else if (user.role === 'RECEPTIONIST') {
      // Receptionist - get hotels where user has permission
      const permissions = await prisma.userPermission.findMany({
        where: { 
          userId: auth.payload.userId,
          isActive: true,
          permission: 'HOTEL_ACCESS'
        },
        select: {
          hotelId: true
        }
      })

      const hotelIds = permissions.map(p => p.hotelId).filter((id): id is string => id !== null)
      
      if (hotelIds.length > 0) {
        hotels = await prisma.hotel.findMany({
          where: { 
            id: { in: hotelIds },
            isActive: true
          },
          select: {
            id: true,
            name: true,
            address: true,
            city: true,
            country: true,
            phone: true,
            email: true,
            rating: true,
            managerId: true,
            isActive: true,
            createdAt: true,
            updatedAt: true,
            images: true,
            _count: {
              select: {
                rooms: true,
                bookings: true,
              }
            }
          },
          orderBy: {
            name: 'asc'
          }
        })
      }
    } else if (user.role === 'ADMIN') {
      // Admin - get all active hotels
      hotels = await prisma.hotel.findMany({
        where: { 
          isActive: true
        },
        select: {
          id: true,
          name: true,
          address: true,
          city: true,
          country: true,
          phone: true,
          email: true,
          rating: true,
          managerId: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
          images: true,
          _count: {
            select: {
              rooms: true,
              bookings: true,
            }
          }
        },
        orderBy: {
          name: 'asc'
        }
      })
    } else {
      // Other roles - no hotels available
      hotels = []
    }

    // Add hotel statistics and current status
    const enrichedHotels = await Promise.all(hotels.map(async (hotel) => {
      // Get recent bookings count
      const recentBookings = await prisma.booking.count({
        where: {
          hotelId: hotel.id,
          checkInDate: {
            gte: new Date(new Date().setDate(new Date().getDate() - 7)) // Last 7 days
          }
        }
      })

      // Get occupancy rate
      const totalRooms = hotel._count.rooms
      const occupiedRooms = await prisma.room.count({
        where: {
          hotelId: hotel.id,
          bookings: {
            some: {
              status: 'CONFIRMED',
              checkInDate: { lte: new Date() },
              checkOutDate: { gt: new Date() }
            }
          }
        }
      })

      const occupancyRate = totalRooms > 0 ? (occupiedRooms / totalRooms * 100).toFixed(1) : "0"

      return {
        ...hotel,
        recentBookings,
        occupancyRate: Number(occupancyRate),
        availableRooms: totalRooms - occupiedRooms
      }
    }))

    return successResponse({
      hotels: enrichedHotels,
      userRole: user.role,
      totalHotels: enrichedHotels.length
    })

  } catch (error: any) {
    console.error("[Get User Hotels Error]", error)
    return failResponse(`خطأ في جلب الفنادق: ${error.message}`)
  }
}

// POST - Set selected hotel for current session
export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const { hotelId } = body

    if (!hotelId) {
      return NextResponse.json(
        failResponse(null, "معرف الفندق مطلوب", "ERROR"),
        { status: 400 }
      )
    }

    // Verify user has access to this hotel
    const user = await prisma.user.findUnique({
      where: { id: auth.payload.userId },
      select: { role: true }
    })

    let hasAccess = false

    if (user?.role === 'HOTEL_MANAGER') {
      // Manager can access their own hotels
      const hotel = await prisma.hotel.findFirst({
        where: {
          id: hotelId,
          managerId: auth.payload.userId,
          isActive: true
        }
      })
      hasAccess = !!hotel
    } else if (user?.role === 'RECEPTIONIST') {
      // Receptionist needs explicit permission
      const permission = await prisma.userPermission.findFirst({
        where: {
          userId: auth.payload.userId,
          hotelId: hotelId,
          permission: 'HOTEL_ACCESS',
          isActive: true
        }
      })
      hasAccess = !!permission
    } else if (user?.role === 'ADMIN') {
      // Admin can access all hotels
      const hotel = await prisma.hotel.findUnique({
        where: { 
          id: hotelId,
          isActive: true 
        }
      })
      hasAccess = !!hotel
    }

    if (!hasAccess) {
      return NextResponse.json(
        failResponse(null, "ليس لديك صلاحية للوصول لهذا الفندق", "ERROR"),
        { status: 400 }
      )
    }

    // Store selected hotel in user session or return it
    const hotel = await prisma.hotel.findUnique({
      where: { id: hotelId },
      select: {
        id: true,
        name: true,
        address: true,
        city: true,
        country: true,
        images: true,
        managerId: true
      }
    })

    if (!hotel) {
      return NextResponse.json(
        failResponse(null, "الفندق غير موجود", "ERROR"),
        { status: 400 }
      )
    }

    // TODO: Store in session/redis for persistence
    // For now, return the hotel info to be stored in Flutter app state

    return successResponse({
      selectedHotel: hotel,
      message: "تم اختيار الفندق بنجاح"
    })

  } catch (error: any) {
    console.error("[Set Selected Hotel Error]", error)
    return failResponse(`خطأ في اختيار الفندق: ${error.message}`)
  }
}