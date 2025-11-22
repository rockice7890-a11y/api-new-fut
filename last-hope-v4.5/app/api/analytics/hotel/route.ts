import type { NextRequest } from "next/server"
import { authenticateRequest } from "@/lib/middleware"
import { apiResponse } from "@/lib/api-response"
import { prisma } from "@/lib/prisma"

export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest) {
  try {
      const user = await authenticateRequest(request)
          if (!user || user.role !== "HOTEL_MANAGER") return apiResponse.unauthorized()

              const hotels = await prisma.hotel.findMany({
                    where: { managerId: user.id },
                          select: { id: true },
                              })

                                  const hotelIds = hotels.map((h) => h.id)

                                      const [totalBookings, occupancyRate, revenue, avgRating] = await Promise.all([
                                            prisma.booking.count({
                                                    where: { hotelId: { in: hotelIds } },
                                                          }),
                                                                prisma.booking.aggregate({
                                                                        where: { hotelId: { in: hotelIds }, status: "CHECKED_IN" },
                                                                                _count: true,
                                                                                      }),
                                                                                            prisma.booking.aggregate({
                                                                                                    where: { hotelId: { in: hotelIds }, status: "COMPLETED" },
                                                                                                            _sum: { totalPrice: true },
                                                                                                                  }),
                                                                                                                        prisma.hotel.aggregate({
                                                                                                                                where: { id: { in: hotelIds } },
                                                                                                                                        _avg: { rating: true },
                                                                                                                                              }),
                                                                                                                                                  ])

                                                                                                                                                      return apiResponse.success(
                                                                                                                                                            {
                                                                                                                                                                    totalBookings,
                                                                                                                                                                            currentOccupancy: occupancyRate._count || 0,
                                                                                                                                                                                    totalRevenue: revenue._sum.totalPrice || 0,
                                                                                                                                                                                            averageRating: avgRating._avg.rating || 0,
                                                                                                                                                                                                  },
                                                                                                                                                                                                        "Hotel analytics retrieved",
                                                                                                                                                                                                            )
                                                                                                                                                                                                              } catch (error) {
                                                                                                                                                                                                                  return apiResponse.error(error instanceof Error ? error.message : "Internal server error")
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                    