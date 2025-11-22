import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createPaymentSchema, updatePaymentSchema } from "@/lib/validation"
import { advancedAPISecurity } from "@/lib/api-security-advanced"

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action === 'BLOCK') {
      console.warn(`[Advanced Security] Payment creation blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons,
        recommendations: decision.recommendations
      })
      return NextResponse.json(
        failResponse(null, "Request blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!

    // تحقق متقدم من صحة المدخلات مع الفلترة
    let body: any
    try {
      body = await req.json()
      // تطبيق فلترة متقدمة للمدخلات المالية
      if (typeof body.amount === 'number' && (body.amount <= 0 || body.amount > 1000000)) {
        return NextResponse.json(
          failResponse(null, "Invalid payment amount", "INVALID_AMOUNT"),
          { status: 400 }
        )
      }
      if (typeof body.currency === 'string' && !['USD', 'EUR', 'GBP', 'AED', 'SAR'].includes(body.currency)) {
        return NextResponse.json(
          failResponse(null, "Unsupported currency", "UNSUPPORTED_CURRENCY"),
          { status: 400 }
        )
      }
    } catch (jsonError) {
      return NextResponse.json(
        failResponse(null, "Invalid JSON format", "INVALID_JSON"),
        { status: 400 }
      )
    }

    const validated = createPaymentSchema.parse(body)

    // Verify the booking exists and belongs to the user with enhanced security
    const booking = await prisma.booking.findFirst({
      where: {
        id: validated.bookingId,
        userId: auth.payload.userId,
      },
      include: {
        payment: true,
        hotel: {
          select: {
            id: true,
            name: true,
            ownerId: true,
          }
        },
        room: {
          select: {
            id: true,
            roomType: true,
            roomNumber: true,
          }
        }
      },
    })

    if (!booking) {
      return NextResponse.json(
        failResponse(null, "Booking not found or access denied", "BOOKING_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Check if payment already exists
    if (booking.payment) {
      return NextResponse.json(
        failResponse(null, "Payment already exists for this booking", "PAYMENT_EXISTS"),
        { status: 409 }
      )
    }

    // Enhanced fraud detection for payments
    const recentPayments = await prisma.payment.findMany({
      where: {
        userId: auth.payload.userId,
        createdAt: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
        }
      }
    })

    // Check for suspicious payment patterns
    if (recentPayments.length > 10) {
      console.warn(`[Fraud Detection] User ${auth.payload.userId} has ${recentPayments.length} payments in 24h`)
    }

    // Enhanced payment creation with audit trail
    const payment = await prisma.payment.create({
      data: {
        bookingId: validated.bookingId,
        amount: Math.round(validated.amount * 100) / 100, // Round to 2 decimal places
        currency: validated.currency,
        status: 'pending',
        method: validated.method,
        stripeId: validated.stripeId,
        metadata: {
          userAgent: req.headers.get('user-agent'),
          ipAddress: req.ip,
          timestamp: new Date().toISOString(),
          securityContext: {
            threatScore: decision.threatScore,
            action: decision.action,
            securityLevel: securityContext.securityLevel
          }
        }
      },
      include: {
        booking: {
          include: {
            hotel: {
              select: {
                name: true,
              },
            },
            room: {
              select: {
                roomType: true,
                roomNumber: true,
              },
            },
          },
        },
      },
    })

    // Enhanced audit logging for payment creation
    console.log(`[Payment Security] Payment created - ID: ${payment.id}, Amount: ${payment.amount} ${payment.currency}, Threat Score: ${decision.threatScore}`)

    // TODO: Integrate with actual payment processor (Stripe, PayPal, etc.) with enhanced security
    // For now, we'll simulate payment processing with enhanced monitoring

    return NextResponse.json(
      successResponse(payment, "Payment created successfully", {
        security: {
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          monitoring: decision.action === 'MONITOR'
        }
      }),
      { 
        status: 201,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Create Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create payment", "CREATE_PAYMENT_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}

export async function GET(req: NextRequest) {
  try {
    // تطبيق النظام المتقدم للأمان
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action === 'BLOCK') {
      console.warn(`[Advanced Security] Payment retrieval blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons
      })
      return NextResponse.json(
        failResponse(null, "Request blocked due to security policy", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!

    // Enhanced parameter validation with security filtering
    const searchParams = req.nextUrl.searchParams
    const bookingId = searchParams.get("bookingId")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Math.min(Number.parseInt(searchParams.get("pageSize") || "10"), 100) // Max 100 items per page
    const status = searchParams.get("status")

    // Enhanced validation for pagination parameters
    if (page < 1 || page > 10000) {
      return NextResponse.json(
        failResponse(null, "Invalid page number", "INVALID_PAGE"),
        { status: 400 }
      )
    }

    const where: any = {}

    // Filter by booking if specified with enhanced security
    if (bookingId && bookingId.length <= 36 && /^[a-fA-F0-9\-]+$/.test(bookingId)) {
      where.bookingId = bookingId
    } else {
      // If no specific booking, only show payments for user's bookings
      const userBookings = await prisma.booking.findMany({
        where: { userId: auth.payload.userId },
        select: { id: true },
      })
      where.bookingId = { in: userBookings.map(b => b.id) }
    }

    // Filter by status if specified with validation
    if (status && ['pending', 'completed', 'failed', 'cancelled', 'refunded'].includes(status)) {
      where.status = status
    }

    // Enhanced query with security optimizations
    const payments = await prisma.payment.findMany({
      where,
      include: {
        booking: {
          include: {
            hotel: {
              select: {
                name: true,
              },
            },
            room: {
              select: {
                roomType: true,
                roomNumber: true,
              },
            },
          },
        },
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.payment.count({ where })

    // Enhanced response with security metadata
    return NextResponse.json(
      successResponse(
        {
          payments,
          total,
          page,
          pageSize,
          hasMore: (page * pageSize) < total,
        },
        "Payments retrieved successfully",
        {
          security: {
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel,
            queryHash: `${bookingId || 'all'}:${status || 'all'}:${page}:${pageSize}`,
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
      }
    )
  } catch (error: any) {
    console.error("[Advanced Get Payments Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch payments", "FETCH_PAYMENTS_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}