/**
 * Complete API Response Examples
 * Demonstrates all available response types and patterns
 */

import { type NextRequest, NextResponse } from "next/server"
import { apiResponse, ErrorCodes } from "@/lib/api-response-improved'
import { prisma } from "@/lib/prisma'
import { generateRequestId } from "@/lib/api-response-improved'

// =============================================
// SUCCESS RESPONSES
// =============================================

// 1. Basic Success Response
export async function exampleSuccess(req: NextRequest) {
  try {
    const data = { id: 1, name: "Example" }
    return apiResponse.success(data, "Operation completed successfully")
  } catch (error) {
    return apiResponse.internalError("Failed to complete operation", error)
  }
}

// 2. Success with Metadata
export async function exampleSuccessWithMetadata(req: NextRequest) {
  try {
    const data = {
      user: { id: 1, name: "John" },
      preferences: { theme: "dark", language: "en" }
    }
    
    return apiResponse.success(data, "User profile loaded", {
      cached: true,
      lastUpdated: new Date().toISOString()
    })
  } catch (error) {
    return apiResponse.internalError("Failed to load user profile", error)
  }
}

// 3. Paginated Response
export async function examplePaginated(req: NextRequest) {
  try {
    const searchParams = req.nextUrl.searchParams
    const page = Number(searchParams.get("page") || "1")
    const limit = Number(searchParams.get("limit") || "10")
    
    const [hotels, total] = await Promise.all([
      prisma.hotel.findMany({
        skip: (page - 1) * limit,
        take: limit,
        orderBy: { name: 'asc' }
      }),
      prisma.hotel.count()
    ])
    
    return apiResponse.successPaginated(
      { hotels },
      { page, limit, total },
      "Hotels retrieved successfully"
    )
  } catch (error) {
    return apiResponse.internalError("Failed to retrieve hotels", error)
  }
}

// =============================================
// FAIL RESPONSES (4xx Errors)
// =============================================

// 4. Bad Request (400)
export async function exampleBadRequest(req: NextRequest) {
  try {
    const body = await req.json()
    
    if (!body.email) {
      return apiResponse.badRequest("Email is required", {
        field: "email",
        provided: body.email
      })
    }
    
    return apiResponse.success({ processed: true }, "Request processed")
  } catch (error) {
    return apiResponse.internalError("Failed to process request", error)
  }
}

// 5. Unauthorized (401)
export async function exampleUnauthorized(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization")
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return apiResponse.unauthorized("Bearer token required")
    }
    
    // Validate token...
    return apiResponse.success({ user: "authenticated" }, "Authentication successful")
  } catch (error) {
    return apiResponse.internalError("Authentication failed", error)
  }
}

// 6. Forbidden (403)
export async function exampleForbidden(req: NextRequest) {
  try {
    // Check user permissions
    const userRole = "USER"
    
    if (userRole !== "ADMIN") {
      return apiResponse.forbidden("Admin privileges required")
    }
    
    return apiResponse.success({ adminData: "secret" }, "Admin access granted")
  } catch (error) {
    return apiResponse.internalError("Permission check failed", error)
  }
}

// 7. Not Found (404)
export async function exampleNotFound(req: NextRequest) {
  try {
    const userId = req.nextUrl.searchParams.get("id")
    
    if (!userId) {
      return apiResponse.badRequest("User ID is required", { field: "id" })
    }
    
    const user = await prisma.user.findUnique({
      where: { id: userId }
    })
    
    if (!user) {
      return apiResponse.notFound(`User with ID ${userId} not found`, "BIZ_001")
    }
    
    return apiResponse.success(user, "User found")
  } catch (error) {
    return apiResponse.internalError("Failed to find user", error)
  }
}

// 8. Conflict (409)
export async function exampleConflict(req: NextRequest) {
  try {
    const body = await req.json()
    
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: body.email }
    })
    
    if (existingUser) {
      return apiResponse.conflict(
        "User with this email already exists",
        "BIZ_002",
        { email: body.email, existingUserId: existingUser.id }
      )
    }
    
    // Create user...
    return apiResponse.success({ created: true }, "User created successfully")
  } catch (error) {
    return apiResponse.internalError("Failed to create user", error)
  }
}

// 9. Unprocessable Entity (422)
export async function exampleUnprocessableEntity(req: NextRequest) {
  try {
    const body = await req.json()
    
    // Validate using Zod schema
    try {
      const userSchema = z.object({
        email: z.string().email(),
        password: z.string().min(8),
        age: z.number().min(18)
      })
      
      const validated = userSchema.parse(body)
      
      return apiResponse.success({ validated }, "Validation passed")
      
    } catch (validationError) {
      if (validationError.name === "ZodError") {
        return apiResponse.unprocessableEntity(
          "Invalid user data provided",
          { 
            validationErrors: validationError.errors,
            provided: body
          }
        )
      }
      throw validationError
    }
    
  } catch (error) {
    return apiResponse.internalError("Validation failed", error)
  }
}

// =============================================
// ERROR RESPONSES (5xx Errors)
// =============================================

// 10. Too Many Requests (429)
export async function exampleRateLimited(req: NextRequest) {
  try {
    // Simulate rate limiting
    const requestCount = Math.floor(Math.random() * 100)
    const rateLimit = 50
    
    if (requestCount > rateLimit) {
      return apiResponse.tooManyRequests(
        "Rate limit exceeded. Please wait before making more requests"
      )
    }
    
    return apiResponse.success(
      { requestCount, limit: rateLimit },
      "Request processed successfully"
    )
  } catch (error) {
    return apiResponse.internalError("Rate limit check failed", error)
  }
}

// 11. Internal Server Error (500)
export async function exampleInternalError(req: NextRequest) {
  try {
    // Simulate database error
    const shouldFail = true
    
    if (shouldFail) {
      const error = new Error("Database connection failed")
      return apiResponse.internalError("Failed to process request", error)
    }
    
    return apiResponse.success({ processed: true }, "Request processed")
  } catch (error) {
    return apiResponse.internalError("Unexpected error occurred", error)
  }
}

// 12. Service Unavailable (503)
export async function exampleServiceUnavailable(req: NextRequest) {
  try {
    // Check service health
    const serviceStatus = "maintenance"
    
    if (serviceStatus === "maintenance") {
      return apiResponse.serviceUnavailable(
        "Service is temporarily under maintenance. Please try again later."
      )
    }
    
    return apiResponse.success({ status: "operational" }, "Service is operational")
  } catch (error) {
    return apiResponse.internalError("Health check failed", error)
  }
}

// =============================================
// SPECIALIZED BUSINESS RESPONSES
// =============================================

// 13. Hotel-Specific Responses
export async function exampleHotelBooking(req: NextRequest) {
  try {
    const body = await req.json()
    const { roomId, checkInDate, checkOutDate } = body
    
    // Validate dates
    const checkIn = new Date(checkInDate)
    const checkOut = new Date(checkOutDate)
    
    if (checkIn >= checkOut) {
      return apiResponse.badRequest(
        "Check-out date must be after check-in date",
        { 
          checkInDate, 
          checkOutDate,
          field: "dates"
        }
      )
    }
    
    // Check room availability
    const availability = await checkRoomAvailability(roomId, checkInDate, checkOutDate)
    
    if (!availability.available) {
      return apiResponse.conflict(
        "Room not available for selected dates",
        "HOTEL_002",
        {
          requested: { checkInDate, checkOutDate },
          unavailableDates: availability.unavailableDates
        }
      )
    }
    
    // Create booking
    const booking = await createBooking(roomId, checkInDate, checkOutDate)
    
    return apiResponse.success(
      {
        booking: {
          id: booking.id,
          reference: booking.reference,
          totalPrice: booking.totalPrice
        },
        paymentRequired: true,
        paymentUrl: `/payment/${booking.id}`
      },
      "Booking created successfully. Please complete payment."
    )
    
  } catch (error) {
    return apiResponse.internalError("Booking creation failed", error)
  }
}

// 14. Payment Responses
export async function examplePaymentProcessing(req: NextRequest) {
  try {
    const body = await req.json()
    const { bookingId, paymentMethod } = body
    
    // Validate payment method
    const validMethods = ["CREDIT_CARD", "PAYPAL", "BANK_TRANSFER"]
    
    if (!validMethods.includes(paymentMethod)) {
      return apiResponse.badRequest(
        "Invalid payment method",
        {
          field: "paymentMethod",
          provided: paymentMethod,
          validMethods: validMethods
        }
      )
    }
    
    // Process payment
    try {
      const paymentResult = await processPayment(bookingId, paymentMethod)
      
      return apiResponse.success(
        {
          paymentId: paymentResult.id,
          status: paymentResult.status,
          amount: paymentResult.amount,
          transactionId: paymentResult.transactionId
        },
        "Payment processed successfully"
      )
      
    } catch (paymentError) {
      if (paymentError.code === "INSUFFICIENT_FUNDS") {
        return apiResponse.conflict(
          "Insufficient funds for payment",
          "PAY_002",
          { required: paymentError.required, available: paymentError.available }
        )
      }
      
      if (paymentError.code === "PAYMENT_DECLINED") {
        return apiResponse.conflict(
          "Payment was declined by the payment provider",
          "PAY_001",
          { reason: paymentError.reason }
        )
      }
      
      throw paymentError
    }
    
  } catch (error) {
    return apiResponse.internalError("Payment processing failed", error)
  }
}

// 15. Complex Response with Multiple Data Types
export async function exampleComplexResponse(req: NextRequest) {
  try {
    const searchParams = req.nextUrl.searchParams
    const userId = searchParams.get("userId")
    
    if (!userId) {
      return apiResponse.badRequest("User ID is required", { field: "userId" })
    }
    
    // Fetch multiple data sources
    const [user, bookings, preferences, notifications] = await Promise.all([
      getUserProfile(userId),
      getUserBookings(userId, { limit: 5 }),
      getUserPreferences(userId),
      getUserNotifications(userId, { unread: true })
    ])
    
    if (!user) {
      return apiResponse.notFound(`User with ID ${userId} not found`, "BIZ_001")
    }
    
    // Complex response with multiple sections
    return apiResponse.success(
      {
        profile: {
          user: user,
          membershipLevel: user.loyaltyLevel,
          totalBookings: bookings.total,
          totalSpent: user.totalSpent
        },
        recentBookings: bookings.items,
        preferences: preferences.settings,
        notifications: {
          unread: notifications.count,
          items: notifications.items
        },
        recommendations: await getPersonalizedRecommendations(userId)
      },
      "User dashboard data retrieved successfully",
      {
        cached: true,
        cacheExpiry: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        dataSources: ["user", "bookings", "preferences", "notifications"]
      }
    )
    
  } catch (error) {
    return apiResponse.internalError("Failed to load user dashboard", error)
  }
}

// =============================================
// HELPER FUNCTIONS (Mock implementations)
// =============================================

async function checkRoomAvailability(roomId: string, checkIn: string, checkOut: string) {
  // Mock implementation
  return {
    available: Math.random() > 0.3,
    unavailableDates: ["2025-12-25", "2025-12-26"]
  }
}

async function createBooking(roomId: string, checkIn: string, checkOut: string) {
  // Mock implementation
  return {
    id: "booking_" + Date.now(),
    reference: "BK" + Math.random().toString(36).substr(2, 8).toUpperCase(),
    totalPrice: 150
  }
}

async function processPayment(bookingId: string, method: string) {
  // Mock implementation
  const success = Math.random() > 0.2
  
  if (!success) {
    const error = new Error("Payment declined")
    ;(error as any).code = "PAYMENT_DECLINED"
    ;(error as any).reason = "Insufficient funds"
    throw error
  }
  
  return {
    id: "pay_" + Date.now(),
    status: "SUCCESS",
    amount: 150,
    transactionId: "txn_" + Math.random().toString(36).substr(2, 12)
  }
}

async function getUserProfile(userId: string) {
  return { id: userId, name: "John Doe", email: "john@example.com" }
}

async function getUserBookings(userId: string, options: any) {
  return {
    total: 10,
    items: [{ id: "bk1", hotel: "Hotel ABC" }, { id: "bk2", hotel: "Hotel XYZ" }]
  }
}

async function getUserPreferences(userId: string) {
  return { settings: { language: "en", notifications: true } }
}

async function getUserNotifications(userId: string, options: any) {
  return { count: 3, items: [{ id: 1, message: "Welcome!" }] }
}

async function getPersonalizedRecommendations(userId: string) {
  return [{ id: "hotel1", name: "Recommended Hotel" }]
}