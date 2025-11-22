import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { createReviewSchema } from "@/lib/validation"
import { z } from "zod"

// Enhanced validation schema for reviews
const enhancedCreateReviewSchema = createReviewSchema.extend({
  checkInDate: z.string().datetime().optional(),
  checkOutDate: z.string().datetime().optional(),
  roomNumber: z.string().optional(),
  staffNames: z.array(z.string()).max(10).optional(), // Names of staff who provided service
  highlights: z.array(z.string()).max(5).optional(), // Positive highlights
  suggestions: z.array(z.string()).max(3).optional(), // Improvement suggestions
  wouldRecommend: z.boolean().default(true),
  bookingReference: z.string().optional(),
  photos: z.array(z.string().url()).max(10).optional(),
  checkInExperience: z.number().min(1).max(5).optional(),
  checkOutExperience: z.number().min(1).max(5).optional(),
  frontDeskService: z.number().min(1).max(5).optional(),
  locationRating: z.number().min(1).max(5).optional(),
  foodQuality: z.number().min(1).max(5).optional(),
  noiseLevel: z.enum(['VERY_QUIET', 'QUIET', 'AVERAGE', 'NOISY', 'VERY_NOISY']).optional(),
  wifiQuality: z.enum(['EXCELLENT', 'GOOD', 'AVERAGE', 'POOR', 'NONE']).optional(),
  parkingAvailability: z.enum(['EXCELLENT', 'GOOD', 'LIMITED', 'DIFFICULT', 'NONE']).optional(),
  checkInTime: z.number().min(0).max(23).optional(), // Hour of check-in
  checkOutTime: z.number().min(0).max(23).optional() // Hour of check-out
})

// Advanced threat detection for review operations
async function detectReviewThreats(
  request: NextRequest,
  userId: string,
  operation: string,
  data: any
): Promise<{ threatScore: number; threats: string[]; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' }> {
  const threats: string[] = []
  let threatScore = 0

  const userAgent = request.headers.get('user-agent') || ''
  const origin = request.headers.get('origin') || ''

  // Malicious client detection
  if (userAgent.includes('bot') || userAgent.includes('crawler') || userAgent.includes('scraper')) {
    threats.push('AUTOMATED_CLIENT_DETECTED')
    threatScore += 60
  }

  // Rating manipulation detection
  if (data?.rating && (data.rating < 1 || data.rating > 5)) {
    threats.push('INVALID_RATING_VALUE')
    threatScore += 70
  }

  // Comment content analysis
  if (data?.comment) {
    const comment = data.comment.toLowerCase()
    
    // Malicious content detection
    const maliciousPatterns = [
      /hack|exploit|bypass|delete|sql|script/i,
      /viagra|cialis|porn|adult/i,
      /spam|advertisement|promotion/i,
      /\b(fuck|shit|damn)\b/i
    ]
    
    if (maliciousPatterns.some(pattern => pattern.test(comment))) {
      threats.push('MALICIOUS_COMMENT_CONTENT')
      threatScore += 80
    }

    // Excessive length detection
    if (comment.length > 2000) {
      threats.push('EXCESSIVE_COMMENT_LENGTH')
      threatScore += 30
    }

    // Suspicious patterns
    if (comment.includes('<script>') || comment.includes('javascript:')) {
      threats.push('SCRIPT_INJECTION_ATTEMPT')
      threatScore += 90
    }
  }

  // Photo URL validation
  if (data?.photos && data.photos.length > 0) {
    for (const photo of data.photos) {
      if (!photo.startsWith('https://') && !photo.startsWith('http://')) {
        threats.push('SUSPICIOUS_PHOTO_URL')
        threatScore += 40
        break
      }
      if (photo.length > 500) {
        threats.push('EXCESSIVE_PHOTO_URL_LENGTH')
        threatScore += 25
        break
      }
    }
  }

  // Booking reference manipulation
  if (data?.bookingReference) {
    if (data.bookingReference.length > 50) {
      threats.push('SUSPICIOUS_BOOKING_REFERENCE')
      threatScore += 35
    }
  }

  // Time-based anomaly detection
  const currentHour = new Date().getHours()
  if (operation === 'CREATE' && currentHour >= 1 && currentHour <= 4) {
    threats.push('OFF_HOURS_REVIEW_CREATION')
    threatScore += 20
  }

  // Geographic anomaly (simulated)
  const userLanguage = request.headers.get('accept-language') || ''
  if (userLanguage && !userLanguage.includes('en') && !userLanguage.includes('ar')) {
    threats.push('UNKNOWN_USER_LANGUAGE')
    threatScore += 15
  }

  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'
  if (threatScore > 80) riskLevel = 'HIGH'
  else if (threatScore > 50) riskLevel = 'MEDIUM'

  return { threatScore, threats, riskLevel }
}

// Advanced audit logging for review operations
async function logAdvancedReviewAction(
  action: string,
  userId: string,
  data: any,
  context: {
    hotelId: string
    reviewId?: string
    userAgent?: string
    ipAddress?: string
    threatAnalysis?: any
  }
) {
  try {
    const correlationId = `review_${action}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const securityContext = {
      correlationId,
      userId,
      action,
      timestamp: new Date().toISOString(),
      endpoint: `/api/reviews`,
      method: 'POST',
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      hotelId: context.hotelId,
      reviewId: context.reviewId,
      threatLevel: context.threatAnalysis?.riskLevel || 'UNKNOWN',
      dataSensitivity: 'HIGH', // Reviews contain personal opinions and experiences
      complianceFlags: ['GDPR_PII', 'CCPA_APPLICABLE', 'REVIEW_MODERATION_REQUIRED']
    }

    console.log(`[REVIEW_SECURITY_AUDIT] ${JSON.stringify(securityContext)}`)
    console.log(`[REVIEW_DATA_AUDIT] Action: ${action}, User: ${userId}, Hotel: ${context.hotelId}`)
    
    if (context.threatAnalysis && context.threatAnalysis.threats.length > 0) {
      console.log(`[REVIEW_THREAT_DETECTION] Threats: ${JSON.stringify(context.threatAnalysis.threats)}`)
    }
  } catch (error) {
    console.error('[Review Audit Logging Error]', error)
  }
}

// Enhanced role-based access control for reviews
async function checkReviewAccess(
  request: NextRequest,
  userId: string,
  role: string,
  hotelId: string,
  operation: string
): Promise<{
  hasAccess: boolean
  hotelManagerId?: string
  response?: NextResponse
  reasons: string[]
}> {
  const reasons: string[] = []
  
  try {
    // Get hotel information
    const hotel = await prisma.hotel.findUnique({
      where: { id: hotelId },
      select: { id: true, managerId: true, status: true, name: true }
    })

    if (!hotel) {
      return {
        hasAccess: false,
        response: NextResponse.json(
          failResponse(null, "Hotel not found", "HOTEL_NOT_FOUND"),
          { status: 404 }
        ),
        reasons: ['HOTEL_NOT_FOUND']
      }
    }

    // Role-based access validation
    if (role === 'ADMIN') {
      return {
        hasAccess: true,
        hotelManagerId: hotel.managerId,
        reasons: ['ADMIN_ACCESS_GRANTED']
      }
    }

    if (role === 'HOTEL_MANAGER') {
      if (hotel.managerId === userId) {
        return {
          hasAccess: true,
          hotelManagerId: hotel.managerId,
          reasons: ['HOTEL_MANAGER_ACCESS_GRANTED']
        }
      } else {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Access denied to this hotel's reviews", "HOTEL_ACCESS_DENIED"),
            { status: 403 }
          ),
          reasons: ['HOTEL_MANAGER_ACCESS_DENIED', 'WRONG_HOTEL']
        }
      }
    }

    if (role === 'USER') {
      return {
        hasAccess: true,
        hotelManagerId: hotel.managerId,
        reasons: ['USER_REVIEW_ACCESS_GRANTED']
      }
    }

    if (role === 'STAFF') {
      // Staff can read reviews but not create them
      if (operation === 'CREATE') {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Staff cannot create reviews", "STAFF_REVIEW_CREATE_DENIED"),
            { status: 403 }
          ),
          reasons: ['STAFF_REVIEW_CREATE_DENIED']
        }
      }
      
      return {
        hasAccess: true,
        hotelManagerId: hotel.managerId,
        reasons: ['STAFF_READ_ACCESS_GRANTED']
      }
    }

    return {
      hasAccess: false,
      response: NextResponse.json(
        failResponse(null, "Insufficient permissions", "INSUFFICIENT_REVIEW_ACCESS"),
        { status: 403 }
      ),
      reasons: ['UNKNOWN_ROLE', `Role: ${role}`]
    }

  } catch (error) {
    console.error('[Review Access Check Error]', error)
    return {
      hasAccess: false,
      response: NextResponse.json(
        failResponse(null, "Access check failed", "ACCESS_CHECK_ERROR"),
        { status: 500 }
      ),
      reasons: ['ACCESS_CHECK_ERROR', error instanceof Error ? error.message : 'Unknown error']
    }
  }
}

// Rate limiting for review operations
const REVIEW_RATE_LIMITS = {
  CREATE: { requests: 3, window: 3600000 }, // 3 reviews per hour
  READ: { requests: 200, window: 60000 } // 200 reads per minute
}

async function checkReviewRateLimit(
  operation: string,
  userId: string
): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
  const limits = REVIEW_RATE_LIMITS[operation as keyof typeof REVIEW_RATE_LIMITS]
  if (!limits) {
    return { allowed: true, remaining: limits.requests, resetTime: Date.now() + limits.window }
  }

  // Simulated rate limiting (use Redis in production)
  return { 
    allowed: true, 
    remaining: limits.requests - 1, 
    resetTime: Date.now() + limits.window 
  }
}

// Enhanced review validation with booking verification
async function validateRevieweligibility(
  userId: string,
  hotelId: string,
  bookingId?: string
): Promise<{
  isEligible: boolean
  booking?: any
  response?: NextResponse
  reasons: string[]
}> {
  const reasons: string[] = []
  
  try {
    // Find completed booking
    const whereClause: any = {
      userId,
      hotelId,
      status: 'COMPLETED'
    }
    
    if (bookingId) {
      whereClause.id = bookingId
    }

    const booking = await prisma.booking.findFirst({
      where: whereClause,
      select: {
        id: true,
        checkInDate: true,
        checkOutDate: true,
        room: {
          select: {
            id: true,
            roomNumber: true,
            roomType: true
          }
        },
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    })

    if (!booking) {
      return {
        isEligible: false,
        response: NextResponse.json(
          failResponse(null, "No completed booking found for this hotel", "NO_COMPLETED_BOOKING"),
          { status: 400 }
        ),
        reasons: ['NO_COMPLETED_BOOKING']
      }
    }

    // Check review window (can review within 30 days after checkout)
    const daysSinceCheckout = Math.floor(
      (new Date().getTime() - new Date(booking.checkOutDate).getTime()) / (1000 * 60 * 60 * 24)
    )

    if (daysSinceCheckout > 30) {
      return {
        isEligible: false,
        response: NextResponse.json(
          failResponse(null, "Review window has expired (30 days after checkout)", "REVIEW_WINDOW_EXPIRED"),
          { status: 400 }
        ),
        reasons: ['REVIEW_WINDOW_EXPIRED', `Days since checkout: ${daysSinceCheckout}`]
      }
    }

    return {
      isEligible: true,
      booking,
      reasons: ['REVIEW_ELIGIBLE', `Days since checkout: ${daysSinceCheckout}`]
    }
  } catch (error) {
    console.error('[Review Eligibility Check Error]', error)
    return {
      isEligible: false,
      response: NextResponse.json(
        failResponse(null, "Failed to validate review eligibility", "VALIDATION_ERROR"),
        { status: 500 }
      ),
      reasons: ['VALIDATION_ERROR', error instanceof Error ? error.message : 'Unknown error']
    }
  }
}

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const startTime = Date.now()
  
  try {
    const auth = await withAuth(req)
    if (!auth.isValid) {
      await logAdvancedReviewAction(
        'CREATE_BLOCKED_NO_AUTH',
        'anonymous',
        {},
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      return auth.response!
    }

    const userId = auth.payload.userId
    const role = auth.payload.role

    const body = await req.json()
    
    // Enhanced validation
    try {
      const validated = enhancedCreateReviewSchema.parse(body)
      Object.assign(body, validated) // Merge validated data
    } catch (validationError: any) {
      await logAdvancedReviewAction(
        'CREATE_BLOCKED_VALIDATION_ERROR',
        userId,
        { validationError: validationError.message },
        {
          hotelId: body.hotelId || 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      
      return NextResponse.json(
        failResponse(null, `Validation error: ${validationError.message}`, "VALIDATION_ERROR"),
        { status: 400 }
      )
    }

    // Advanced threat detection
    const threatAnalysis = await detectReviewThreats(
      req,
      userId,
      'CREATE_REVIEW',
      body
    )

    if (threatAnalysis.threatScore > 75) {
      await logAdvancedReviewAction(
        'CREATE_BLOCKED_HIGH_THREAT',
        userId,
        { threatAnalysis },
        {
          hotelId: body.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Review creation blocked due to security concerns", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    // Rate limiting check
    const rateLimit = await checkReviewRateLimit('CREATE', userId)
    if (!rateLimit.allowed) {
      return NextResponse.json(
        failResponse(null, "Rate limit exceeded for review creation", "RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }

    // Enhanced access control
    const accessCheck = await checkReviewAccess(
      req,
      userId,
      role,
      body.hotelId,
      'CREATE'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    // Enhanced booking validation
    const eligibilityCheck = await validateRevieweligibility(
      userId,
      body.hotelId,
      body.bookingId
    )

    if (!eligibilityCheck.isEligible) {
      return eligibilityCheck.response!
    }

    const booking = eligibilityCheck.booking!

    // Check for existing review
    const existingReview = await prisma.review.findFirst({
      where: {
        userId,
        hotelId: body.hotelId,
        bookingId: body.bookingId || null
      },
      select: { id: true, createdAt: true }
    })

    if (existingReview) {
      await logAdvancedReviewAction(
        'CREATE_BLOCKED_EXISTING_REVIEW',
        userId,
        { 
          existingReviewId: existingReview.id,
          existingReviewDate: existingReview.createdAt
        },
        {
          hotelId: body.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "You have already reviewed this booking", "REVIEW_EXISTS"),
        { status: 409 }
      )
    }

    // Content moderation simulation
    const contentModerationResult = await prisma.$transaction(async (tx) => {
      // Enhanced review creation with comprehensive data
      const reviewData = {
        userId,
        hotelId: body.hotelId,
        bookingId: body.bookingId,
        rating: body.rating,
        comment: body.comment?.trim(),
        cleanliness: body.cleanliness,
        comfort: body.comfort,
        service: body.service,
        value: body.value,
        // Enhanced fields
        checkInDate: body.checkInDate,
        checkOutDate: body.checkOutDate,
        roomNumber: body.roomNumber || booking.room.roomNumber,
        staffNames: body.staffNames || [],
        highlights: body.highlights || [],
        suggestions: body.suggestions || [],
        wouldRecommend: body.wouldRecommend,
        bookingReference: body.bookingReference,
        photos: body.photos || [],
        checkInExperience: body.checkInExperience,
        checkOutExperience: body.checkOutExperience,
        frontDeskService: body.frontDeskService,
        locationRating: body.locationRating,
        foodQuality: body.foodQuality,
        noiseLevel: body.noiseLevel,
        wifiQuality: body.wifiQuality,
        parkingAvailability: body.parkingAvailability,
        checkInTime: body.checkInTime,
        checkOutTime: body.checkOutTime,
        // Security and metadata
        verified: true, // Auto-verify since they have completed booking
        moderated: false, // Will be reviewed by moderation system
        moderationScore: 100 - threatAnalysis.threatScore, // Higher score = less moderation needed
        threatScore: threatAnalysis.threatScore,
        securityFlags: threatAnalysis.threats,
        moderationFlags: threatAnalysis.threats.length > 0 ? ['AUTO_REVIEW'] : [],
        // Audit trail
        createdBy: userId,
        auditTrail: {
          createdAt: new Date(),
          createdBy: userId,
          threatScore: threatAnalysis.threatScore,
          securityFlags: threatAnalysis.threats,
          bookingReference: booking.id
        }
      }

      const review = await tx.review.create({
        data: reviewData,
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              avatar: true,
            },
          },
          hotel: {
            select: {
              id: true,
              name: true,
              city: true,
              country: true
            },
          },
          booking: {
            select: {
              id: true,
              room: {
                select: {
                  roomNumber: true,
                  roomType: true
                }
              }
            }
          }
        },
      })

      // Update hotel's overall rating with enhanced calculation
      const allReviews = await tx.review.findMany({
        where: { hotelId: body.hotelId },
        select: { 
          rating: true,
          threatScore: true,
          moderated: true
        }
      })

      // Weighted rating calculation (lower threat scores get more weight)
      const weightedSum = allReviews.reduce((sum, r) => {
        const weight = r.moderated ? 0.5 : 1 // Moderated reviews have less weight
        return sum + (r.rating * weight)
      }, 0)
      
      const totalWeight = allReviews.reduce((sum, r) => {
        const weight = r.moderated ? 0.5 : 1
        return sum + weight
      }, 0)

      const newWeightedAverageRating = totalWeight > 0 ? weightedSum / totalWeight : 0

      await tx.hotel.update({
        where: { id: body.hotelId },
        data: {
          rating: Math.round(newWeightedAverageRating * 10) / 10,
          totalReviews: allReviews.length,
          lastReviewDate: new Date()
        },
      })

      // Create moderation queue entry if needed
      if (threatAnalysis.threats.length > 0 || !contentModerationResult.isClean) {
        await tx.moderationQueue.create({
          data: {
            reviewId: review.id,
            content: review.comment,
            threatScore: threatAnalysis.threatScore,
            flags: threatAnalysis.threats,
            status: 'PENDING',
            priority: threatAnalysis.threatScore > 60 ? 'HIGH' : 'MEDIUM',
            assignedTo: null,
            createdAt: new Date()
          }
        })
      }

      return review
    })

    // Advanced audit logging
    await logAdvancedReviewAction(
      'REVIEW_CREATED',
      userId,
      { 
        reviewId: contentModerationResult.id,
        rating: contentModerationResult.rating,
        bookingId: contentModerationResult.bookingId,
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: body.hotelId,
        reviewId: contentModerationResult.id,
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return NextResponse.json(
      successResponse(
        {
          ...contentModerationResult,
          threatScore: threatAnalysis.threatScore,
          riskLevel: threatAnalysis.riskLevel,
          securityValidated: true,
          performance: {
            responseTime: Date.now() - startTime,
            rateLimitRemaining: rateLimit.remaining,
            securityChecks: threatAnalysis.threats.length,
            contentModerated: threatAnalysis.threats.length > 0
          },
          auditInfo: {
            accessGranted: [...accessCheck.reasons, ...eligibilityCheck.reasons],
            role: role,
            timestamp: new Date().toISOString(),
            bookingEligibility: eligibilityCheck.reasons
          }
        },
        "Review created successfully with enhanced security and moderation"
      ),
      { status: 201 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Create Review Advanced Error] ${duration}ms`, error)
    
    await logAdvancedReviewAction(
      'CREATE_REVIEW_ERROR',
      'system',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        hotelId: 'unknown',
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    return NextResponse.json(
      failResponse(null, error.message || "Failed to create review", "CREATE_REVIEW_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  const startTime = Date.now()
  
  try {
    // Flexible authentication (allow public reads)
    const auth = await withAuth(req)
    const userId = auth?.payload?.userId || 'anonymous'
    const role = auth?.payload?.role || 'ANONYMOUS'

    const searchParams = req.nextUrl.searchParams
    const hotelId = searchParams.get("hotelId")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Math.min(Number.parseInt(searchParams.get("pageSize") || "10"), 100)
    const minRating = searchParams.get("minRating") ? Number.parseInt(searchParams.get("minRating")!) : undefined
    const maxRating = searchParams.get("maxRating") ? Number.parseInt(searchParams.get("maxRating")!) : undefined
    const sortBy = searchParams.get("sortBy") || "createdAt"
    const sortOrder = searchParams.get("sortOrder") || "desc"
    const verifiedOnly = searchParams.get("verifiedOnly") === "true"
    const includeModerated = searchParams.get("includeModerated") === "true" && role === 'ADMIN'

    if (!hotelId) {
      return NextResponse.json(
        failResponse(null, "Hotel ID is required", "HOTEL_ID_REQUIRED"),
        { status: 400 }
      )
    }

    // Rate limiting check (except for public access)
    let rateLimit = { allowed: true, remaining: 999, resetTime: Date.now() + 60000 }
    if (role !== 'ANONYMOUS') {
      rateLimit = await checkReviewRateLimit('READ', userId)
      if (!rateLimit.allowed) {
        return NextResponse.json(
          failResponse(null, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        )
      }
    }

    // Enhanced filtering
    const where: any = { hotelId }
    if (minRating !== undefined) where.rating = { gte: minRating }
    if (maxRating !== undefined) where.rating = { ...where.rating, lte: maxRating }
    if (verifiedOnly) where.verified = true
    if (!includeModerated) where.moderated = false

    // Enhanced query with comprehensive includes
    const reviews = await prisma.review.findMany({
      where,
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            avatar: true,
          },
        },
        hotel: {
          select: {
            id: true,
            name: true,
            city: true,
            country: true
          },
        },
        booking: {
          select: {
            id: true,
            room: {
              select: {
                roomNumber: true,
                roomType: true
              }
            }
          }
        },
        // Additional data for admins
        ...(role === 'ADMIN' && {
          threatScore: true,
          securityFlags: true,
          moderationFlags: true,
          moderationScore: true
        })
      },
      orderBy: { 
        [sortBy]: sortOrder === 'desc' ? 'desc' : 'asc' 
      },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    // Enhanced data processing
    const processedReviews = reviews.map(review => {
      // Calculate review metrics
      const averageSubRatings = review.cleanliness && review.comfort && review.service && review.value ? 
        (review.cleanliness + review.comfort + review.service + review.value) / 4 : null

      // Format data based on user role
      const formattedReview = {
        ...review,
        averageSubRatings: averageSubRatings ? Math.round(averageSubRatings * 100) / 100 : null,
        verified: review.verified,
        // Security masking for non-admin users
        ...(role !== 'ADMIN' && {
          threatScore: undefined,
          securityFlags: undefined,
          moderationFlags: undefined,
          moderationScore: undefined
        })
      }

      // Remove sensitive data for anonymous users
      if (role === 'ANONYMOUS') {
        delete formattedReview.user.firstName
        delete formattedReview.user.lastName
        delete formattedReview.user.avatar
        delete formattedReview.booking
      }

      return formattedReview
    })

    // Get total count
    const total = await prisma.review.count({ where })

    // Calculate rating distribution with enhanced metrics
    const ratingStats = await prisma.review.groupBy({
      by: ['rating'],
      where: { 
        hotelId, 
        verified: verifiedOnly,
        ...(includeModerated ? {} : { moderated: false })
      },
      _count: {
        rating: true,
      },
    })

    const ratingDistribution = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 }
    ratingStats.forEach(stat => {
      ratingDistribution[stat.rating as keyof typeof ratingDistribution] = stat._count.rating
    })

    // Calculate additional statistics
    const stats = await prisma.review.aggregate({
      where: { 
        hotelId, 
        verified: verifiedOnly,
        ...(includeModerated ? {} : { moderated: false })
      },
      _avg: {
        rating: true,
        cleanliness: true,
        comfort: true,
        service: true,
        value: true
      },
      _count: {
        _all: true
      }
    })

    // Advanced audit logging (for authenticated users)
    if (role !== 'ANONYMOUS') {
      await logAdvancedReviewAction(
        'REVIEWS_RETRIEVED',
        userId,
        { 
          query: { hotelId, minRating, maxRating, verifiedOnly },
          results: total,
          performance: { duration: Date.now() - startTime }
        },
        {
          hotelId: hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
    }

    return NextResponse.json(
      successResponse(
        {
          reviews: processedReviews,
          total,
          page,
          pageSize,
          hasMore: (page * pageSize) < total,
          ratingDistribution,
          statistics: {
            averageRating: Math.round((stats._avg.rating || 0) * 100) / 100,
            averageCleanliness: Math.round((stats._avg.cleanliness || 0) * 100) / 100,
            averageComfort: Math.round((stats._avg.comfort || 0) * 100) / 100,
            averageService: Math.round((stats._avg.service || 0) * 100) / 100,
            averageValue: Math.round((stats._avg.value || 0) * 100) / 100,
            totalReviews: stats._count._all
          },
          performance: {
            responseTime: Date.now() - startTime,
            rateLimitRemaining: rateLimit.remaining,
            securityChecks: 0,
            totalProcessed: reviews.length,
            anonymousAccess: role === 'ANONYMOUS'
          },
          securityInfo: {
            accessLevel: role,
            publicAccess: true,
            dataFiltered: role === 'ANONYMOUS',
            moderationApplied: !includeModerated
          }
        },
        "Reviews retrieved successfully with enhanced analytics"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Get Reviews Advanced Error] ${duration}ms`, error)
    
    await logAdvancedReviewAction(
      'REVIEWS_RETRIEVAL_ERROR',
      'system',
      { 
        error: error.message,
        duration,
        stack: error.stack
      },
      {
        hotelId: 'unknown',
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
      }
    )
    
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch reviews", "FETCH_REVIEWS_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}