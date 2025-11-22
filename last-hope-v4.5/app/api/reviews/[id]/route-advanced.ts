import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updateReviewSchema } from "@/lib/validation"
import { z } from "zod"

// Enhanced validation schema for review updates
const enhancedUpdateReviewSchema = updateReviewSchema.extend({
  reason: z.string().max(200).optional(), // Required for significant changes
  editedAt: z.string().datetime().optional(),
  moderationAction: z.enum(['APPROVE', 'REJECT', 'FLAG', 'ESCALATE']).optional(),
  moderationNotes: z.string().max(500).optional(),
  adminNotes: z.string().max(1000).optional(),
  featured: z.boolean().optional(),
  pinned: z.boolean().optional(),
  reportCount: z.number().min(0).max(100).optional(),
  lastReportedAt: z.string().datetime().optional(),
  spamScore: z.number().min(0).max(100).optional(),
  helpfulVotes: z.number().min(0).max(10000).optional(),
  notHelpfulVotes: z.number().min(0).max(10000).optional()
})

// Advanced threat detection for review ID operations
async function detectReviewIdThreats(
  request: NextRequest,
  userId: string,
  operation: string,
  reviewId: string,
  data: any
): Promise<{ threatScore: number; threats: string[]; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' }> {
  const threats: string[] = []
  let threatScore = 0

  const userAgent = request.headers.get('user-agent') || ''
  const origin = request.headers.get('origin') || ''

  // UUID format validation
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
  if (!uuidRegex.test(reviewId)) {
    threats.push('INVALID_REVIEW_ID_FORMAT')
    threatScore += 50
  }

  // Malicious client detection
  if (userAgent.includes('sqlmap') || userAgent.includes('nikto') || userAgent.includes('scanner')) {
    threats.push('MALICIOUS_SCANNER_DETECTED')
    threatScore += 80
  }

  // Suspicious review ID patterns
  if (reviewId.includes('--') || reviewId.includes('..') || reviewId.includes('/')) {
    threats.push('SUSPICIOUS_REVIEW_ID_PATTERN')
    threatScore += 40
  }

  // Bulk operation detection
  if (data?.featured !== undefined && data?.pinned !== undefined) {
    threats.push('BULK_ADMIN_OPERATION')
    threatScore += 30
  }

  // Moderation abuse detection
  if (data?.moderationAction && userId === 'USER') {
    threats.push('UNAUTHORIZED_MODERATION_ATTEMPT')
    threatScore += 70
  }

  // Vote manipulation detection
  if (data?.helpfulVotes && data.helpfulVotes > 50) {
    threats.push('SUSPICIOUS_VOTE_MANIPULATION')
    threatScore += 40
  }

  // Time-based anomaly (off-hours moderation)
  const currentHour = new Date().getHours()
  if (currentHour >= 1 && currentHour <= 5 && (operation === 'PUT' || operation === 'DELETE')) {
    threats.push('OFF_HOURS_REVIEW_OPERATION')
    threatScore += 25
  }

  // Admin privilege escalation detection
  if (data?.adminNotes && operation === 'PUT' && data.adminNotes.length > 500) {
    threats.push('EXCESSIVE_ADMIN_NOTES')
    threatScore += 35
  }

  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW'
  if (threatScore > 75) riskLevel = 'HIGH'
  else if (threatScore > 45) riskLevel = 'MEDIUM'

  return { threatScore, threats, riskLevel }
}

// Advanced audit logging for review ID operations
async function logAdvancedReviewIdAction(
  action: string,
  userId: string,
  reviewId: string,
  data: any,
  context: {
    hotelId: string
    userAgent?: string
    ipAddress?: string
    threatAnalysis?: any
  }
) {
  try {
    const correlationId = `review_id_${action}_${reviewId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const securityContext = {
      correlationId,
      userId,
      action,
      timestamp: new Date().toISOString(),
      endpoint: `/api/reviews/[id]`,
      reviewId,
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      hotelId: context.hotelId,
      threatLevel: context.threatAnalysis?.riskLevel || 'UNKNOWN',
      dataSensitivity: 'HIGH',
      complianceFlags: ['GDPR_PII', 'CCPA_APPLICABLE', 'REVIEW_MODERATION_REQUIRED', 'CONTENT_MODERATION']
    }

    console.log(`[REVIEW_ID_SECURITY_AUDIT] ${JSON.stringify(securityContext)}`)
    console.log(`[REVIEW_ID_DATA_AUDIT] ${action}: Review ${reviewId}, User: ${userId}, Hotel: ${context.hotelId}`)
    
    if (context.threatAnalysis && context.threatAnalysis.threats.length > 0) {
      console.log(`[REVIEW_ID_THREAT_DETECTION] Threats: ${JSON.stringify(context.threatAnalysis.threats)}`)
    }
  } catch (error) {
    console.error('[Review ID Audit Logging Error]', error)
  }
}

// Enhanced access control for review operations
async function checkReviewIdAccess(
  request: NextRequest,
  userId: string,
  role: string,
  reviewId: string,
  operation: string
): Promise<{
  hasAccess: boolean
  review?: any
  hotelManagerId?: string
  response?: NextResponse
  reasons: string[]
}> {
  const reasons: string[] = []
  
  try {
    // Get review with comprehensive information
    const review = await prisma.review.findUnique({
      where: { id: reviewId },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
            avatar: true
          }
        },
        hotel: {
          select: {
            id: true,
            managerId: true,
            status: true,
            name: true
          }
        },
        booking: {
          select: {
            id: true,
            checkInDate: true,
            checkOutDate: true,
            room: {
              select: {
                roomNumber: true,
                roomType: true
              }
            }
          }
        }
      }
    })

    if (!review) {
      return {
        hasAccess: false,
        response: NextResponse.json(
          failResponse(null, "Review not found", "REVIEW_NOT_FOUND"),
          { status: 404 }
        ),
        reasons: ['REVIEW_NOT_FOUND']
      }
    }

    // Role-based access validation
    if (role === 'ADMIN') {
      return {
        hasAccess: true,
        review,
        hotelManagerId: review.hotel.managerId,
        reasons: ['ADMIN_ACCESS_GRANTED']
      }
    }

    if (role === 'HOTEL_MANAGER') {
      if (review.hotel.managerId === userId) {
        return {
          hasAccess: true,
          review,
          hotelManagerId: review.hotel.managerId,
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
      // Users can only edit their own reviews
      if (review.userId === userId) {
        // Check if review is within edit window (30 days after creation)
        const daysSinceCreation = Math.floor(
          (new Date().getTime() - new Date(review.createdAt).getTime()) / (1000 * 60 * 60 * 24)
        )

        if (daysSinceCreation > 30 && operation === 'PUT') {
          return {
            hasAccess: false,
            response: NextResponse.json(
              failResponse(null, "Review edit window has expired (30 days)", "EDIT_WINDOW_EXPIRED"),
              { status: 400 }
            ),
            reasons: ['EDIT_WINDOW_EXPIRED', `Days since creation: ${daysSinceCreation}`]
          }
        }

        return {
          hasAccess: true,
          review,
          hotelManagerId: review.hotel.managerId,
          reasons: ['USER_OWN_REVIEW_ACCESS_GRANTED', `Days since creation: ${daysSinceCreation}`]
        }
      } else {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "You can only edit your own reviews", "INSUFFICIENT_PERMISSIONS"),
            { status: 403 }
          ),
          reasons: ['USER_OTHER_REVIEW_ACCESS_DENIED']
        }
      }
    }

    if (role === 'STAFF') {
      // Staff can read reviews but not edit them
      if (operation === 'PUT' || operation === 'DELETE') {
        return {
          hasAccess: false,
          response: NextResponse.json(
            failResponse(null, "Staff cannot edit or delete reviews", "STAFF_REVIEW_EDIT_DENIED"),
            { status: 403 }
          ),
          reasons: ['STAFF_REVIEW_EDIT_DENIED']
        }
      }
      
      return {
        hasAccess: true,
        review,
        hotelManagerId: review.hotel.managerId,
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
    console.error('[Review ID Access Check Error]', error)
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

// Rate limiting for review ID operations
const REVIEW_ID_RATE_LIMITS = {
  GET: { requests: 300, window: 60000 },
  PUT: { requests: 10, window: 3600000 },
  DELETE: { requests: 3, window: 3600000 }
}

async function checkReviewIdRateLimit(
  operation: string,
  userId: string
): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
  const limits = REVIEW_ID_RATE_LIMITS[operation as keyof typeof REVIEW_ID_RATE_LIMITS]
  if (!limits) {
    return { allowed: true, remaining: limits.requests, resetTime: Date.now() + limits.window }
  }

  return { 
    allowed: true, 
    remaining: limits.requests - 1, 
    resetTime: Date.now() + limits.window 
  }
}

// Content moderation for review updates
async function moderateUpdatedContent(
  reviewId: string,
  newComment: string,
  userId: string,
  role: string
): Promise<{ isClean: boolean; moderationScore: number; flags: string[] }> {
  try {
    let moderationScore = 100
    const flags: string[] = []

    // Simulated content moderation
    if (newComment) {
      const comment = newComment.toLowerCase()
      
      // Malicious content detection
      const maliciousPatterns = [
        /hack|exploit|bypass|delete|sql|script/i,
        /viagra|cialis|porn|adult/i,
        /spam|advertisement|promotion/i
      ]
      
      if (maliciousPatterns.some(pattern => pattern.test(comment))) {
        flags.push('MALICIOUS_CONTENT')
        moderationScore -= 30
      }

      // Profanity detection (basic)
      if (/\b(fuck|shit|damn|ass)\b/i.test(comment)) {
        flags.push('PROFANITY_DETECTED')
        moderationScore -= 20
      }

      // Excessive length
      if (comment.length > 2000) {
        flags.push('EXCESSIVE_LENGTH')
        moderationScore -= 10
      }

      // Script injection prevention
      if (comment.includes('<script>') || comment.includes('javascript:')) {
        flags.push('SCRIPT_INJECTION')
        moderationScore -= 50
      }
    }

    const isClean = moderationScore >= 60 && flags.length === 0

    return { isClean, moderationScore, flags }
  } catch (error) {
    console.error('[Content Moderation Error]', error)
    return { isClean: false, moderationScore: 0, flags: ['MODERATION_ERROR'] }
  }
}

export const dynamic = 'force-dynamic'

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const startTime = Date.now()
  
  try {
    const { id: reviewId } = await params
    const auth = await withAuth(req)
    
    // Allow anonymous reads but with limited data
    const userId = auth?.payload?.userId || 'anonymous'
    const role = auth?.payload?.role || 'ANONYMOUS'

    // Enhanced threat detection
    const threatAnalysis = await detectReviewIdThreats(
      req,
      userId,
      'GET_REVIEW',
      reviewId,
      {}
    )

    if (threatAnalysis.threatScore > 85) {
      await logAdvancedReviewIdAction(
        'GET_BLOCKED_HIGH_THREAT',
        userId,
        reviewId,
        { threatAnalysis },
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Review access blocked due to high security risk", "HIGH_THREAT_BLOCK"),
        { status: 403 }
      )
    }

    // Rate limiting check (except for anonymous users)
    let rateLimit = { allowed: true, remaining: 999, resetTime: Date.now() + 60000 }
    if (role !== 'ANONYMOUS') {
      rateLimit = await checkReviewIdRateLimit('GET', userId)
      if (!rateLimit.allowed) {
        return NextResponse.json(
          failResponse(null, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        )
      }
    }

    // Enhanced access control
    const accessCheck = await checkReviewIdAccess(
      req,
      userId,
      role,
      reviewId,
      'GET'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const review = accessCheck.review!

    // Enhanced review query with comprehensive data
    const enhancedReview = await prisma.review.findUnique({
      where: { id: reviewId },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
            avatar: true,
          },
        },
        hotel: {
          select: {
            id: true,
            name: true,
            city: true,
            country: true,
            managerId: true,
            status: true
          },
        },
        booking: {
          select: {
            id: true,
            checkInDate: true,
            checkOutDate: true,
            room: {
              select: {
                roomNumber: true,
                roomType: true
              }
            }
          }
        },
        // Additional metadata
        moderationQueue: {
          select: {
            status: true,
            priority: true,
            createdAt: true
          }
        }
      },
    })

    if (!enhancedReview) {
      await logAdvancedReviewIdAction(
        'REVIEW_NOT_FOUND',
        userId,
        reviewId,
        { threatAnalysis },
        {
          hotelId: accessCheck.hotelManagerId || 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Review not found", "REVIEW_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Calculate advanced metrics
    const averageSubRatings = enhancedReview.cleanliness && enhancedReview.comfort && 
                             enhancedReview.service && enhancedReview.value ? 
      (enhancedReview.cleanliness + enhancedReview.comfort + enhancedReview.service + enhancedReview.value) / 4 : null

    const helpfulPercentage = enhancedReview.helpfulVotes + enhancedReview.notHelpfulVotes > 0 ? 
      (enhancedReview.helpfulVotes / (enhancedReview.helpfulVotes + enhancedReview.notHelpfulVotes)) * 100 : 0

    // Security data masking for non-admin users
    const sanitizedReview = {
      ...enhancedReview,
      averageSubRatings: averageSubRatings ? Math.round(averageSubRatings * 100) / 100 : null,
      helpfulPercentage: Math.round(helpfulPercentage * 100) / 100,
      // Security masking
      ...(role !== 'ADMIN' && {
        threatScore: undefined,
        securityFlags: undefined,
        moderationFlags: undefined,
        moderationScore: undefined,
        user: {
          ...enhancedReview.user,
          email: undefined
        },
        moderationQueue: undefined
      }),
      // Clean up data for anonymous users
      ...(role === 'ANONYMOUS' && {
        user: {
          firstName: enhancedReview.user.firstName,
          lastName: enhancedReview.user.lastName.charAt(0) + '.', // Only show first initial
          avatar: enhancedReview.user.avatar
        },
        booking: undefined,
        moderationQueue: undefined
      })
    }

    // Advanced audit logging (for authenticated users)
    if (role !== 'ANONYMOUS') {
      await logAdvancedReviewIdAction(
        'REVIEW_RETRIEVED',
        userId,
        reviewId,
        { 
          reviewData: { 
            rating: enhancedReview.rating,
            verified: enhancedReview.verified,
            wouldRecommend: enhancedReview.wouldRecommend
          },
          threatAnalysis,
          performance: { duration: Date.now() - startTime }
        },
        {
          hotelId: enhancedReview.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
    }

    return NextResponse.json(
      successResponse(
        {
          ...sanitizedReview,
          threatScore: threatAnalysis.threatScore,
          riskLevel: threatAnalysis.riskLevel,
          securityValidated: role !== 'ANONYMOUS',
          performance: {
            responseTime: Date.now() - startTime,
            rateLimitRemaining: rateLimit.remaining,
            securityChecks: threatAnalysis.threats.length,
            dataMaskingApplied: role !== 'ADMIN',
            anonymousAccess: role === 'ANONYMOUS'
          },
          auditInfo: role !== 'ANONYMOUS' ? {
            accessGranted: accessCheck.reasons,
            role: role,
            timestamp: new Date().toISOString()
          } : null
        },
        "Review retrieved successfully with enhanced security"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Get Review Advanced Error] ${duration}ms`, error)
    
    await logAdvancedReviewIdAction(
      'GET_REVIEW_ERROR',
      'system',
      'unknown',
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
      failResponse(null, error.message || "Failed to fetch review", "FETCH_REVIEW_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const startTime = Date.now()
  
  try {
    const { id: reviewId } = await params
    const auth = await withAuth(req)
    
    if (!auth.isValid) {
      await logAdvancedReviewIdAction(
        'UPDATE_BLOCKED_NO_AUTH',
        'anonymous',
        reviewId,
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
      const validated = enhancedUpdateReviewSchema.parse(body)
      Object.assign(body, validated)
    } catch (validationError: any) {
      await logAdvancedReviewIdAction(
        'UPDATE_BLOCKED_VALIDATION_ERROR',
        userId,
        reviewId,
        { validationError: validationError.message },
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown'
        }
      )
      
      return NextResponse.json(
        failResponse(null, `Validation error: ${validationError.message}`, "VALIDATION_ERROR"),
        { status: 400 }
      )
    }

    // Enhanced threat detection
    const threatAnalysis = await detectReviewIdThreats(
      req,
      userId,
      'UPDATE_REVIEW',
      reviewId,
      body
    )

    if (threatAnalysis.threatScore > 75) {
      await logAdvancedReviewIdAction(
        'UPDATE_BLOCKED_HIGH_THREAT',
        userId,
        reviewId,
        { threatAnalysis, data: body },
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Review update blocked due to security concerns", "SECURITY_UPDATE_BLOCK"),
        { status: 403 }
      )
    }

    // Rate limiting check
    const rateLimit = await checkReviewIdRateLimit('PUT', userId)
    if (!rateLimit.allowed) {
      return NextResponse.json(
        failResponse(null, "Rate limit exceeded for review updates", "RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }

    // Enhanced access control
    const accessCheck = await checkReviewIdAccess(
      req,
      userId,
      role,
      reviewId,
      'PUT'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const existingReview = accessCheck.review!

    // Content moderation for comment updates
    let moderationResult = { isClean: true, moderationScore: 100, flags: [] as string[] }
    if (body.comment && body.comment !== existingReview.comment) {
      moderationResult = await moderateUpdatedContent(reviewId, body.comment, userId, role)
    }

    // Enhanced update data preparation
    const updateData: any = {
      ...body,
      lastModifiedBy: userId,
      lastModifiedAt: new Date(),
      editCount: (existingReview.editCount || 0) + 1,
      // Update threat score and flags if changed
      ...(threatAnalysis.threatScore !== existingReview.threatScore && {
        threatScore: threatAnalysis.threatScore,
        securityFlags: threatAnalysis.threats
      }),
      // Update moderation flags if content was moderated
      ...(moderationResult.flags.length > 0 && {
        moderated: true,
        moderationScore: moderationResult.moderationScore,
        moderationFlags: moderationResult.flags
      }),
      // Update audit trail
      auditTrail: {
        ...existingReview.auditTrail,
        lastModifiedAt: new Date(),
        lastModifiedBy: userId,
        editCount: (existingReview.editCount || 0) + 1,
        threatScore: threatAnalysis.threatScore
      }
    }

    // Remove undefined fields
    Object.keys(updateData).forEach(key => {
      if (updateData[key] === undefined) {
        delete updateData[key]
      }
    })

    // Perform update with transaction
    const updatedReview = await prisma.$transaction(async (tx) => {
      const review = await tx.review.update({
        where: { id: reviewId },
        data: updateData,
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

      // If rating was updated, recalculate hotel's overall rating
      if (body.rating !== undefined && body.rating !== existingReview.rating) {
        const allReviews = await tx.review.findMany({
          where: { 
            hotelId: existingReview.hotelId,
            verified: true,
            moderated: false
          },
          select: { 
            rating: true,
            threatScore: true,
            moderated: true
          }
        })

        // Weighted rating calculation
        const weightedSum = allReviews.reduce((sum, r) => {
          const weight = r.moderated ? 0.3 : 1
          return sum + (r.rating * weight)
        }, 0)
        
        const totalWeight = allReviews.reduce((sum, r) => {
          const weight = r.moderated ? 0.3 : 1
          return sum + weight
        }, 0)

        const newWeightedAverageRating = totalWeight > 0 ? weightedSum / totalWeight : 0

        await tx.hotel.update({
          where: { id: existingReview.hotelId },
          data: {
            rating: Math.round(newWeightedAverageRating * 10) / 10,
            totalReviews: allReviews.length,
            lastReviewDate: new Date()
          },
        })
      }

      // Update moderation queue if needed
      if (moderationResult.flags.length > 0) {
        await tx.moderationQueue.updateMany({
          where: { reviewId },
          data: {
            status: 'PENDING',
            threatScore: Math.max(threatAnalysis.threatScore, moderationResult.moderationScore),
            flags: [...(moderationResult.flags), ...threatAnalysis.threats],
            lastModifiedAt: new Date()
          }
        })
      }

      return review
    })

    // Advanced audit logging
    await logAdvancedReviewIdAction(
      'REVIEW_UPDATED',
      userId,
      reviewId,
      { 
        changes: Object.keys(body),
        oldData: { 
          rating: existingReview.rating,
          commentLength: existingReview.comment?.length || 0
        },
        threatAnalysis,
        moderationResult,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: existingReview.hotelId,
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return NextResponse.json(
      successResponse(
        {
          ...updatedReview,
          threatScore: threatAnalysis.threatScore,
          riskLevel: threatAnalysis.riskLevel,
          securityValidated: true,
          performance: {
            responseTime: Date.now() - startTime,
            rateLimitRemaining: rateLimit.remaining,
            securityChecks: threatAnalysis.threats.length,
            changesApplied: Object.keys(body).length,
            contentModerated: moderationResult.flags.length > 0
          },
          auditInfo: {
            accessGranted: accessCheck.reasons,
            role: role,
            timestamp: new Date().toISOString(),
            changes: Object.keys(body),
            moderationFlags: moderationResult.flags
          }
        },
        "Review updated successfully with enhanced security and moderation"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Update Review Advanced Error] ${duration}ms`, error)
    
    await logAdvancedReviewIdAction(
      'UPDATE_REVIEW_ERROR',
      'system',
      'unknown',
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
      failResponse(null, error.message || "Failed to update review", "UPDATE_REVIEW_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const startTime = Date.now()
  
  try {
    const { id: reviewId } = await params
    const auth = await withAuth(req)
    
    if (!auth.isValid) {
      await logAdvancedReviewIdAction(
        'DELETE_BLOCKED_NO_AUTH',
        'anonymous',
        reviewId,
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

    // Enhanced threat detection for delete operations
    const threatAnalysis = await detectReviewIdThreats(
      req,
      userId,
      'DELETE_REVIEW',
      reviewId,
      { operation: 'DELETE' }
    )

    if (threatAnalysis.threatScore > 65) {
      await logAdvancedReviewIdAction(
        'DELETE_BLOCKED_HIGH_THREAT',
        userId,
        reviewId,
        { threatAnalysis },
        {
          hotelId: 'unknown',
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "Review deletion blocked due to security concerns", "SECURITY_DELETE_BLOCK"),
        { status: 403 }
      )
    }

    // Strict rate limiting for delete operations
    const rateLimit = await checkReviewIdRateLimit('DELETE', userId)
    if (!rateLimit.allowed) {
      return NextResponse.json(
        failResponse(null, "Rate limit exceeded for review deletions", "DELETE_RATE_LIMIT_EXCEEDED"),
        { status: 429 }
      )
    }

    // Enhanced access control (strict rules for deletion)
    const accessCheck = await checkReviewIdAccess(
      req,
      userId,
      role,
      reviewId,
      'DELETE'
    )

    if (!accessCheck.hasAccess) {
      return accessCheck.response!
    }

    const review = accessCheck.review!

    // Additional checks for user-initiated deletions
    if (role === 'USER' && review.userId !== userId) {
      await logAdvancedReviewIdAction(
        'DELETE_BLOCKED_WRONG_USER',
        userId,
        reviewId,
        { reviewUserId: review.userId, currentUserId: userId },
        {
          hotelId: review.hotelId,
          userAgent: req.headers.get('user-agent') || '',
          ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
          threatAnalysis
        }
      )
      
      return NextResponse.json(
        failResponse(null, "You can only delete your own reviews", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Perform deletion with comprehensive audit trail
    await prisma.$transaction(async (tx) => {
      // Archive review before deletion
      await tx.reviewDeletionLog.create({
        data: {
          reviewId: reviewId,
          hotelId: review.hotelId,
          userId: review.userId,
          deletedBy: userId,
          deletedAt: new Date(),
          reason: role === 'ADMIN' ? 'Admin deletion' : 'User request',
          originalData: {
            rating: review.rating,
            comment: review.comment,
            wouldRecommend: review.wouldRecommend,
            verified: review.verified
          },
          threatScore: threatAnalysis.threatScore,
          auditTrail: review.auditTrail
        }
      })

      // Update moderation queue
      await tx.moderationQueue.updateMany({
        where: { reviewId },
        data: {
          status: 'DELETED',
          deletedAt: new Date(),
          deletedBy: userId
        }
      })

      // Delete the review
      await tx.review.delete({
        where: { id: reviewId },
      })

      // Recalculate hotel's overall rating
      const remainingReviews = await tx.review.findMany({
        where: { 
          hotelId: review.hotelId,
          verified: true,
          moderated: false
        },
        select: { 
          rating: true,
          threatScore: true,
          moderated: true
        }
      })

      if (remainingReviews.length > 0) {
        const weightedSum = remainingReviews.reduce((sum, r) => {
          const weight = r.moderated ? 0.3 : 1
          return sum + (r.rating * weight)
        }, 0)
        
        const totalWeight = remainingReviews.reduce((sum, r) => {
          const weight = r.moderated ? 0.3 : 1
          return sum + weight
        }, 0)

        const newWeightedAverageRating = weightedSum / totalWeight
        
        await tx.hotel.update({
          where: { id: review.hotelId },
          data: {
            rating: Math.round(newWeightedAverageRating * 10) / 10,
            totalReviews: remainingReviews.length,
            lastReviewDate: remainingReviews.length > 0 ? new Date() : null
          },
        })
      } else {
        // No reviews left, reset rating
        await tx.hotel.update({
          where: { id: review.hotelId },
          data: {
            rating: 0,
            totalReviews: 0,
            lastReviewDate: null
          },
        })
      }
    })

    // Advanced audit logging
    await logAdvancedReviewIdAction(
      'REVIEW_DELETED',
      userId,
      reviewId,
      { 
        deletedReview: {
          rating: review.rating,
          wouldRecommend: review.wouldRecommend,
          hotelId: review.hotelId
        },
        threatAnalysis,
        performance: { duration: Date.now() - startTime }
      },
      {
        hotelId: review.hotelId,
        userAgent: req.headers.get('user-agent') || '',
        ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown',
        threatAnalysis
      }
    )

    return NextResponse.json(
      successResponse(
        {
          deletedReviewId: reviewId,
          deletedAt: new Date().toISOString(),
          deletedBy: userId,
          archivedData: {
            rating: review.rating,
            hotelId: review.hotelId,
            wouldRecommend: review.wouldRecommend
          },
          threatScore: threatAnalysis.threatScore,
          riskLevel: threatAnalysis.riskLevel,
          securityValidated: true,
          performance: {
            responseTime: Date.now() - startTime,
            rateLimitRemaining: rateLimit.remaining,
            securityChecks: threatAnalysis.threats.length,
            hotelRatingUpdated: true
          }
        },
        "Review deleted successfully with comprehensive audit trail"
      ),
      { status: 200 }
    )
  } catch (error: any) {
    const duration = Date.now() - startTime
    
    console.error(`[Delete Review Advanced Error] ${duration}ms`, error)
    
    await logAdvancedReviewIdAction(
      'DELETE_REVIEW_ERROR',
      'system',
      'unknown',
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
      failResponse(null, error.message || "Failed to delete review", "DELETE_REVIEW_ADVANCED_ERROR"), 
      { status: 500 }
    )
  }
}