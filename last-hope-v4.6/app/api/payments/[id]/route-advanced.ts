import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updatePaymentSchema } from "@/lib/validation"
import { advancedAPISecurity } from "@/lib/api-security-advanced"

export const dynamic = 'force-dynamic'

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // تطبيق النظام المتقدم للأمان
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action === 'BLOCK') {
      console.warn(`[Advanced Security] Payment detail access blocked for request from ${req.ip}`, {
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

    const { id } = await params
    
    // Enhanced ID validation with security checks
    if (!id || typeof id !== 'string' || id.length > 36 || !/^[a-fA-F0-9\-]+$/.test(id)) {
      return NextResponse.json(
        failResponse(null, "Invalid payment ID", "INVALID_PAYMENT_ID"),
        { status: 400 }
      )
    }
    
    const payment = await prisma.payment.findUnique({
      where: { id },
      include: {
        booking: {
          include: {
            user: {
              select: {
                firstName: true,
                lastName: true,
                email: true,
              },
            },
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

    if (!payment) {
      return NextResponse.json(
        failResponse(null, "Payment not found", "PAYMENT_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Enhanced access permissions with audit trail
    const isOwner = payment.booking.userId === auth.payload.userId
    const isAdmin = auth.payload.role === 'ADMIN'
    const isHotelManager = await prisma.hotel.findFirst({
      where: {
        id: payment.booking.hotelId,
        managerId: auth.payload.userId,
      },
    })

    if (!isOwner && !isAdmin && !isHotelManager) {
      console.warn(`[Security] Unauthorized payment access attempt by user ${auth.payload.userId} for payment ${id}`)
      return NextResponse.json(
        failResponse(null, "Access denied", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Enhanced response with security metadata
    return NextResponse.json(
      successResponse(payment, "Payment retrieved successfully", {
        security: {
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          accessType: isOwner ? 'OWNER' : isAdmin ? 'ADMIN' : 'MANAGER',
          monitoring: decision.action === 'MONITOR'
        }
      }),
      { 
        status: 200,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Get Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch payment", "FETCH_PAYMENT_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // تطبيق النظام المتقدم للأمان
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action === 'BLOCK') {
      console.warn(`[Advanced Security] Payment update blocked for request from ${req.ip}`, {
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

    const { id } = await params
    
    // Enhanced ID validation
    if (!id || typeof id !== 'string' || id.length > 36 || !/^[a-fA-F0-9\-]+$/.test(id)) {
      return NextResponse.json(
        failResponse(null, "Invalid payment ID", "INVALID_PAYMENT_ID"),
        { status: 400 }
      )
    }

    // Enhanced input validation with security filtering
    let body: any
    try {
      body = await req.json()
    } catch (jsonError) {
      return NextResponse.json(
        failResponse(null, "Invalid JSON format", "INVALID_JSON"),
        { status: 400 }
      )
    }

    const validated = updatePaymentSchema.parse(body)

    // Find the payment with enhanced security
    const payment = await prisma.payment.findUnique({
      where: { id },
      include: {
        booking: {
          include: {
            hotel: {
              select: { managerId: true },
            },
          },
        },
      },
    })

    if (!payment) {
      return NextResponse.json(
        failResponse(null, "Payment not found", "PAYMENT_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Enhanced permissions check with audit logging
    const isHotelManager = payment.booking.hotel.managerId === auth.payload.userId
    const isAdmin = auth.payload.role === 'ADMIN'

    if (!isHotelManager && !isAdmin) {
      console.warn(`[Security] Unauthorized payment update attempt by user ${auth.payload.userId} for payment ${id}`)
      return NextResponse.json(
        failResponse(null, "Only hotel managers and admins can update payments", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Enhanced data validation for payment updates
    const updateData: any = {}
    
    if (validated.status !== undefined) {
      // Validate status transitions for security
      const allowedStatuses = ['pending', 'completed', 'failed', 'cancelled', 'refunded']
      if (!allowedStatuses.includes(validated.status)) {
        return NextResponse.json(
          failResponse(null, "Invalid payment status", "INVALID_STATUS"),
          { status: 400 }
        )
      }
      
      updateData.status = validated.status
      
      // Enhanced timestamp logic with timezone awareness
      if (validated.status === 'completed' && !payment.paidAt) {
        updateData.paidAt = new Date()
        console.log(`[Payment Security] Payment ${id} marked as completed by ${auth.payload.role}`)
      } else if (validated.status === 'refunded' && !payment.refundedAt) {
        updateData.refundedAt = new Date()
        console.log(`[Payment Security] Payment ${id} marked as refunded by ${auth.payload.role}`)
      }
    }
    
    if (validated.transactionId !== undefined) {
      // Enhanced transaction ID validation
      if (typeof validated.transactionId === 'string' && validated.transactionId.length <= 255) {
        updateData.transactionId = validated.transactionId
      } else {
        return NextResponse.json(
          failResponse(null, "Invalid transaction ID", "INVALID_TRANSACTION_ID"),
          { status: 400 }
        )
      }
    }
    
    if (validated.paidAt !== undefined) {
      const paidAtDate = new Date(validated.paidAt)
      if (!isNaN(paidAtDate.getTime()) && paidAtDate <= new Date()) {
        updateData.paidAt = paidAtDate
      } else {
        return NextResponse.json(
          failResponse(null, "Invalid paid at date", "INVALID_DATE"),
          { status: 400 }
        )
      }
    }
    
    if (validated.refundedAt !== undefined) {
      const refundedAtDate = new Date(validated.refundedAt)
      if (!isNaN(refundedAtDate.getTime()) && refundedAtDate <= new Date()) {
        updateData.refundedAt = refundedAtDate
      } else {
        return NextResponse.json(
          failResponse(null, "Invalid refunded at date", "INVALID_DATE"),
          { status: 400 }
        )
      }
    }

    // Enhanced payment update with audit trail
    const updatedPayment = await prisma.payment.update({
      where: { id },
      data: {
        ...updateData,
        updatedAt: new Date(),
        metadata: {
          ...payment.metadata,
          lastUpdateBy: auth.payload.userId,
          lastUpdateRole: auth.payload.role,
          lastUpdateReason: 'API_UPDATE',
          securityContext: {
            threatScore: decision.threatScore,
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

    // Enhanced booking status updates with validation
    if (validated.status === 'completed' && payment.booking.status === 'PENDING') {
      await prisma.booking.update({
        where: { id: payment.bookingId },
        data: { 
          status: 'CONFIRMED',
          updatedAt: new Date()
        },
      })
      console.log(`[Booking Security] Booking ${payment.bookingId} confirmed due to payment completion`)
    }

    if (validated.status === 'refunded') {
      await prisma.booking.update({
        where: { id: payment.bookingId },
        data: { 
          status: 'CANCELLED',
          updatedAt: new Date()
        },
      })
      console.log(`[Booking Security] Booking ${payment.bookingId} cancelled due to refund`)
    }

    console.log(`[Payment Security] Payment ${id} updated by ${auth.payload.role} - Status: ${validated.status}`)

    return NextResponse.json(
      successResponse(updatedPayment, "Payment updated successfully", {
        security: {
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          updateType: 'MANUAL',
          audit: {
            updatedBy: auth.payload.userId,
            updatedAt: new Date().toISOString()
          }
        }
      }),
      { 
        status: 200,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Update Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update payment", "UPDATE_PAYMENT_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // تطبيق النظام المتقدم للأمان - DELETE requires highest security
    const securityContext = await advancedAPISecurity.analyzeSecurityContext(req)
    const decision = await advancedAPISecurity.makeSecurityDecision(securityContext)
    
    if (decision.action !== 'ALLOW') {
      console.warn(`[Advanced Security] Payment deletion blocked for request from ${req.ip}`, {
        threatScore: decision.threatScore,
        reasons: decision.reasons,
        requiresAdminApproval: true
      })
      return NextResponse.json(
        failResponse(null, "Payment deletion requires additional security verification", "SECURITY_BLOCK"),
        { status: 403 }
      )
    }

    const auth = await withAuth(req)
    if (!auth.isValid) return auth.response!

    const { id } = await params

    // Enhanced ID validation for DELETE operations
    if (!id || typeof id !== 'string' || id.length > 36 || !/^[a-fA-F0-9\-]+$/.test(id)) {
      return NextResponse.json(
        failResponse(null, "Invalid payment ID", "INVALID_PAYMENT_ID"),
        { status: 400 }
      )
    }

    // Find the payment with enhanced security
    const payment = await prisma.payment.findUnique({
      where: { id },
      include: {
        booking: {
          include: {
            hotel: {
              select: { managerId: true },
            },
          },
        },
      },
    })

    if (!payment) {
      return NextResponse.json(
        failResponse(null, "Payment not found", "PAYMENT_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Strict permissions check - only admins can delete payments with enhanced logging
    if (auth.payload.role !== 'ADMIN') {
      console.warn(`[Security] Non-admin delete attempt for payment ${id} by user ${auth.payload.userId}`)
      return NextResponse.json(
        failResponse(null, "Only administrators can delete payments", "INSUFFICIENT_PERMISSIONS"),
        { status: 403 }
      )
    }

    // Enhanced protection for completed payments
    if (payment.status === 'completed') {
      return NextResponse.json(
        failResponse(null, "Cannot delete completed payments", "PAYMENT_COMPLETED"),
        { status: 400 }
      )
    }

    // Enhanced logging for payment deletion
    console.log(`[Payment Security] Deleting payment ${id} by admin ${auth.payload.userId}`, {
      paymentAmount: payment.amount,
      paymentCurrency: payment.currency,
      paymentStatus: payment.status,
      securityThreatScore: decision.threatScore
    })

    // Create audit log before deletion
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'DELETE_PAYMENT',
        resourceType: 'Payment',
        resourceId: id,
        details: {
          deletedPayment: {
            id: payment.id,
            amount: payment.amount,
            currency: payment.currency,
            status: payment.status,
            createdAt: payment.createdAt
          },
          deletedBy: auth.payload.userId,
          deletedAt: new Date().toISOString(),
          securityContext: {
            threatScore: decision.threatScore,
            securityLevel: securityContext.securityLevel
          }
        }
      }
    })

    // Delete payment with enhanced error handling
    await prisma.payment.delete({
      where: { id },
    })

    console.log(`[Payment Security] Payment ${id} successfully deleted by admin ${auth.payload.userId}`)

    return NextResponse.json(
      successResponse(null, "Payment deleted successfully", {
        security: {
          threatScore: decision.threatScore,
          securityLevel: securityContext.securityLevel,
          action: 'DELETED',
          audit: {
            deletedBy: auth.payload.userId,
            deletedAt: new Date().toISOString(),
            requiresAuditReview: true
          }
        }
      }),
      { 
        status: 200,
        headers: {
          'X-Security-Threat-Score': decision.threatScore.toString(),
          'X-Security-Action': decision.action,
          'X-Security-Level': securityContext.securityLevel,
          'X-Admin-Action': 'DELETE_PAYMENT'
        }
      }
    )
  } catch (error: any) {
    console.error("[Advanced Delete Payment Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to delete payment", "DELETE_PAYMENT_ERROR"), 
      { 
        status: 500,
        headers: {
          'X-Error-Type': 'ADVANCED_SECURITY_ERROR'
        }
      }
    )
  }
}