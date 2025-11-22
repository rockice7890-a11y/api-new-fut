import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { z } from "zod"
import { v4 as uuidv4 } from "uuid"

export const dynamic = 'force-dynamic'

// Validation Schemas
const createTransactionSchema = z.object({
  hotelId: z.string(),
  category: z.enum([
    'REVENUE_ROOM', 'REVENUE_FNB', 'REVENUE_SPA', 'REVENUE_EVENTS', 'REVENUE_OTHER',
    'EXPENSE_STAFF', 'EXPENSE_UTILITIES', 'EXPENSE_SUPPLIES', 
    'EXPENSE_MAINTENANCE', 'EXPENSE_MARKETING', 'EXPENSE_INSURANCE', 'EXPENSE_OTHER'
  ]),
  type: z.enum(['INCOME', 'EXPENSE']),
  amount: z.number().positive(),
  currency: z.string().default('USD'),
  bookingId: z.string().optional(),
  invoiceId: z.string().optional(),
  paymentId: z.string().optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 
    'CORPORATE_BILL', 'LOYALTY_POINTS', 'PROMOTION_CREDIT'
  ]),
  transactionDate: z.string().transform((str) => new Date(str)).optional(),
  description: z.string().min(1).max(500),
  notes: z.string().max(1000).optional(),
  taxAmount: z.number().min(0).default(0),
  taxRate: z.number().min(0).max(1).default(0),
  receiptUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional()
})

const updateTransactionSchema = z.object({
  amount: z.number().positive().optional(),
  currency: z.string().optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 
    'CORPORATE_BILL', 'LOYALTY_POINTS', 'PROMOTION_CREDIT'
  ]).optional(),
  description: z.string().min(1).max(500).optional(),
  notes: z.string().max(1000).optional(),
  taxAmount: z.number().min(0).optional(),
  taxRate: z.number().min(0).max(1).optional(),
  status: z.enum(['PENDING', 'COMPLETED', 'FAILED', 'CANCELLED', 'REFUNDED', 'PARTIALLY_PAID']).optional(),
  receiptUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional()
})

// GET /api/accounting/transactions - Get financial transactions
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    
    // Pagination
    const page = parseInt(searchParams.get('page') || '1')
    const pageSize = parseInt(searchParams.get('pageSize') || '20')
    
    // Filters
    const hotelId = searchParams.get('hotelId')
    const category = searchParams.get('category')
    const type = searchParams.get('type') // INCOME or EXPENSE
    const status = searchParams.get('status')
    const paymentMethod = searchParams.get('paymentMethod')
    
    // Date Range
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    const fiscalYear = searchParams.get('fiscalYear')
    const fiscalPeriod = searchParams.get('fiscalPeriod')
    
    // Search
    const search = searchParams.get('search') // Search in description
    
    // Build where clause
    const where: any = {}
    
    // Role-based filtering
    if (auth.payload.role === 'HOTEL_MANAGER') {
      // Hotel managers can only see transactions for their hotels
      const userHotels = await prisma.hotel.findMany({
        where: { managerId: auth.payload.userId },
        select: { id: true }
      })
      where.hotelId = { in: userHotels.map(h => h.id) }
    }
    
    if (hotelId) where.hotelId = hotelId
    if (category) where.category = category
    if (type) where.type = type
    if (status) where.status = status
    if (paymentMethod) where.paymentMethod = paymentMethod
    
    // Date filtering
    if (startDate || endDate) {
      where.transactionDate = {}
      if (startDate) where.transactionDate.gte = new Date(startDate)
      if (endDate) where.transactionDate.lte = new Date(endDate)
    }
    
    if (fiscalYear) where.fiscalYear = parseInt(fiscalYear)
    if (fiscalPeriod) where.fiscalPeriod = fiscalPeriod
    
    // Search in description
    if (search) {
      where.description = {
        contains: search,
        mode: 'insensitive'
      }
    }

    const [transactions, total] = await Promise.all([
      prisma.financialTransaction.findMany({
        where,
        include: {
          hotel: {
            select: { name: true, city: true }
          },
          booking: {
            select: {
              id: true,
              bookingReference: true,
              guestName: true,
              totalPrice: true
            }
          },
          invoice: {
            select: {
              id: true,
              invoiceNumber: true,
              totalAmount: true
            }
          },
          payment: {
            select: {
              id: true,
              status: true,
              method: true
            }
          }
        },
        orderBy: { transactionDate: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.financialTransaction.count({ where })
    ])

    // Calculate summary statistics
    const summary = await prisma.financialTransaction.groupBy({
      by: ['type'],
      where: {
        ...where,
        // Remove pagination for summary
        // Remove search for summary to avoid filtering
      },
      _sum: { amount: true }
    })

    const totalIncome = summary.find(s => s.type === 'INCOME')?._sum.amount || 0
    const totalExpense = summary.find(s => s.type === 'EXPENSE')?._sum.amount || 0
    const netAmount = totalIncome - totalExpense

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            transactions,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: {
              totalIncome,
              totalExpense,
              netAmount,
              transactionCount: total
            }
          },
          "Financial transactions retrieved successfully"
        )
      )
    )
  } catch (error: any) {
    console.error("[Get Transactions Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch transactions", "FETCH_TRANSACTIONS_ERROR"),
        { status: 500 }
      )
    )
  }
}

// POST /api/accounting/transactions - Create new financial transaction
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
  if (!auth.isValid) return auth.response!

  try {
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`create_transaction:${clientIP}`, 100, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Too many transaction creation requests", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        )
      )
    }

    const body = await req.json()
    const validated = createTransactionSchema.parse(body)

    // Verify hotel access
    if (auth.payload.role === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { 
          managerId: auth.payload.userId,
          id: validated.hotelId
        },
        select: { id: true }
      })
      
      if (userHotels.length === 0) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Access denied to this hotel", "ACCESS_DENIED"),
            { status: 403 }
          )
        )
      }
    }

    // Verify related records exist
    if (validated.bookingId) {
      const booking = await prisma.booking.findUnique({
        where: { id: validated.bookingId }
      })
      if (!booking) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Booking not found", "BOOKING_NOT_FOUND"),
            { status: 404 }
          )
        )
      }
    }

    // Calculate fiscal period
    const transactionDate = validated.transactionDate || new Date()
    const fiscalYear = transactionDate.getFullYear()
    const fiscalPeriod = `${transactionDate.getFullYear()}-${String(transactionDate.getMonth() + 1).padStart(2, '0')}`

    // Generate unique transaction number
    const transactionNumber = `TXN-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`

    // Create transaction
    const transaction = await prisma.financialTransaction.create({
      data: {
        ...validated,
        transactionNumber,
        transactionDate,
        fiscalYear,
        fiscalPeriod,
        status: validated.type === 'INCOME' ? 'COMPLETED' : 'PENDING',
        createdBy: auth.payload.userId
      },
      include: {
        hotel: {
          select: { name: true, city: true }
        },
        booking: {
          select: {
            id: true,
            bookingReference: true,
            guestName: true,
            totalPrice: true
          }
        }
      }
    })

    // Create audit log
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'CREATE',
        resource: 'FINANCIAL_TRANSACTION',
        resourceId: transaction.id,
        endpoint: '/api/accounting/transactions',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          transactionNumber: transaction.transactionNumber,
          amount: transaction.amount,
          category: transaction.category,
          type: transaction.type
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(transaction, "Financial transaction created successfully"),
        { status: 201 }
      )
    )
  } catch (error: any) {
    console.error("[Create Transaction Error]", error)
    
    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse({ errors: error.errors }, "Invalid transaction data", "VALIDATION_ERROR"),
          { status: 400 }
        )
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to create transaction", "CREATE_TRANSACTION_ERROR"),
        { status: 500 }
      )
    )
  }
}

// PUT /api/accounting/transactions - Update transaction
export async function PUT(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const transactionId = searchParams.get('id')
    
    if (!transactionId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Transaction ID is required", "MISSING_TRANSACTION_ID"),
          { status: 400 }
        )
      )
    }

    // Verify transaction exists and user has access
    const existingTransaction = await prisma.financialTransaction.findUnique({
      where: { id: transactionId },
      include: { hotel: true }
    })

    if (!existingTransaction) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Transaction not found", "TRANSACTION_NOT_FOUND"),
          { status: 404 }
        )
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && existingTransaction.hotel.managerId !== auth.payload.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this transaction", "ACCESS_DENIED"),
          { status: 403 }
        )
      )
    }

    const body = await req.json()
    const validated = updateTransactionSchema.parse(body)

    const updatedTransaction = await prisma.financialTransaction.update({
      where: { id: transactionId },
      data: validated,
      include: {
        hotel: {
          select: { name: true, city: true }
        },
        booking: {
          select: {
            id: true,
            bookingReference: true,
            guestName: true
          }
        }
      }
    })

    // Create audit log
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'UPDATE',
        resource: 'FINANCIAL_TRANSACTION',
        resourceId: transactionId,
        endpoint: '/api/accounting/transactions',
        method: 'PUT',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          amount: existingTransaction.amount,
          status: existingTransaction.status,
          description: existingTransaction.description
        }),
        newValues: JSON.stringify({
          amount: updatedTransaction.amount,
          status: updatedTransaction.status,
          description: updatedTransaction.description
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(updatedTransaction, "Financial transaction updated successfully")
      )
    )
  } catch (error: any) {
    console.error("[Update Transaction Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to update transaction", "UPDATE_TRANSACTION_ERROR"),
        { status: 500 }
      )
    )
  }
}

// DELETE /api/accounting/transactions - Delete transaction
export async function DELETE(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const transactionId = searchParams.get('id')
    
    if (!transactionId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Transaction ID is required", "MISSING_TRANSACTION_ID"),
          { status: 400 }
        )
      )
    }

    // Verify transaction exists and user has access
    const existingTransaction = await prisma.financialTransaction.findUnique({
      where: { id: transactionId },
      include: { hotel: true }
    })

    if (!existingTransaction) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Transaction not found", "TRANSACTION_NOT_FOUND"),
          { status: 404 }
        )
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && existingTransaction.hotel.managerId !== auth.payload.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this transaction", "ACCESS_DENIED"),
          { status: 403 }
        )
      )
    }

    // Prevent deletion of completed transactions
    if (existingTransaction.status === 'COMPLETED') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Cannot delete completed transactions", "INVALID_OPERATION"),
          { status: 400 }
        )
      )
    }

    await prisma.financialTransaction.delete({
      where: { id: transactionId }
    })

    // Create audit log
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'DELETE',
        resource: 'FINANCIAL_TRANSACTION',
        resourceId: transactionId,
        endpoint: '/api/accounting/transactions',
        method: 'DELETE',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          transactionNumber: existingTransaction.transactionNumber,
          amount: existingTransaction.amount,
          category: existingTransaction.category
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(null, "Financial transaction deleted successfully")
      )
    )
  } catch (error: any) {
    console.error("[Delete Transaction Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to delete transaction", "DELETE_TRANSACTION_ERROR"),
        { status: 500 }
      )
    )
  }
}