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
const createExpenseSchema = z.object({
  hotelId: z.string(),
  categoryId: z.string(),
  vendorId: z.string().optional(),
  amount: z.number().positive(),
  currency: z.string().default('USD'),
  description: z.string().min(1).max(500),
  notes: z.string().max(1000).optional(),
  expenseDate: z.string().transform((str) => new Date(str)).optional(),
  dueDate: z.string().transform((str) => new Date(str)).optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 'CORPORATE_BILL'
  ]),
  invoiceNumber: z.string().optional(),
  receiptNumber: z.string().optional(),
  receiptUrl: z.string().url().optional(),
  invoiceUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional(),
  bookingId: z.string().optional()
})

const updateExpenseSchema = z.object({
  amount: z.number().positive().optional(),
  currency: z.string().optional(),
  description: z.string().min(1).max(500).optional(),
  notes: z.string().max(1000).optional(),
  expenseDate: z.string().transform((str) => new Date(str)).optional(),
  dueDate: z.string().transform((str) => new Date(str)).optional(),
  paymentMethod: z.enum([
    'CASH', 'CARD', 'BANK_TRANSFER', 'MOBILE_WALLET', 'CHECK', 'CORPORATE_BILL'
  ]).optional(),
  invoiceNumber: z.string().optional(),
  receiptNumber: z.string().optional(),
  receiptUrl: z.string().url().optional(),
  invoiceUrl: z.string().url().optional(),
  attachments: z.array(z.string().url()).optional(),
  isApproved: z.boolean().optional(),
  approvalNotes: z.string().optional()
})

// GET /api/accounting/expenses - Get expenses
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
    const categoryId = searchParams.get('categoryId')
    const vendorId = searchParams.get('vendorId')
    const status = searchParams.get('status')
    const paymentMethod = searchParams.get('paymentMethod')
    const isApproved = searchParams.get('isApproved')
    
    // Date Range
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    
    // Search
    const search = searchParams.get('search') // Search in description
    
    // Build where clause
    const where: any = {}
    
    // Role-based filtering
    if (auth.payload.role === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { managerId: auth.payload.userId },
        select: { id: true }
      })
      where.hotelId = { in: userHotels.map(h => h.id) }
    }
    
    if (hotelId) where.hotelId = hotelId
    if (categoryId) where.categoryId = categoryId
    if (vendorId) where.vendorId = vendorId
    if (status) where.status = status
    if (paymentMethod) where.paymentMethod = paymentMethod
    if (isApproved !== null && isApproved !== undefined) {
      where.isApproved = isApproved === 'true'
    }
    
    // Date filtering
    if (startDate || endDate) {
      where.expenseDate = {}
      if (startDate) where.expenseDate.gte = new Date(startDate)
      if (endDate) where.expenseDate.lte = new Date(endDate)
    }
    
    // Search in description
    if (search) {
      where.description = {
        contains: search,
        mode: 'insensitive'
      }
    }

    const [expenses, total] = await Promise.all([
      prisma.expenseRecord.findMany({
        where,
        include: {
          hotel: {
            select: { name: true, city: true }
          },
          category: {
            select: { name: true, categoryType: true }
          },
          vendor: {
            select: {
              name: true,
              companyName: true,
              rating: true,
              reliabilityScore: true
            }
          },
          booking: {
            select: {
              id: true,
              bookingReference: true,
              guestName: true
            }
          }
        },
        orderBy: { expenseDate: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.expenseRecord.count({ where })
    ])

    // Calculate summary statistics
    const summary = await prisma.expenseRecord.groupBy({
      by: ['status'],
      where: {
        ...where,
        // Remove pagination and search for summary
      },
      _sum: { totalAmount: true },
      _count: true
    })

    const totalExpenses = summary.reduce((sum, item) => sum + (item._sum.totalAmount || 0), 0)
    const approvedExpenses = summary.find(s => s.status === 'COMPLETED')?._sum.totalAmount || 0
    const pendingExpenses = summary.find(s => s.status === 'PENDING')?._sum.totalAmount || 0

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            expenses,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: {
              totalExpenses,
              approvedExpenses,
              pendingExpenses,
              expenseCount: total
            }
          },
          "Expenses retrieved successfully"
        )
      )
    )
  } catch (error: any) {
    console.error("[Get Expenses Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch expenses", "FETCH_EXPENSES_ERROR"),
        { status: 500 }
      )
    )
  }
}

// POST /api/accounting/expenses - Create new expense
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
  if (!auth.isValid) return auth.response!

  try {
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`create_expense:${clientIP}`, 100, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Too many expense creation requests", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        )
      )
    }

    const body = await req.json()
    const validated = createExpenseSchema.parse(body)

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

    // Verify category exists and belongs to hotel
    const category = await prisma.expenseCategory.findUnique({
      where: { id: validated.categoryId }
    })

    if (!category || (category.hotelId && category.hotelId !== validated.hotelId)) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Invalid expense category", "INVALID_CATEGORY"),
          { status: 400 }
        )
      )
    }

    // Verify vendor if provided
    if (validated.vendorId) {
      const vendor = await prisma.vendor.findUnique({
        where: { id: validated.vendorId }
      })
      
      if (!vendor) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Vendor not found", "VENDOR_NOT_FOUND"),
            { status: 404 }
          )
        )
      }
    }

    // Calculate total amount
    const expenseDate = validated.expenseDate || new Date()
    const totalAmount = validated.amount // Tax calculation can be added here

    // Generate unique expense number
    const expenseNumber = `EXP-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`

    // Create expense
    const expense = await prisma.expenseRecord.create({
      data: {
        ...validated,
        expenseNumber,
        expenseDate,
        totalAmount,
        taxAmount: 0, // Can be calculated based on tax rules
        createdBy: auth.payload.userId
      },
      include: {
        hotel: {
          select: { name: true, city: true }
        },
        category: {
          select: { name: true, categoryType: true }
        },
        vendor: {
          select: {
            name: true,
            companyName: true,
            rating: true
          }
        }
      }
    })

    // Create audit log
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'CREATE',
        resource: 'EXPENSE_RECORD',
        resourceId: expense.id,
        endpoint: '/api/accounting/expenses',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          expenseNumber: expense.expenseNumber,
          amount: expense.amount,
          category: expense.category.name
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(expense, "Expense created successfully"),
        { status: 201 }
      )
    )
  } catch (error: any) {
    console.error("[Create Expense Error]", error)
    
    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse({ errors: error.errors }, "Invalid expense data", "VALIDATION_ERROR"),
          { status: 400 }
        )
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to create expense", "CREATE_EXPENSE_ERROR"),
        { status: 500 }
      )
    )
  }
}

// PUT /api/accounting/expenses - Update expense
export async function PUT(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const expenseId = searchParams.get('id')
    
    if (!expenseId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Expense ID is required", "MISSING_EXPENSE_ID"),
          { status: 400 }
        )
      )
    }

    // Verify expense exists and user has access
    const existingExpense = await prisma.expenseRecord.findUnique({
      where: { id: expenseId },
      include: { hotel: true }
    })

    if (!existingExpense) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Expense not found", "EXPENSE_NOT_FOUND"),
          { status: 404 }
        )
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && existingExpense.hotel.managerId !== auth.payload.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this expense", "ACCESS_DENIED"),
          { status: 403 }
        )
      )
    }

    const body = await req.json()
    const validated = updateExpenseSchema.parse(body)

    const updateData: any = { ...validated }

    // Handle approval
    if (validated.isApproved !== undefined) {
      if (validated.isApproved) {
        updateData.approvedBy = auth.payload.userId
        updateData.approvedAt = new Date()
        updateData.status = 'COMPLETED'
      }
      delete updateData.isApproved // Remove from update data
    }

    const updatedExpense = await prisma.expenseRecord.update({
      where: { id: expenseId },
      data: updateData,
      include: {
        hotel: {
          select: { name: true, city: true }
        },
        category: {
          select: { name: true, categoryType: true }
        },
        vendor: {
          select: {
            name: true,
            companyName: true,
            rating: true
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
        resource: 'EXPENSE_RECORD',
        resourceId: expenseId,
        endpoint: '/api/accounting/expenses',
        method: 'PUT',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          amount: existingExpense.amount,
          status: existingExpense.status,
          description: existingExpense.description
        }),
        newValues: JSON.stringify({
          amount: updatedExpense.amount,
          status: updatedExpense.status,
          description: updatedExpense.description
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(updatedExpense, "Expense updated successfully")
      )
    )
  } catch (error: any) {
    console.error("[Update Expense Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to update expense", "UPDATE_EXPENSE_ERROR"),
        { status: 500 }
      )
    )
  }
}
