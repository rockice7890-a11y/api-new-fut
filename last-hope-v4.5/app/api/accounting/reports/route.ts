import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { rateLimit } from "@/lib/rate-limit"
import { EnhancedAccountingService } from "@/lib/services/enhanced-accounting.service"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Validation Schemas
const generateReportSchema = z.object({
  hotelId: z.string(),
  startDate: z.string().transform((str) => new Date(str)),
  endDate: z.string().transform((str) => new Date(str)),
  reportType: z.enum(['DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'YEARLY'])
})

const getReportsSchema = z.object({
  hotelId: z.string().optional(),
  reportType: z.enum(['DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'YEARLY']).optional(),
  startDate: z.string().transform((str) => new Date(str)).optional(),
  endDate: z.string().transform((str) => new Date(str)).optional(),
  page: z.number().positive().optional(),
  pageSize: z.number().positive().optional()
})

// GET /api/accounting/reports - Get financial reports
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    
    // Parse filters
    const hotelId = searchParams.get('hotelId')
    const reportType = searchParams.get('reportType')
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    const page = parseInt(searchParams.get('page') || '1')
    const pageSize = parseInt(searchParams.get('pageSize') || '20')

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
    if (reportType) where.reportType = reportType
    
    // Date range filtering
    if (startDate || endDate) {
      where.startDate = {}
      if (startDate) where.startDate.gte = new Date(startDate)
      if (endDate) where.startDate.lte = new Date(endDate)
      
      // Also check endDate field
      if (startDate || endDate) {
        where.OR = [
          {
            AND: [
              { startDate: { gte: startDate ? new Date(startDate) : undefined } },
              { startDate: { lte: endDate ? new Date(endDate) : undefined } }
            ]
          },
          {
            AND: [
              { endDate: { gte: startDate ? new Date(startDate) : undefined } },
              { endDate: { lte: endDate ? new Date(endDate) : undefined } }
            ]
          }
        ]
      }
    }

    const [reports, total] = await Promise.all([
      prisma.financialReport.findMany({
        where,
        include: {
          hotel: {
            select: { name: true, city: true }
          }
        },
        orderBy: { generatedAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.financialReport.count({ where })
    ])

    // Calculate summary statistics
    const summary = await prisma.financialReport.groupBy({
      by: ['reportType'],
      where: {
        ...where,
        // Remove pagination for summary
      },
      _count: true,
      _sum: {
        totalRevenue: true,
        totalExpenses: true,
        netProfit: true
      }
    })

    const totalRevenue = summary.reduce((sum, item) => sum + (item._sum.totalRevenue || 0), 0)
    const totalExpenses = summary.reduce((sum, item) => sum + (item._sum.totalExpenses || 0), 0)
    const totalProfit = summary.reduce((sum, item) => sum + (item._sum.netProfit || 0), 0)

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            reports,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            },
            summary: {
              totalRevenue,
              totalExpenses,
              totalProfit,
              reportCount: total
            }
          },
          "Financial reports retrieved successfully"
        )
      )
    )
  } catch (error: any) {
    console.error("[Get Financial Reports Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch financial reports", "FETCH_REPORTS_ERROR"),
        { status: 500 }
      )
    )
  }
}

// POST /api/accounting/reports - Generate new financial report
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    const rateLimitCheck = rateLimit(`generate_report:${clientIP}`, 20, 60 * 60 * 1000)
    if (!rateLimitCheck.success) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Too many report generation requests", "RATE_LIMIT_EXCEEDED"),
          { status: 429 }
        )
      )
    }

    const body = await req.json()
    const validated = generateReportSchema.parse(body)

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

    // Validate date range
    if (validated.startDate >= validated.endDate) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Start date must be before end date", "INVALID_DATE_RANGE"),
          { status: 400 }
        )
      )
    }

    // Check if report already exists for this period
    const existingReport = await prisma.financialReport.findFirst({
      where: {
        hotelId: validated.hotelId,
        reportType: validated.reportType,
        startDate: validated.startDate,
        endDate: validated.endDate
      }
    })

    if (existingReport) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Report already exists for this period", "REPORT_EXISTS"),
          { status: 409 }
        )
      )
    }

    // Generate report using service
    const report = await EnhancedAccountingService.generateFinancialReport(
      validated.hotelId,
      validated.startDate,
      validated.endDate,
      validated.reportType
    )

    // Create audit log
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'CREATE',
        resource: 'FINANCIAL_REPORT',
        resourceId: report.reportId || 'system_generated',
        endpoint: '/api/accounting/reports',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          hotelId: validated.hotelId,
          reportType: validated.reportType,
          period: report.period,
          totalRevenue: report.totalRevenue,
          totalExpense: report.totalExpense
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(report, "Financial report generated successfully"),
        { status: 201 }
      )
    )
  } catch (error: any) {
    console.error("[Generate Financial Report Error]", error)
    
    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse({ errors: error.errors }, "Invalid report data", "VALIDATION_ERROR"),
          { status: 400 }
        )
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to generate financial report", "GENERATE_REPORT_ERROR"),
        { status: 500 }
      )
    )
  }
}

// DELETE /api/accounting/reports - Delete financial report
export async function DELETE(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const reportId = searchParams.get('id')
    
    if (!reportId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Report ID is required", "MISSING_REPORT_ID"),
          { status: 400 }
        )
      )
    }

    // Verify report exists and user has access
    const existingReport = await prisma.financialReport.findUnique({
      where: { id: reportId },
      include: { hotel: true }
    })

    if (!existingReport) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Report not found", "REPORT_NOT_FOUND"),
          { status: 404 }
        )
      )
    }

    // Check permissions
    if (auth.payload.role === 'HOTEL_MANAGER' && existingReport.hotel.managerId !== auth.payload.userId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Access denied to this report", "ACCESS_DENIED"),
          { status: 403 }
        )
      )
    }

    // Prevent deletion of final reports
    if (existingReport.isFinal) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Cannot delete final reports", "INVALID_OPERATION"),
          { status: 400 }
        )
      )
    }

    await prisma.financialReport.delete({
      where: { id: reportId }
    })

    // Create audit log
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'DELETE',
        resource: 'FINANCIAL_REPORT',
        resourceId: reportId,
        endpoint: '/api/accounting/reports',
        method: 'DELETE',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        oldValues: JSON.stringify({
          reportName: existingReport.reportName,
          reportType: existingReport.reportType,
          period: existingReport.reportPeriod
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(null, "Financial report deleted successfully")
      )
    )
  } catch (error: any) {
    console.error("[Delete Financial Report Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to delete financial report", "DELETE_REPORT_ERROR"),
        { status: 500 }
      )
    )
  }
}