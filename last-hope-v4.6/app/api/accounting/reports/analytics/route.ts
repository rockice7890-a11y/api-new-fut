import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"

export const dynamic = 'force-dynamic'

// GET /api/accounting/reports/analytics - Get financial analytics
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const hotelId = searchParams.get('hotelId')
    const period = searchParams.get('period') || '12months' // 3months, 6months, 12months, 24months
    const metrics = searchParams.get('metrics')?.split(',') || ['revenue', 'expenses', 'profit']

    if (!hotelId) {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse(null, "Hotel ID is required", "MISSING_HOTEL_ID"),
          { status: 400 }
        )
      )
    }

    // Verify hotel access
    if (auth.payload.role === 'HOTEL_MANAGER') {
      const userHotels = await prisma.hotel.findMany({
        where: { 
          managerId: auth.payload.userId,
          id: hotelId
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

    // Calculate date range based on period
    const endDate = new Date()
    const startDate = new Date()
    
    switch (period) {
      case '3months':
        startDate.setMonth(endDate.getMonth() - 3)
        break
      case '6months':
        startDate.setMonth(endDate.getMonth() - 6)
        break
      case '12months':
        startDate.setFullYear(endDate.getFullYear() - 1)
        break
      case '24months':
        startDate.setFullYear(endDate.getFullYear() - 2)
        break
      default:
        startDate.setFullYear(endDate.getFullYear() - 1)
    }

    // Get transactions for the period
    const transactions = await prisma.financialTransaction.findMany({
      where: {
        hotelId,
        transactionDate: {
          gte: startDate,
          lte: endDate
        }
      },
      select: {
        amount: true,
        type: true,
        category: true,
        transactionDate: true
      },
      orderBy: { transactionDate: 'asc' }
    })

    // Group data by month
    const monthlyData = new Map<string, { income: number, expense: number, categories: any }>()
    
    transactions.forEach(transaction => {
      const month = transaction.transactionDate.toISOString().slice(0, 7) // YYYY-MM
      const current = monthlyData.get(month) || { 
        income: 0, 
        expense: 0, 
        categories: {} 
      }
      
      if (transaction.type === 'INCOME') {
        current.income += transaction.amount
      } else {
        current.expense += transaction.amount
      }
      
      // Track by category
      const categoryKey = transaction.category
      if (!current.categories[categoryKey]) {
        current.categories[categoryKey] = { income: 0, expense: 0 }
      }
      
      if (transaction.type === 'INCOME') {
        current.categories[categoryKey].income += transaction.amount
      } else {
        current.categories[categoryKey].expense += transaction.amount
      }
      
      monthlyData.set(month, current)
    })

    // Convert to array and calculate metrics
    const monthlyTrends = Array.from(monthlyData.entries())
      .map(([month, data]) => ({
        month,
        income: data.income,
        expense: data.expense,
        profit: data.income - data.expense,
        profitMargin: data.income > 0 ? ((data.income - data.expense) / data.income) * 100 : 0,
        categories: data.categories
      }))
      .sort((a, b) => a.month.localeCompare(b.month))

    // Calculate key performance indicators
    const totalIncome = monthlyTrends.reduce((sum, month) => sum + month.income, 0)
    const totalExpense = monthlyTrends.reduce((sum, month) => sum + month.expense, 0)
    const totalProfit = totalIncome - totalExpense
    const avgMonthlyIncome = totalIncome / monthlyTrends.length || 0
    const avgMonthlyExpense = totalExpense / monthlyTrends.length || 0
    const overallProfitMargin = totalIncome > 0 ? (totalProfit / totalIncome) * 100 : 0

    // Calculate growth rates
    if (monthlyTrends.length >= 2) {
      const recentMonths = monthlyTrends.slice(-3) // Last 3 months
      const previousMonths = monthlyTrends.slice(-6, -3) // Previous 3 months
      
      const recentAvgIncome = recentMonths.reduce((sum, month) => sum + month.income, 0) / recentMonths.length
      const previousAvgIncome = previousMonths.length > 0 ? 
        previousMonths.reduce((sum, month) => sum + month.income, 0) / previousMonths.length : recentAvgIncome
      
      const incomeGrowth = previousAvgIncome > 0 ? 
        ((recentAvgIncome - previousAvgIncome) / previousAvgIncome) * 100 : 0

      // Add growth rates to analytics
      monthlyTrends.forEach(month => {
        (month as any).incomeGrowth = incomeGrowth
      })
    }

    // Category performance
    const categoryPerformance = new Map<string, { total: number, percentage: number }>()
    const allCategories = new Set<string>()
    
    monthlyTrends.forEach(month => {
      Object.keys(month.categories).forEach(category => allCategories.add(category))
    })
    
    allCategories.forEach(category => {
      let totalAmount = 0
      monthlyTrends.forEach(month => {
        if (month.categories[category]) {
          totalAmount += month.categories[category].income + month.categories[category].expense
        }
      })
      categoryPerformance.set(category, {
        total: totalAmount,
        percentage: totalIncome > 0 ? (totalAmount / totalIncome) * 100 : 0
      })
    })

    const analytics = {
      period: {
        startDate,
        endDate,
        months: monthlyTrends.length
      },
      summary: {
        totalIncome,
        totalExpense,
        totalProfit,
        avgMonthlyIncome,
        avgMonthlyExpense,
        overallProfitMargin
      },
      trends: monthlyTrends,
      categoryPerformance: Object.fromEntries(categoryPerformance),
      keyMetrics: {
        bestMonth: monthlyTrends.reduce((best, month) => 
          month.income > best.income ? month : best, 
          monthlyTrends[0] || { month: 'N/A', income: 0 }
        ),
        worstMonth: monthlyTrends.reduce((worst, month) => 
          month.income < worst.income ? month : worst, 
          monthlyTrends[0] || { month: 'N/A', income: 0 }
        ),
        growthRate: (monthlyTrends[monthlyTrends.length - 1] as any)?.incomeGrowth || 0
      },
      generatedAt: new Date()
    }

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(analytics, "Financial analytics retrieved successfully")
      )
    )
  } catch (error: any) {
    console.error("[Get Financial Analytics Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch financial analytics", "FETCH_ANALYTICS_ERROR"),
        { status: 500 }
      )
    )
  }
}
