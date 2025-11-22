import { prisma } from "@/lib/prisma"
import { FinancialTransaction, TransactionCategory, TransactionStatus, PaymentMethod } from "@prisma/client"

export interface CreateTransactionData {
  hotelId: string
  category: TransactionCategory
  type: 'INCOME' | 'EXPENSE'
  amount: number
  currency?: string
  bookingId?: string
  invoiceId?: string
  paymentId?: string
  paymentMethod: PaymentMethod
  description: string
  notes?: string
  taxAmount?: number
  taxRate?: number
  receiptUrl?: string
  attachments?: string[]
  createdBy: string
}

export interface TransactionFilters {
  hotelId?: string
  category?: TransactionCategory
  type?: 'INCOME' | 'EXPENSE'
  status?: TransactionStatus
  paymentMethod?: PaymentMethod
  startDate?: Date
  endDate?: Date
  fiscalYear?: number
  fiscalPeriod?: string
  search?: string
  page?: number
  pageSize?: number
}

export interface TransactionSummary {
  totalIncome: number
  totalExpense: number
  netAmount: number
  transactionCount: number
  categoryBreakdown: Array<{
    category: TransactionCategory
    amount: number
    count: number
  }>
  monthlyTrend: Array<{
    month: string
    income: number
    expense: number
    net: number
  }>
}

export class EnhancedAccountingService {
  
  /**
   * Create a new financial transaction with validation and audit trail
   */
  static async createTransaction(data: CreateTransactionData): Promise<FinancialTransaction> {
    try {
      // Validate hotel access
      const hotel = await prisma.hotel.findUnique({
        where: { id: data.hotelId }
      })
      
      if (!hotel) {
        throw new Error('Hotel not found')
      }

      // Generate unique transaction number
      const transactionNumber = `TXN-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`
      
      // Calculate fiscal period
      const transactionDate = new Date()
      const fiscalYear = transactionDate.getFullYear()
      const fiscalPeriod = `${transactionDate.getFullYear()}-${String(transactionDate.getMonth() + 1).padStart(2, '0')}`

      // Determine initial status
      let status: TransactionStatus = data.type === 'INCOME' ? 'COMPLETED' : 'PENDING'

      // Create transaction
      const transaction = await prisma.financialTransaction.create({
        data: {
          ...data,
          transactionNumber,
          transactionDate,
          fiscalYear,
          fiscalPeriod,
          status,
          currency: data.currency || 'USD',
          taxAmount: data.taxAmount || 0,
          taxRate: data.taxRate || 0
        },
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
      await prisma.auditLog.create({
        data: {
          userId: data.createdBy,
          action: 'CREATE',
          resource: 'FINANCIAL_TRANSACTION',
          resourceId: transaction.id,
          endpoint: '/api/accounting/transactions',
          method: 'POST',
          ipAddress: 'system',
          newValues: JSON.stringify({
            transactionNumber: transaction.transactionNumber,
            amount: transaction.amount,
            category: transaction.category,
            type: transaction.type
          }),
          success: true
        }
      })

      // Update revenue/expense streams if applicable
      await this.updateRevenueStreams(transaction.hotelId, transaction.category, transaction.amount, fiscalYear, fiscalPeriod)

      return transaction
    } catch (error) {
      console.error('Error creating transaction:', error)
      throw error
    }
  }

  /**
   * Get transactions with advanced filtering and pagination
   */
  static async getTransactions(filters: TransactionFilters = {}): Promise<{
    transactions: FinancialTransaction[]
    total: number
    summary: TransactionSummary
  }> {
    try {
      const {
        hotelId,
        category,
        type,
        status,
        paymentMethod,
        startDate,
        endDate,
        fiscalYear,
        fiscalPeriod,
        search,
        page = 1,
        pageSize = 20
      } = filters

      // Build where clause
      const where: any = {}
      
      if (hotelId) where.hotelId = hotelId
      if (category) where.category = category
      if (type) where.type = type
      if (status) where.status = status
      if (paymentMethod) where.paymentMethod = paymentMethod
      if (fiscalYear) where.fiscalYear = fiscalYear
      if (fiscalPeriod) where.fiscalPeriod = fiscalPeriod

      // Date filtering
      if (startDate || endDate) {
        where.transactionDate = {}
        if (startDate) where.transactionDate.gte = startDate
        if (endDate) where.transactionDate.lte = endDate
      }

      // Search in description
      if (search) {
        where.description = {
          contains: search,
          mode: 'insensitive'
        }
      }

      // Get transactions
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
                guestName: true
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
      const summary = await this.calculateTransactionSummary(where)

      return {
        transactions,
        total,
        summary
      }
    } catch (error) {
      console.error('Error getting transactions:', error)
      throw error
    }
  }

  /**
   * Calculate comprehensive transaction summary
   */
  static async calculateTransactionSummary(where: any): Promise<TransactionSummary> {
    try {
      // Get total amounts by type
      const typeSummary = await prisma.financialTransaction.groupBy({
        by: ['type'],
        where,
        _sum: { amount: true },
        _count: true
      })

      const totalIncome = typeSummary.find(t => t.type === 'INCOME')?._sum.amount || 0
      const totalExpense = typeSummary.find(t => t.type === 'EXPENSE')?._sum.amount || 0
      const transactionCount = typeSummary.reduce((sum, t) => sum + t._count, 0)

      // Get category breakdown
      const categoryBreakdown = await prisma.financialTransaction.groupBy({
        by: ['category'],
        where,
        _sum: { amount: true },
        _count: true
      })

      const categoryStats = categoryBreakdown.map(cb => ({
        category: cb.category,
        amount: cb._sum.amount || 0,
        count: cb._count
      }))

      // Get monthly trend (last 12 months)
      const twelveMonthsAgo = new Date()
      twelveMonthsAgo.setMonth(twelveMonthsAgo.getMonth() - 12)

      const monthlyData = await prisma.financialTransaction.findMany({
        where: {
          ...where,
          transactionDate: { gte: twelveMonthsAgo }
        },
        select: {
          amount: true,
          type: true,
          transactionDate: true
        },
        orderBy: { transactionDate: 'asc' }
      })

      // Group by month
      const monthlyMap = new Map<string, { income: number, expense: number }>()
      
      monthlyData.forEach(transaction => {
        const month = transaction.transactionDate.toISOString().slice(0, 7) // YYYY-MM
        const current = monthlyMap.get(month) || { income: 0, expense: 0 }
        
        if (transaction.type === 'INCOME') {
          current.income += transaction.amount
        } else {
          current.expense += transaction.amount
        }
        
        monthlyMap.set(month, current)
      })

      const monthlyTrend = Array.from(monthlyMap.entries()).map(([month, data]) => ({
        month,
        income: data.income,
        expense: data.expense,
        net: data.income - data.expense
      }))

      return {
        totalIncome,
        totalExpense,
        netAmount: totalIncome - totalExpense,
        transactionCount,
        categoryBreakdown: categoryStats,
        monthlyTrend
      }
    } catch (error) {
      console.error('Error calculating transaction summary:', error)
      throw error
    }
  }

  /**
   * Update revenue/expense streams
   */
  static async updateRevenueStreams(
    hotelId: string,
    category: TransactionCategory,
    amount: number,
    fiscalYear: number,
    fiscalPeriod: string
  ): Promise<void> {
    try {
      const existing = await prisma.revenueStream.findUnique({
        where: {
          hotelId_category_fiscalYear_fiscalPeriod: {
            hotelId,
            category,
            fiscalYear,
            fiscalPeriod
          }
        }
      })

      if (existing) {
        // Update existing stream
        await prisma.revenueStream.update({
          where: { id: existing.id },
          data: {
            actualRevenue: existing.actualRevenue + amount,
            varianceAmount: (existing.actualRevenue + amount) - existing.targetRevenue,
            variancePercent: ((existing.actualRevenue + amount) - existing.targetRevenue) / existing.targetRevenue * 100
          }
        })
      } else {
        // Create new stream
        await prisma.revenueStream.create({
          data: {
            hotelId,
            name: this.getCategoryName(category),
            category,
            actualRevenue: amount,
            targetRevenue: 0,
            plannedRevenue: 0,
            varianceAmount: amount,
            variancePercent: 0,
            fiscalYear,
            fiscalPeriod
          }
        })
      }
    } catch (error) {
      console.error('Error updating revenue streams:', error)
    }
  }

  /**
   * Get category display name
   */
  private static getCategoryName(category: TransactionCategory): string {
    const categoryNames: Record<TransactionCategory, string> = {
      REVENUE_ROOM: 'إيرادات الغرف',
      REVENUE_FNB: 'إيرادات الطعام والمشروبات',
      REVENUE_SPA: 'إيرادات السبا',
      REVENUE_EVENTS: 'إيرادات الفعاليات',
      REVENUE_OTHER: 'إيرادات أخرى',
      EXPENSE_STAFF: 'نفقات الموظفين',
      EXPENSE_UTILITIES: 'نفقات المرافق',
      EXPENSE_SUPPLIES: 'نفقات المؤن',
      EXPENSE_MAINTENANCE: 'نفقات الصيانة',
      EXPENSE_MARKETING: 'نفقات التسويق',
      EXPENSE_INSURANCE: 'نفقات التأمين',
      EXPENSE_OTHER: 'نفقات أخرى'
    }
    
    return categoryNames[category] || category
  }

  /**
   * Generate financial report
   */
  static async generateFinancialReport(
    hotelId: string,
    startDate: Date,
    endDate: Date,
    reportType: 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'QUARTERLY' | 'YEARLY'
  ): Promise<any> {
    try {
      // Get all transactions in the period
      const transactions = await prisma.financialTransaction.findMany({
        where: {
          hotelId,
          transactionDate: {
            gte: startDate,
            lte: endDate
          }
        },
        include: {
          booking: {
            select: {
              id: true,
              checkInDate: true,
              checkOutDate: true
            }
          }
        }
      })

      // Calculate revenue by category
      const revenueByCategory = new Map<TransactionCategory, number>()
      const expenseByCategory = new Map<TransactionCategory, number>()
      
      let totalRevenue = 0
      let totalExpense = 0

      transactions.forEach(transaction => {
        if (transaction.type === 'INCOME') {
          totalRevenue += transaction.amount
          revenueByCategory.set(
            transaction.category,
            (revenueByCategory.get(transaction.category) || 0) + transaction.amount
          )
        } else {
          totalExpense += transaction.amount
          expenseByCategory.set(
            transaction.category,
            (expenseByCategory.get(transaction.category) || 0) + transaction.amount
          )
        }
      })

      // Get booking metrics for the period
      const bookings = await prisma.booking.findMany({
        where: {
          hotelId,
          createdAt: {
            gte: startDate,
            lte: endDate
          }
        },
        include: {
          room: true
        }
      })

      const occupiedNights = bookings.reduce((total, booking) => {
        const nights = Math.ceil(
          (booking.checkOutDate.getTime() - booking.checkInDate.getTime()) / (1000 * 60 * 60 * 24)
        )
        return total + nights
      }, 0)

      const totalBookings = bookings.length
      const totalGuests = bookings.reduce((sum, booking) => sum + booking.guests, 0)

      // Generate report
      const report = {
        reportName: `${reportType} Financial Report`,
        reportType,
        startDate,
        endDate,
        period: `${startDate.toISOString().slice(0, 10)} to ${endDate.toISOString().slice(0, 10)}`,
        
        // Revenue Summary
        totalRevenue,
        revenueBreakdown: Object.fromEntries(revenueByCategory),
        
        // Expense Summary
        totalExpense,
        expenseBreakdown: Object.fromEntries(expenseByCategory),
        
        // Profit & Loss
        grossProfit: totalRevenue - totalExpense,
        profitMargin: totalRevenue > 0 ? ((totalRevenue - totalExpense) / totalRevenue) * 100 : 0,
        
        // Booking Metrics
        totalBookings,
        totalGuests,
        occupiedNights,
        
        // Performance Indicators
        avgBookingValue: totalBookings > 0 ? totalRevenue / totalBookings : 0,
        avgRevenuePerNight: occupiedNights > 0 ? totalRevenue / occupiedNights : 0,
        
        // Generated metadata
        generatedAt: new Date(),
        transactionCount: transactions.length
      }

      // Save report to database
      await prisma.financialReport.create({
        data: {
          hotelId,
          reportName: report.reportName,
          reportType,
          reportPeriod: this.getReportPeriod(reportType, startDate),
          startDate,
          endDate,
          totalRevenue,
          totalExpenses: totalExpense,
          grossProfit: totalRevenue - totalExpense,
          netProfit: totalRevenue - totalExpense,
          profitMargin: totalRevenue > 0 ? ((totalRevenue - totalExpense) / totalRevenue) * 100 : 0,
          generatedBy: 'SYSTEM',
          isFinal: true
        }
      })

      return report
    } catch (error) {
      console.error('Error generating financial report:', error)
      throw error
    }
  }

  /**
   * Get report period string
   */
  private static getReportPeriod(reportType: string, date: Date): string {
    const year = date.getFullYear()
    const month = date.getMonth() + 1
    
    switch (reportType) {
      case 'DAILY':
        return `${year}-${String(month).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
      case 'WEEKLY':
        const weekStart = new Date(date)
        weekStart.setDate(date.getDate() - date.getDay())
        return `${year}-W${Math.ceil(weekStart.getDate() / 7)}`
      case 'MONTHLY':
        return `${year}-${String(month).padStart(2, '0')}`
      case 'QUARTERLY':
        const quarter = Math.ceil(month / 3)
        return `${year}-Q${quarter}`
      case 'YEARLY':
        return `${year}`
      default:
        return `${year}-${String(month).padStart(2, '0')}`
    }
  }
}