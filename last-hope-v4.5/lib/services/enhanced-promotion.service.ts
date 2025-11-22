import { prisma } from "@/lib/prisma"
import { PromotionCampaign, PromotionType, PromotionTarget, PromotionStatus } from "@prisma/client"

export interface CreatePromotionData {
  hotelId?: string
  name: string
  description?: string
  type: PromotionType
  target: PromotionTarget
  targetCriteria?: any
  value: number
  maxDiscount?: number
  minBookingValue?: number
  maxBookingValue?: number
  validFrom: Date
  validUntil: Date
  maxUses?: number
  maxUsesPerUser?: number
  maxUsesPerDay?: number
  maxUsesPerWeek?: number
  canStackWithOther?: boolean
  stackablePromotions?: string[]
  eligibleCountries?: string[]
  minNights?: number
  maxNights?: number
  totalBudget?: number
  promoCode?: string
  affiliateCode?: string
  bannerImage?: string
  termsConditions?: string
  createdBy: string
}

export interface PromotionFilters {
  hotelId?: string
  type?: PromotionType
  status?: PromotionStatus
  target?: PromotionTarget
  activeOnly?: boolean
  startDate?: Date
  endDate?: Date
  search?: string
  page?: number
  pageSize?: number
}

export interface PromotionValidationResult {
  isValid: boolean
  promotion?: PromotionCampaign
  discountAmount: number
  discountType: string
  finalAmount: number
  savings: number
  errorMessage?: string
  errorCode?: string
}

export class EnhancedPromotionService {
  
  /**
   * Create a new promotion campaign
   */
  static async createPromotion(data: CreatePromotionData): Promise<PromotionCampaign> {
    try {
      // Validate hotel access if hotelId provided
      if (data.hotelId) {
        const hotel = await prisma.hotel.findUnique({
          where: { id: data.hotelId }
        })
        
        if (!hotel) {
          throw new Error('Hotel not found')
        }
      }

      // Validate promo code uniqueness if provided
      if (data.promoCode) {
        const existingPromotion = await prisma.promotionCampaign.findFirst({
          where: { promoCode: data.promoCode }
        })
        
        if (existingPromotion) {
          throw new Error('Promo code already exists')
        }
      }

      // Validate date range
      if (data.validFrom >= data.validUntil) {
        throw new Error('Valid from date must be before valid until date')
      }

      // Set initial status based on dates
      const now = new Date()
      let status: PromotionStatus = 'DRAFT'
      
      if (data.validFrom <= now && data.validUntil >= now) {
        status = 'ACTIVE'
      } else if (data.validFrom > now) {
        status = 'SCHEDULED'
      }

      // Calculate cost per use
      const costPerUse = data.totalBudget && data.maxUses ? 
        data.totalBudget / data.maxUses : 0

      const promotion = await prisma.promotionCampaign.create({
        data: {
          ...data,
          status,
          costPerUse,
          totalUsed: 0,
          todayUsed: 0,
          weekUsed: 0,
          spentBudget: 0
        },
        include: {
          hotel: {
            select: { name: true, city: true }
          }
        }
      })

      // Create audit log
      await prisma.auditLog.create({
        data: {
          userId: data.createdBy,
          action: 'CREATE',
          resource: 'PROMOTION_CAMPAIGN',
          resourceId: promotion.id,
          endpoint: '/api/promotion-campaigns',
          method: 'POST',
          ipAddress: 'system',
          newValues: JSON.stringify({
            name: promotion.name,
            type: promotion.type,
            value: promotion.value,
            status: promotion.status
          }),
          success: true
        }
      })

      return promotion
    } catch (error) {
      console.error('Error creating promotion:', error)
      throw error
    }
  }

  /**
   * Validate and calculate promotion discount
   */
  static async validatePromotion(
    promoCode: string,
    hotelId: string | undefined,
    bookingDetails: {
      totalAmount: number
      checkInDate?: Date
      checkOutDate?: Date
      nights?: number
      userId: string
      bookingValue: number
    }
  ): Promise<PromotionValidationResult> {
    try {
      // Find promotion by promo code
      const promotion = await prisma.promotionCampaign.findFirst({
        where: {
          promoCode,
          status: 'ACTIVE',
          validFrom: { lte: new Date() },
          validUntil: { gte: new Date() }
        },
        include: {
          hotel: {
            select: { id: true, name: true }
          }
        }
      })

      if (!promotion) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: 'Invalid or expired promo code',
          errorCode: 'INVALID_PROMO_CODE'
        }
      }

      // Check hotel-specific promotions
      if (hotelId && promotion.hotelId && promotion.hotelId !== hotelId) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: 'Promo code not valid for this hotel',
          errorCode: 'INVALID_HOTEL'
        }
      }

      // Check global usage limits
      if (promotion.maxUses && promotion.totalUsed >= promotion.maxUses) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: 'Promo code usage limit reached',
          errorCode: 'USAGE_LIMIT_REACHED'
        }
      }

      // Check budget limits
      if (promotion.totalBudget && promotion.spentBudget >= promotion.totalBudget) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: 'Promotion budget exhausted',
          errorCode: 'BUDGET_EXHAUSTED'
        }
      }

      // Check user-specific usage
      if (promotion.maxUsesPerUser) {
        const userUsage = await prisma.promotionUsage.count({
          where: {
            campaignId: promotion.id,
            userId: bookingDetails.userId
          }
        })
        
        if (userUsage >= promotion.maxUsesPerUser) {
          return {
            isValid: false,
            discountAmount: 0,
            discountType: '',
            finalAmount: bookingDetails.bookingValue,
            savings: 0,
            errorMessage: 'You have reached the maximum uses for this promo code',
            errorCode: 'USER_USAGE_LIMIT_REACHED'
          }
        }
      }

      // Check daily usage limit
      if (promotion.maxUsesPerDay) {
        const today = new Date()
        today.setHours(0, 0, 0, 0)
        const tomorrow = new Date(today)
        tomorrow.setDate(tomorrow.getDate() + 1)

        const dailyUsage = await prisma.promotionUsage.count({
          where: {
            campaignId: promotion.id,
            usedAt: {
              gte: today,
              lt: tomorrow
            }
          }
        })

        if (dailyUsage >= promotion.maxUsesPerDay) {
          return {
            isValid: false,
            discountAmount: 0,
            discountType: '',
            finalAmount: bookingDetails.bookingValue,
            savings: 0,
            errorMessage: 'Daily usage limit reached for this promo code',
            errorCode: 'DAILY_USAGE_LIMIT_REACHED'
          }
        }
      }

      // Check weekly usage limit
      if (promotion.maxUsesPerWeek) {
        const weekStart = new Date()
        weekStart.setDate(weekStart.getDate() - weekStart.getDay())
        weekStart.setHours(0, 0, 0, 0)
        const weekEnd = new Date(weekStart)
        weekEnd.setDate(weekEnd.getDate() + 7)

        const weeklyUsage = await prisma.promotionUsage.count({
          where: {
            campaignId: promotion.id,
            usedAt: {
              gte: weekStart,
              lt: weekEnd
            }
          }
        })

        if (weeklyUsage >= promotion.maxUsesPerWeek) {
          return {
            isValid: false,
            discountAmount: 0,
            discountType: '',
            finalAmount: bookingDetails.bookingValue,
            savings: 0,
            errorMessage: 'Weekly usage limit reached for this promo code',
            errorCode: 'WEEKLY_USAGE_LIMIT_REACHED'
          }
        }
      }

      // Check booking value limits
      if (promotion.minBookingValue && bookingDetails.bookingValue < promotion.minBookingValue) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: `Minimum booking value of ${promotion.minBookingValue} required`,
          errorCode: 'MIN_BOOKING_VALUE_NOT_MET'
        }
      }

      if (promotion.maxBookingValue && bookingDetails.bookingValue > promotion.maxBookingValue) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: `Maximum booking value of ${promotion.maxBookingValue} allowed`,
          errorCode: 'MAX_BOOKING_VALUE_EXCEEDED'
        }
      }

      // Check nights limits
      if (promotion.minNights && bookingDetails.nights && bookingDetails.nights < promotion.minNights) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: `Minimum stay of ${promotion.minNights} nights required`,
          errorCode: 'MIN_NIGHTS_NOT_MET'
        }
      }

      if (promotion.maxNights && bookingDetails.nights && bookingDetails.nights > promotion.maxNights) {
        return {
          isValid: false,
          discountAmount: 0,
          discountType: '',
          finalAmount: bookingDetails.bookingValue,
          savings: 0,
          errorMessage: `Maximum stay of ${promotion.maxNights} nights allowed`,
          errorCode: 'MAX_NIGHTS_EXCEEDED'
        }
      }

      // Check country restrictions
      if (promotion.eligibleCountries && promotion.eligibleCountries.length > 0) {
        const user = await prisma.user.findUnique({
          where: { id: bookingDetails.userId }
        })
        
        // This would need location data - for now we'll skip this check
        // In a real implementation, you'd check user's country
      }

      // Calculate discount amount
      let discountAmount = 0
      const discountType = promotion.type

      switch (promotion.type) {
        case 'PERCENTAGE_OFF':
          discountAmount = (bookingDetails.bookingValue * promotion.value) / 100
          if (promotion.maxDiscount && discountAmount > promotion.maxDiscount) {
            discountAmount = promotion.maxDiscount
          }
          break
        case 'FIXED_AMOUNT_OFF':
          discountAmount = Math.min(promotion.value, bookingDetails.bookingValue)
          break
        case 'DISCOUNT':
          discountAmount = Math.min(promotion.value, bookingDetails.bookingValue)
          break
        case 'FB_CREDIT':
        case 'SPA_CREDIT':
          discountAmount = promotion.value
          break
        case 'FREE_NIGHT':
          // For free nights, discount would be calculated based on average nightly rate
          discountAmount = promotion.value // This would need additional logic
          break
        case 'ROOM_UPGRADE':
          // Room upgrade value would need to be calculated
          discountAmount = promotion.value // This would need additional logic
          break
        default:
          discountAmount = 0
      }

      const finalAmount = Math.max(0, bookingDetails.bookingValue - discountAmount)

      return {
        isValid: true,
        promotion,
        discountAmount,
        discountType,
        finalAmount,
        savings: discountAmount
      }
    } catch (error) {
      console.error('Error validating promotion:', error)
      return {
        isValid: false,
        discountAmount: 0,
        discountType: '',
        finalAmount: bookingDetails.bookingValue,
        savings: 0,
        errorMessage: 'Failed to validate promotion',
        errorCode: 'VALIDATION_ERROR'
      }
    }
  }

  /**
   * Use a promotion and record the usage
   */
  static async usePromotion(
    campaignId: string,
    userId: string,
    bookingId: string | undefined,
    bookingDetails: {
      originalAmount: number
      discountAmount: number
      finalAmount: number
      deviceType?: string
      ipAddress?: string
      userAgent?: string
      referrer?: string
    }
  ): Promise<void> {
    try {
      const promotion = await prisma.promotionCampaign.findUnique({
        where: { id: campaignId }
      })

      if (!promotion) {
        throw new Error('Promotion not found')
      }

      // Create usage record
      await prisma.promotionUsage.create({
        data: {
          campaignId,
          userId,
          bookingId,
          usedAt: new Date(),
          promoCode: promotion.promoCode || undefined,
          originalAmount: bookingDetails.originalAmount,
          discountAmount: bookingDetails.discountAmount,
          finalAmount: bookingDetails.finalAmount,
          deviceType: bookingDetails.deviceType,
          ipAddress: bookingDetails.ipAddress,
          userAgent: bookingDetails.userAgent,
          referrer: bookingDetails.referrer,
          isValid: true
        }
      })

      // Update promotion counters
      const updates: any = {
        totalUsed: { increment: 1 },
        spentBudget: { increment: bookingDetails.discountAmount }
      }

      // Update daily counter
      const today = new Date()
      today.setHours(0, 0, 0, 0)
      
      if (promotion.lastUpdated?.toDateString() === today.toDateString()) {
        updates.todayUsed = { increment: 1 }
      } else {
        updates.todayUsed = 1
      }

      // Update weekly counter
      const weekStart = new Date(today)
      weekStart.setDate(today.getDate() - today.getDay())
      
      if (promotion.lastUpdated && promotion.lastUpdated.getTime() >= weekStart.getTime()) {
        updates.weekUsed = { increment: 1 }
      } else {
        updates.weekUsed = 1
      }

      await prisma.promotionCampaign.update({
        where: { id: campaignId },
        data: {
          ...updates,
          lastUpdated: new Date()
        }
      })

      // Create audit log
      await prisma.auditLog.create({
        data: {
          userId,
          action: 'USE',
          resource: 'PROMOTION_CAMPAIGN',
          resourceId: campaignId,
          endpoint: '/api/promotion-campaigns/use',
          method: 'POST',
          ipAddress: 'system',
          newValues: JSON.stringify({
            discountAmount: bookingDetails.discountAmount,
            finalAmount: bookingDetails.finalAmount
          }),
          success: true
        }
      })
    } catch (error) {
      console.error('Error using promotion:', error)
      throw error
    }
  }

  /**
   * Get promotions with advanced filtering
   */
  static async getPromotions(filters: PromotionFilters = {}): Promise<{
    promotions: PromotionCampaign[]
    total: number
  }> {
    try {
      const {
        hotelId,
        type,
        status,
        target,
        activeOnly,
        startDate,
        endDate,
        search,
        page = 1,
        pageSize = 20
      } = filters

      // Build where clause
      const where: any = {}
      
      if (hotelId) where.hotelId = hotelId
      if (type) where.type = type
      if (status) where.status = status
      if (target) where.target = target

      // Active campaigns only
      if (activeOnly) {
        const now = new Date()
        where.status = { in: ['ACTIVE', 'SCHEDULED'] }
        where.validFrom = { lte: now }
        where.validUntil = { gte: now }
      }

      // Date range filtering
      if (startDate || endDate) {
        where.OR = []
        if (startDate) {
          where.OR.push({
            AND: [
              { validFrom: { lte: startDate } },
              { validUntil: { gte: startDate } }
            ]
          })
        }
        if (endDate) {
          where.OR.push({
            AND: [
              { validFrom: { lte: endDate } },
              { validUntil: { gte: endDate } }
            ]
          })
        }
      }

      // Search in name, description, and promo code
      if (search) {
        where.OR = [
          ...(where.OR || []),
          { name: { contains: search, mode: 'insensitive' } },
          { description: { contains: search, mode: 'insensitive' } },
          { promoCode: { contains: search, mode: 'insensitive' } }
        ]
      }

      const [promotions, total] = await Promise.all([
        prisma.promotionCampaign.findMany({
          where,
          include: {
            hotel: {
              select: { name: true, city: true }
            },
            _count: {
              select: {
                promotionUsages: true
              }
            }
          },
          orderBy: [
            { status: 'asc' },
            { createdAt: 'desc' }
          ],
          skip: (page - 1) * pageSize,
          take: pageSize
        }),
        prisma.promotionCampaign.count({ where })
      ])

      return {
        promotions,
        total
      }
    } catch (error) {
      console.error('Error getting promotions:', error)
      throw error
    }
  }

  /**
   * Auto-expire promotions that have passed their valid until date
   */
  static async autoExpirePromotions(): Promise<void> {
    try {
      const now = new Date()
      
      await prisma.promotionCampaign.updateMany({
        where: {
          status: { in: ['ACTIVE', 'SCHEDULED'] },
          validUntil: { lt: now }
        },
        data: {
          status: 'EXPIRED'
        }
      })
    } catch (error) {
      console.error('Error auto-expiring promotions:', error)
    }
  }

  /**
   * Get promotion analytics
   */
  static async getPromotionAnalytics(campaignId: string): Promise<any> {
    try {
      const campaign = await prisma.promotionCampaign.findUnique({
        where: { id: campaignId },
        include: {
          promotionUsages: {
            orderBy: { usedAt: 'desc' }
          }
        }
      })

      if (!campaign) {
        throw new Error('Campaign not found')
      }

      // Calculate usage statistics
      const totalUsage = campaign.promotionUsages.length
      const uniqueUsers = new Set(campaign.promotionUsages.map(u => u.userId)).size
      
      // Calculate total discount given
      const totalDiscount = campaign.promotionUsages.reduce((sum, usage) => sum + usage.discountAmount, 0)
      
      // Calculate average discount per use
      const avgDiscount = totalUsage > 0 ? totalDiscount / totalUsage : 0
      
      // Calculate ROI
      const totalCost = campaign.spentBudget || 0
      const revenue = campaign.promotionUsages.reduce((sum, usage) => sum + usage.finalAmount, 0)
      const roi = totalCost > 0 ? ((revenue - totalCost) / totalCost) * 100 : 0

      // Calculate conversion rate (if we had view/click data)
      const conversionRate = campaign.viewCount > 0 ? (totalUsage / campaign.viewCount) * 100 : 0

      return {
        campaign: {
          id: campaign.id,
          name: campaign.name,
          type: campaign.type,
          status: campaign.status,
          createdAt: campaign.createdAt
        },
        usage: {
          totalUsage,
          uniqueUsers,
          totalDiscount,
          avgDiscount,
          conversionRate
        },
        financial: {
          totalCost,
          totalRevenue: revenue,
          netProfit: revenue - totalCost,
          roi,
          costPerUse: totalUsage > 0 ? totalCost / totalUsage : 0
        },
        performance: {
          totalSpent: campaign.spentBudget || 0,
          budgetUtilization: campaign.totalBudget ? (campaign.spentBudget / campaign.totalBudget) * 100 : 0,
          usageRate: campaign.maxUses ? (totalUsage / campaign.maxUses) * 100 : 0
        }
      }
    } catch (error) {
      console.error('Error getting promotion analytics:', error)
      throw error
    }
  }
}