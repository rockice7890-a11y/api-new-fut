import { prisma } from "@/lib/prisma"

export class LoyaltyService {
  static readonly POINTS_PER_DOLLAR = 1
  static readonly TIER_THRESHOLDS = {
    SILVER: 1000,
    GOLD: 5000,
    PLATINUM: 10000,
  }

  static async addPoints(userId: string, amount: number, reason: string) {
    const loyalty = await prisma.loyaltyPoint.findUnique({ where: { userId } })

    if (!loyalty) {
      return prisma.loyaltyPoint.create({
        data: {
          userId,
          points: amount,
          totalEarned: amount,
        },
      })
    }

    const newPoints = loyalty.points + amount
    const newTier = this.calculateTier(loyalty.totalEarned + amount)

    return prisma.loyaltyPoint.update({
      where: { userId },
      data: {
        points: newPoints,
        totalEarned: { increment: amount },
        tier: newTier,
      },
    })
  }

  static async redeemPoints(userId: string, amount: number) {
    const loyalty = await prisma.loyaltyPoint.findUnique({ where: { userId } })

    if (!loyalty || loyalty.points < amount) {
      throw new Error("Insufficient loyalty points")
    }

    return prisma.loyaltyPoint.update({
      where: { userId },
      data: {
        points: { decrement: amount },
        totalRedeemed: { increment: amount },
      },
    })
  }

  static calculateTier(totalEarned: number) {
    if (totalEarned >= this.TIER_THRESHOLDS.PLATINUM) return "PLATINUM"
    if (totalEarned >= this.TIER_THRESHOLDS.GOLD) return "GOLD"
    if (totalEarned >= this.TIER_THRESHOLDS.SILVER) return "SILVER"
    return "BRONZE"
  }
}
