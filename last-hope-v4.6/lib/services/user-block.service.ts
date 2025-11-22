import { prisma } from "@/lib/prisma"
import type { BlockReasonType } from "@prisma/client"

export const userBlockService = {
  async blockUser(userId: string, reason: BlockReasonType, description: string, blockedBy: string) {
    return prisma.userBlock.upsert({
      where: { userId },
      update: {
        isBlocked: true,
        reason,
        description,
        blockedBy,
        blockedAt: new Date(),
        unblockAt: null,
      },
      create: {
        userId,
        reason,
        description,
        blockedBy,
        isBlocked: true,
      },
    })
  },

  async unblockUser(userId: string) {
    return prisma.userBlock.update({
      where: { userId },
      data: {
        isBlocked: false,
        unblockAt: new Date(),
      },
    })
  },

  async checkIfUserBlocked(userId: string) {
    const blockInfo = await prisma.userBlock.findUnique({
      where: { userId },
    })
    return blockInfo?.isBlocked || false
  },

  async getBlockedUser(userId: string) {
    return prisma.userBlock.findUnique({
      where: { userId },
    })
  },

  async getAllBlockedUsers(skip = 0, take = 10) {
    return prisma.userBlock.findMany({
      where: { isBlocked: true },
      skip,
      take,
      include: { user: true },
    })
  },
}
