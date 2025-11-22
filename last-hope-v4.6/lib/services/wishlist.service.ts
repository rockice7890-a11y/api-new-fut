import { prisma } from "@/lib/prisma"

export class WishlistService {
  static async addToWishlist(userId: string, hotelId: string) {
    return prisma.wishlist.create({
      data: { userId, hotelId },
    })
  }

  static async removeFromWishlist(userId: string, hotelId: string) {
    return prisma.wishlist.delete({
      where: { userId_hotelId: { userId, hotelId } },
    })
  }

  static async getUserWishlist(userId: string) {
    return prisma.wishlist.findMany({
      where: { userId },
      include: { hotel: true },
      orderBy: { createdAt: "desc" },
    })
  }

  static async isInWishlist(userId: string, hotelId: string) {
    const wish = await prisma.wishlist.findUnique({
      where: { userId_hotelId: { userId, hotelId } },
    })
    return !!wish
  }
}
