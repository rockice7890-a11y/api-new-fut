import { prisma } from "@/lib/prisma"
import { z } from "zod"

export const promotionImageSchema = z.object({
  imageUrl: z.string().url(),
  title: z.string().min(1).max(200),
  description: z.string().max(500).optional(),
  altText: z.string().optional(),
  displayOrder: z.number().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
})

export class PromotionService {
  // Add promotion image
  static async addPromotionImage(hotelId: string, data: z.infer<typeof promotionImageSchema>) {
    const validData = promotionImageSchema.parse(data)

    return await prisma.promotionImage.create({
      data: {
        hotelId,
        ...validData,
        startDate: validData.startDate ? new Date(validData.startDate) : undefined,
        endDate: validData.endDate ? new Date(validData.endDate) : undefined,
      },
    })
  }

  // Get promotion images
  static async getPromotionImages(hotelId: string, onlyActive = true) {
    const whereClause: any = { hotelId }
    if (onlyActive) {
      whereClause.isActive = true
      whereClause.startDate = { lte: new Date() }
      whereClause.OR = [{ endDate: { gte: new Date() } }, { endDate: null }]
    }

    return await prisma.promotionImage.findMany({
      where: whereClause,
      orderBy: { displayOrder: "asc" },
    })
  }

  // Update promotion image
  static async updatePromotionImage(imageId: string, data: Partial<z.infer<typeof promotionImageSchema>>) {
    return await prisma.promotionImage.update({
      where: { id: imageId },
      data: {
        ...data,
        startDate: data.startDate ? new Date(data.startDate) : undefined,
        endDate: data.endDate ? new Date(data.endDate) : undefined,
      },
    })
  }

  // Delete promotion image
  static async deletePromotionImage(imageId: string) {
    return await prisma.promotionImage.delete({
      where: { id: imageId },
    })
  }

  // Toggle promotion visibility
  static async togglePromotionVisibility(imageId: string, isActive: boolean) {
    return await prisma.promotionImage.update({
      where: { id: imageId },
      data: { isActive },
    })
  }
}
