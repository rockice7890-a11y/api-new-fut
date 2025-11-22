import { prisma } from "@/lib/prisma"

export class DiscountService {
  static async validateDiscount(hotelId: string, code: string, bookingDetails: any) {
    const discount = await prisma.discount.findUnique({
      where: { hotelId_code: { hotelId, code } },
    })

    if (!discount) return { valid: false, error: "Discount code not found" }
    if (new Date() > discount.validUntil) return { valid: false, error: "Discount expired" }
    if (discount.usageLimit && discount.used >= discount.usageLimit) {
      return { valid: false, error: "Discount usage limit reached" }
    }

    if (discount.minStay && bookingDetails.nights < discount.minStay) {
      return { valid: false, error: `Minimum stay of ${discount.minStay} nights required` }
    }

    return { valid: true, discount }
  }

  static async calculateDiscount(discount: any, totalPrice: number) {
    if (discount.type === "PERCENTAGE") {
      return (totalPrice * discount.value) / 100
    } else if (discount.type === "FIXED_AMOUNT") {
      return discount.value
    }
    return 0
  }

  static async useDiscount(discountId: string) {
    return prisma.discount.update({
      where: { id: discountId },
      data: { used: { increment: 1 } },
    })
  }
}
