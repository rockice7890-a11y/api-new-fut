import { prisma } from "@/lib/prisma"

export const invoiceService = {
  async createInvoice(bookingId: string, hotelId: string, userId: string, totalAmount: number) {
    const invoiceNumber = `INV-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`

    return prisma.invoice.create({
      data: {
        invoiceNumber,
        bookingId,
        hotelId,
        userId,
        subtotal: totalAmount * 0.9,
        tax: totalAmount * 0.1,
        totalAmount,
        status: "ISSUED",
        dueDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      },
    })
  },

  async getInvoice(invoiceId: string) {
    return prisma.invoice.findUnique({
      where: { id: invoiceId },
      include: { booking: true, hotel: true, user: true },
    })
  },

  async getInvoicesByUser(userId: string, skip = 0, take = 10) {
    return prisma.invoice.findMany({
      where: { userId },
      skip,
      take,
      orderBy: { createdAt: "desc" },
      include: { booking: true, hotel: true },
    })
  },

  async markAsPaid(invoiceId: string, paymentMethod: string) {
    return prisma.invoice.update({
      where: { id: invoiceId },
      data: {
        status: "PAID",
        paidDate: new Date(),
        paymentMethod,
      },
    })
  },

  async getOverdueInvoices() {
    return prisma.invoice.findMany({
      where: {
        AND: [{ status: "ISSUED" }, { dueDate: { lt: new Date() } }],
      },
      include: { user: true, hotel: true },
    })
  },
}
