import { prisma } from "@/lib/prisma"

export const checkoutReminderService = {
  async createReminder(bookingId: string, userId: string, hotelId: string, reminderTime: Date, reminderText: string) {
    return prisma.checkoutReminder.create({
      data: {
        bookingId,
        userId,
        hotelId,
        reminderTime,
        reminderText,
      },
    })
  },

  async getPendingReminders() {
    return prisma.checkoutReminder.findMany({
      where: {
        AND: [{ sent: false }, { reminderTime: { lte: new Date() } }],
      },
      include: { booking: true, user: true, hotel: true },
    })
  },

  async markAsSent(reminderId: string) {
    return prisma.checkoutReminder.update({
      where: { id: reminderId },
      data: {
        sent: true,
        sentAt: new Date(),
      },
    })
  },

  async getBookingReminders(bookingId: string) {
    return prisma.checkoutReminder.findMany({
      where: { bookingId },
      orderBy: { reminderTime: "asc" },
    })
  },
}
