import { prisma } from "@/lib/prisma"
import type { StaffNotificationType } from "@prisma/client"

export const staffNotificationService = {
  async sendNotification(
    hotelId: string,
    senderId: string,
    recipientId: string,
    type: StaffNotificationType,
    subject: string,
    message: string,
    priority = "NORMAL",
  ) {
    return prisma.staffNotification.create({
      data: {
        hotelId,
        senderId,
        recipientId,
        type,
        subject,
        message,
        priority,
      },
    })
  },

  async getStaffNotifications(staffId: string, skip = 0, take = 10) {
    return prisma.staffNotification.findMany({
      where: { recipientId: staffId },
      skip,
      take,
      include: { sender: true, hotel: true },
      orderBy: { createdAt: "desc" },
    })
  },

  async getUnreadNotifications(staffId: string) {
    return prisma.staffNotification.findMany({
      where: { recipientId: staffId, isRead: false },
      include: { sender: true },
      orderBy: { priority: "desc" },
    })
  },

  async markAsRead(notificationId: string) {
    return prisma.staffNotification.update({
      where: { id: notificationId },
      data: {
        isRead: true,
        readAt: new Date(),
      },
    })
  },

  async broadcastNotification(
    hotelId: string,
    senderId: string,
    staffIds: string[],
    type: StaffNotificationType,
    subject: string,
    message: string,
  ) {
    return prisma.staffNotification.createMany({
      data: staffIds.map((staffId) => ({
        hotelId,
        senderId,
        recipientId: staffId,
        type,
        subject,
        message,
      })),
    })
  },
}
