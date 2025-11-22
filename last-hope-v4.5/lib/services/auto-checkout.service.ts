import { prisma } from "@/lib/prisma"
import type { BookingStatus } from "@prisma/client"
import { NotificationService } from "@/lib/services/notification.service"

export const autoCheckoutService = {
  // جدولة مهام المغادرة التلقائية
  async scheduleAutoCheckouts() {
    try {
      const hotels = await prisma.hotelSettings.findMany({
        where: { autoCheckoutEnabled: true },
      })

      for (const hotelSettings of hotels) {
        const tomorrow = new Date()
        tomorrow.setDate(tomorrow.getDate() + 1)
        tomorrow.setHours(11, 0, 0, 0) // 11 AM

        const bookings = await prisma.booking.findMany({
          where: {
            hotelId: hotelSettings.hotelId,
            checkOutDate: {
              gte: new Date(tomorrow.getTime() - 24 * 60 * 60 * 1000),
              lt: tomorrow,
            },
            status: { in: ["CHECKED_IN", "CONFIRMED"] as BookingStatus[] },
          },
        })

        for (const booking of bookings) {
          const scheduledTime = new Date(booking.checkOutDate)
          scheduledTime.setHours(12, 0, 0, 0) // 12 PM (ساعة بعد الـ 11 AM)

          await prisma.autoCheckoutTask.create({
            data: {
              hotelId: hotelSettings.hotelId,
              bookingId: booking.id,
              roomId: booking.roomId,
              scheduledTime,
              reason: "CHECKOUT_TIME_EXCEEDED",
              status: "PENDING",
            },
          })

          // إنشاء مهمة معلقة للتأكيد من الموظف
          await prisma.pendingCheckout.create({
            data: {
              hotelId: hotelSettings.hotelId,
              bookingId: booking.id,
              roomId: booking.roomId,
              autoCheckoutAt: scheduledTime,
            },
          })
        }
      }

      console.log("[v0] تم جدولة مهام المغادرة التلقائية بنجاح")
    } catch (error) {
      console.error("[v0] خطأ في جدولة المغادرة التلقائية:", error)
    }
  },

  // معالجة المغادرة التلقائية
  async processAutoCheckout(taskId: string, staffId?: string) {
    try {
      const task = await prisma.autoCheckoutTask.findUnique({
        where: { id: taskId },
        include: { booking: true, hotel: true },
      })

      if (!task) {
        throw new Error("مهمة المغادرة غير موجودة")
      }

      // تحديث حالة الحجز
      const updatedBooking = await prisma.booking.update({
        where: { id: task.bookingId },
        data: { status: "CHECKED_OUT" as BookingStatus },
      })

      // تحديث حالة الغرفة
      await prisma.room.update({
        where: { id: task.roomId },
        data: { status: "AVAILABLE" },
      })

      // تحديث المهمة
      await prisma.autoCheckoutTask.update({
        where: { id: taskId },
        data: {
          status: "COMPLETED",
          processedAt: new Date(),
        },
      })

      // تأكيد المغادرة من الموظف
      if (staffId) {
        await prisma.pendingCheckout.updateMany({
          where: { bookingId: task.bookingId },
          data: {
            isConfirmed: true,
            staffConfirmedAt: new Date(),
            staffConfirmedBy: staffId,
          },
        })
      }

      // إنشاء إخطار للعميل
      await NotificationService.createNotification(
        task.booking.userId,
        "SYSTEM_ALERT",
        "تم تأكيد مغادرتك",
        "تم تأكيد خروجك من الفندق، نتمنى أن تكون قد استمتعت بإقامتك",
      )

      console.log("[v0] تمت معالجة المغادرة التلقائية بنجاح:", task.bookingId)
      return updatedBooking
    } catch (error) {
      console.error("[v0] خطأ في معالجة المغادرة التلقائية:", error)
      throw error
    }
  },

  // الحصول على المهام المعلقة
  async getPendingCheckouts(hotelId: string) {
    return await prisma.pendingCheckout.findMany({
      where: {
        hotelId,
        isConfirmed: false,
      },
      include: {
        booking: { include: { user: true } },
      },
      orderBy: { autoCheckoutAt: "asc" },
    })
  },

  // تأكيد المغادرة من الموظف
  async confirmCheckout(pendingCheckoutId: string, staffId: string, notes?: string) {
    return await prisma.pendingCheckout.update({
      where: { id: pendingCheckoutId },
      data: {
        isConfirmed: true,
        staffConfirmedAt: new Date(),
        staffConfirmedBy: staffId,
        confirmationNotes: notes,
      },
    })
  },

  // تفعيل/تعطيل المغادرة التلقائية
  async toggleAutoCheckout(hotelId: string, enabled: boolean) {
    return await prisma.hotelSettings.update({
      where: { hotelId },
      data: { autoCheckoutEnabled: enabled },
    })
  },
}
