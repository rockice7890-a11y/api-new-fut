import { prisma } from "@/lib/prisma"

export const realtimeUpdateService = {
  // إنشاء تحديث فوري
  async createRealtimeUpdate(hotelId: string, eventType: string, resourceType: string, resourceId: string, data: any) {
    try {
      const update = await prisma.realtimeUpdate.create({
        data: {
          hotelId,
          eventType,
          resourceType,
          resourceId,
          data: JSON.stringify(data),
        },
      })

      // هنا يمكن إضافة WebSocket broadcast
      console.log("[v0] تم إنشاء تحديث فوري:", update.id)
      return update
    } catch (error) {
      console.error("[v0] خطأ في إنشاء التحديث الفوري:", error)
      throw error
    }
  },

  // الحصول على التحديثات الأخيرة
  async getRecentUpdates(hotelId: string, limit = 50) {
    return await prisma.realtimeUpdate.findMany({
      where: { hotelId },
      orderBy: { createdAt: "desc" },
      take: limit,
    })
  },

  // الحصول على التحديثات حسب نوع المورد
  async getUpdatesForResource(hotelId: string, resourceType: string, resourceId: string) {
    return await prisma.realtimeUpdate.findMany({
      where: {
        hotelId,
        resourceType,
        resourceId,
      },
      orderBy: { createdAt: "desc" },
    })
  },

  // تنظيف التحديثات القديمة (أكثر من 30 يوم)
  async cleanOldUpdates() {
    const thirtyDaysAgo = new Date()
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30)

    const deleted = await prisma.realtimeUpdate.deleteMany({
      where: {
        createdAt: { lt: thirtyDaysAgo },
      },
    })

    console.log("[v0] تم حذف التحديثات القديمة:", deleted.count)
    return deleted
  },
}
