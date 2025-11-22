import { prisma } from "@/lib/prisma"

export const serviceService = {
  // إنشاء خدمة جديدة
  async createService(
    hotelId: string,
    data: {
      name: string
      description?: string
      price: number
      icon?: string
    },
  ) {
    return prisma.service.create({
      data: {
        hotelId,
        ...data,
      },
    })
  },

  // تحديث الخدمة
  async updateService(
    serviceId: string,
    data: {
      name?: string
      description?: string
      price?: number
      icon?: string
      isActive?: boolean
    },
  ) {
    return prisma.service.update({
      where: { id: serviceId },
      data,
    })
  },

  // حذف الخدمة
  async deleteService(serviceId: string) {
    return prisma.service.delete({
      where: { id: serviceId },
    })
  },

  // الحصول على جميع خدمات الفندق
  async getHotelServices(hotelId: string, onlyActive = true) {
    return prisma.service.findMany({
      where: {
        hotelId,
        ...(onlyActive && { isActive: true }),
      },
    })
  },

  // الحصول على خدمة محددة
  async getServiceById(serviceId: string) {
    return prisma.service.findUnique({
      where: { id: serviceId },
    })
  },

  // تعطيل/تفعيل الخدمة
  async toggleService(serviceId: string) {
    const service = await prisma.service.findUnique({
      where: { id: serviceId },
    })

    return prisma.service.update({
      where: { id: serviceId },
      data: {
        isActive: !service?.isActive,
      },
    })
  },
}
