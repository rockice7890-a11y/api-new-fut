import { prisma } from "@/lib/prisma"

export const organizationService = {
  // إنشاء منظمة جديدة
  async createOrganization(data: {
    name: string
    description?: string
    email?: string
    phone?: string
    address?: string
    city?: string
    country?: string
    logo?: string
    website?: string
    contactPerson?: string
    taxId?: string
    hotelId?: string
  }) {
    return prisma.organization.create({
      data,
    })
  },

  // تحديث المنظمة
  async updateOrganization(organizationId: string, data: any) {
    return prisma.organization.update({
      where: { id: organizationId },
      data,
    })
  },

  // حذف المنظمة
  async deleteOrganization(organizationId: string) {
    return prisma.organization.delete({
      where: { id: organizationId },
    })
  },

  // الحصول على جميع المنظمات
  async getAllOrganizations(hotelId?: string) {
    return prisma.organization.findMany({
      where: hotelId ? { hotelId } : {},
      include: {
        guestDetails: true,
      },
    })
  },

  // الحصول على منظمة محددة
  async getOrganizationById(organizationId: string) {
    return prisma.organization.findUnique({
      where: { id: organizationId },
      include: {
        guestDetails: true,
      },
    })
  },

  // تبديل حالة المنظمة
  async toggleOrganization(organizationId: string) {
    const org = await prisma.organization.findUnique({
      where: { id: organizationId },
    })

    return prisma.organization.update({
      where: { id: organizationId },
      data: {
        isActive: !org?.isActive,
      },
    })
  },

  // الحصول على عدد النزلاء التابعين للمنظمة
  async getOrganizationGuestCount(organizationId: string) {
    return prisma.guestDetails.count({
      where: { organizationId },
    })
  },
}
