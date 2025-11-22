import { prisma } from "@/lib/prisma"
import type { RoomStatus } from "@prisma/client"

export const roomService = {
  async createRoom(
    hotelId: string,
    data: {
      roomType: string
      roomNumber?: string
      capacity: number
      beds: number
      basePrice: number
      description?: string
      amenities?: string[]
      images?: string[]
    },
  ) {
    return prisma.room.create({
      data: {
        hotelId,
        ...data,
        amenities: data.amenities || [],
        images: data.images || [],
      },
    })
  },

  // تحديث الغرفة
  async updateRoom(
    roomId: string,
    data: {
      roomType?: string
      roomNumber?: string
      capacity?: number
      beds?: number
      basePrice?: number
      status?: RoomStatus
      description?: string
      amenities?: string[]
      images?: string[]
    },
  ) {
    return prisma.room.update({
      where: { id: roomId },
      data,
    })
  },

  // حذف الغرفة
  async deleteRoom(roomId: string) {
    return prisma.room.delete({
      where: { id: roomId },
    })
  },

  // الحصول على جميع الغرف في الفندق
  async getHotelRooms(hotelId: string) {
    return prisma.room.findMany({
      where: { hotelId },
      include: {
        services: {
          include: { service: true },
        },
      },
    })
  },

  // الحصول على غرفة محددة
  async getRoomById(roomId: string) {
    return prisma.room.findUnique({
      where: { id: roomId },
      include: {
        services: {
          include: { service: true },
        },
        inventory: true,
      },
    })
  },

  // إضافة خدمة للغرفة
  async addServiceToRoom(roomId: string, serviceId: string) {
    return prisma.roomService.create({
      data: {
        roomId,
        serviceId,
      },
    })
  },

  // إزالة خدمة من الغرفة
  async removeServiceFromRoom(roomId: string, serviceId: string) {
    return prisma.roomService.deleteMany({
      where: {
        roomId,
        serviceId,
      },
    })
  },
}
