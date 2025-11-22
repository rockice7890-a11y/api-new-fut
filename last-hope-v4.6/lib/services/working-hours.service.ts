import { prisma } from "@/lib/prisma"

export const workingHoursService = {
  async setWorkingHours(hotelId: string, weeklyHours: any, timezone = "UTC") {
    return prisma.hotelWorkingHours.upsert({
      where: { hotelId },
      update: {
        monday: weeklyHours.monday || "08:00-23:00",
        tuesday: weeklyHours.tuesday || "08:00-23:00",
        wednesday: weeklyHours.wednesday || "08:00-23:00",
        thursday: weeklyHours.thursday || "08:00-23:00",
        friday: weeklyHours.friday || "08:00-23:00",
        saturday: weeklyHours.saturday || "08:00-23:00",
        sunday: weeklyHours.sunday || "08:00-23:00",
        timezone,
      },
      create: {
        hotelId,
        monday: weeklyHours.monday || "08:00-23:00",
        tuesday: weeklyHours.tuesday || "08:00-23:00",
        wednesday: weeklyHours.wednesday || "08:00-23:00",
        thursday: weeklyHours.thursday || "08:00-23:00",
        friday: weeklyHours.friday || "08:00-23:00",
        saturday: weeklyHours.saturday || "08:00-23:00",
        sunday: weeklyHours.sunday || "08:00-23:00",
        timezone,
      },
    })
  },

  async getWorkingHours(hotelId: string) {
    return prisma.hotelWorkingHours.findUnique({
      where: { hotelId },
    })
  },

  async isHotelOpen(hotelId: string) {
    const workingHours = await this.getWorkingHours(hotelId)
    if (!workingHours) return true

    const now = new Date()
    const dayName = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][
      now.getDay()
    ].toLowerCase()

    // @ts-ignore
    const todayHours = workingHours[dayName] as string
    if (!todayHours) return true

    const [start, end] = todayHours.split("-")
    const [startHour, startMin] = start.split(":").map(Number)
    const [endHour, endMin] = end.split(":").map(Number)

    const currentTime = now.getHours() * 60 + now.getMinutes()
    const startTime = startHour * 60 + startMin
    const endTime = endHour * 60 + endMin

    return currentTime >= startTime && currentTime <= endTime
  },

  async addHoliday(hotelId: string, date: Date) {
    const workingHours = await this.getWorkingHours(hotelId)
    const holidays = workingHours?.holidays || []

    return prisma.hotelWorkingHours.update({
      where: { hotelId },
      data: {
        holidays: [...holidays, date.toISOString()],
      },
    })
  },
}
