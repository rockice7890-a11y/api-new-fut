import { prisma } from "@/lib/prisma"
import { z } from "zod"

export const guestDetailsSchema = z.object({
  fullName: z.string().min(2).max(100),
  nationalId: z.string().optional(),
  passportNumber: z.string().optional(),
  phoneNumber: z.string().regex(/^\+?[1-9]\d{1,14}$/),
  city: z.string().min(2),
  country: z.string().min(2),
  organizationId: z.string().optional(),
  specialRequests: z.string().max(500).optional(),
  emergencyContact: z.string().optional(),
  emergencyPhone: z.string().optional(),
})

export class GuestDetailsService {
  // Create or update guest details
  static async saveGuestDetails(bookingId: string, userId: string, data: z.infer<typeof guestDetailsSchema>) {
    const validData = guestDetailsSchema.parse(data)

    const booking = await prisma.booking.findUnique({ where: { id: bookingId } })
    if (!booking) throw new Error("Booking not found")

    const guestDetails = await prisma.guestDetails.upsert({
      where: { bookingId },
      update: validData,
      create: {
        bookingId,
        userId,
        checkInDate: booking.checkInDate,
        checkOutDate: booking.checkOutDate,
        guestCount: booking.guests,
        ...validData,
      },
    })

    return guestDetails
  }

  // Get guest details for a booking
  static async getGuestDetails(bookingId: string) {
    const guestDetails = await prisma.guestDetails.findUnique({
      where: { bookingId },
    })

    if (!guestDetails) throw new Error("Guest details not found")
    return guestDetails
  }

  // Verify guest details
  static async verifyGuestDetails(bookingId: string) {
    return await prisma.guestDetails.update({
      where: { bookingId },
      data: {
        verified: true,
        verifiedAt: new Date(),
      },
    })
  }

  // Get guest details for check-in
  static async getCheckInDetails(bookingId: string) {
    const details = await prisma.guestDetails.findUnique({
      where: { bookingId },
      include: {
        booking: {
          include: {
            hotel: { select: { id: true, name: true, checkInTime: true } },
            room: { select: { id: true, roomNumber: true, roomType: true } },
          },
        },
      },
    })

    if (!details) throw new Error("Guest details not found")
    return details
  }
}
