import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import { checkoutReminderService } from "@/lib/services/checkout-reminder.service"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const reminderSchema = z.object({
  bookingId: z.string(),
  hotelId: z.string(),
  reminderTime: z.string().datetime(),
  reminderText: z.string(),
})

export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized()
    }

    const data = reminderSchema.parse(await req.json())

    const reminder = await checkoutReminderService.createReminder(
      data.bookingId,
      user.userId,
      data.hotelId,
      new Date(data.reminderTime),
      data.reminderText,
    )

    return apiResponse.success(reminder, "Checkout reminder created")
  } catch (error) {
    return apiResponse.error("Failed to create reminder")
  }
}
