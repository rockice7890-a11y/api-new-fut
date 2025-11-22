import { type NextRequest, NextResponse } from "next/server"
import { verifyToken } from "@/lib/auth"
import { apiResponse } from "@/lib/api-response"
import { invoiceService } from "@/lib/services/invoice.service"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const invoiceSchema = z.object({
  bookingId: z.string(),
  hotelId: z.string(),
  totalAmount: z.number().positive(),
})

export async function GET(req: NextRequest) {
  try {
    const token = req.headers.get("Authorization")?.split(" ")[1]
    const user = token ? verifyToken(token) : null

    if (!user) {
      return apiResponse.unauthorized()
    }

    const page = Number.parseInt(req.nextUrl.searchParams.get("page") || "1")
    const pageSize = Number.parseInt(req.nextUrl.searchParams.get("pageSize") || "10")
    const skip = (page - 1) * pageSize

    const invoices = await invoiceService.getInvoicesByUser(user.userId, skip, pageSize)

    return apiResponse.success({ invoices, page, pageSize }, "Invoices retrieved")
  } catch (error) {
    return apiResponse.error("Failed to retrieve invoices")
  }
}
