import type { NextRequest } from "next/server"
import { invoiceSenderService } from "@/lib/services/invoice-sender.service"
import { authenticate } from "@/lib/middleware"
import { authorize } from "@/lib/middleware/permissions.middleware"
import { prisma } from "@/lib/prisma"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const user = await authenticate(request)
    if (!user) {
      return apiResponse.unauthorized("المستخدم غير مصرح")
    }

    const body = await request.json()
    const { invoiceId, hotelId } = body

    if (invoiceId) {
      // التحقق من أن المستخدم لديه صلاحية إرسال الفاتورة
      const invoice = await prisma.invoice.findUnique({
        where: { id: invoiceId },
        include: { hotel: true },
      })

      if (!invoice) {
        return apiResponse.notFound("الفاتورة غير موجودة")
      }

      if (invoice.hotel?.managerId !== user.id && user.role !== "ADMIN") {
        return apiResponse.forbidden("لا تملك صلاحية إرسال هذه الفاتورة")
      }

      // إرسال الفاتورة
      await invoiceSenderService.sendInvoiceEmail(invoiceId)

      return apiResponse.success(null, "تم إرسال الفاتورة بنجاح")
    } else if (hotelId) {
      await authorize(user.id, "ADMIN")

      // إرسال تذكيرات الفواتير المتأخرة
      const results = await invoiceSenderService.sendOverdueInvoiceReminders(hotelId)

      return apiResponse.success(results, "تم إرسال التذكيرات بنجاح")
    } else {
      return apiResponse.badRequest("معرف الفاتورة أو الفندق مطلوب")
    }
  } catch (error: any) {
    return apiResponse.error(error.message || "خطأ في إرسال الفاتورة أو التذكيرات")
  }
}
