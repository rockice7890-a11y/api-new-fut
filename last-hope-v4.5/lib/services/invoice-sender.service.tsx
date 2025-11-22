import { prisma } from "@/lib/prisma"
import type { Invoice } from "@prisma/client"
import nodemailer from "nodemailer"

// إعداد خدمة البريد
const createEmailTransporter = async (hotelId: string) => {
  // يمكن تحديث هذا ليستخدم بيانات اعتبارات البريد من قاعدة البيانات أو متغيرات البيئة
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD,
    },
  })

  return transporter
}

export const invoiceSenderService = {
  // إرسال فاتورة فردية
  async sendInvoiceEmail(invoiceId: string) {
    try {
      const invoice = await prisma.invoice.findUnique({
        where: { id: invoiceId },
        include: {
          booking: {
            include: { user: true, hotel: true },
          },
          user: true,
          hotel: true,
        },
      })

      if (!invoice || !invoice.booking) {
        throw new Error("الفاتورة أو الحجز غير موجود")
      }

      const hotelEmail = invoice.hotel?.email || process.env.HOTEL_EMAIL
      const userEmail = invoice.user?.email

      if (!userEmail) {
        throw new Error("بريد العميل غير موجود")
      }

      // إنشاء محتوى البريد
      const emailContent = this.generateInvoiceEmailContent(invoice)

      // إرسال البريد
      const transporter = await createEmailTransporter(invoice.hotelId)

      await transporter.sendMail({
        from: hotelEmail,
        to: userEmail,
        subject: `فاتورة #${invoice.invoiceNumber}`,
        html: emailContent,
      })

      // تحديث حالة الفاتورة
      await prisma.invoice.update({
        where: { id: invoiceId },
        data: { status: "ISSUED" },
      })

      console.log("[v0] تم إرسال الفاتورة بنجاح:", invoiceId)
      return true
    } catch (error) {
      console.error("[v0] خطأ في إرسال الفاتورة:", error)
      throw error
    }
  },

  // إرسال فواتير متعددة
  async sendBulkInvoices(hotelId: string, invoiceIds: string[]) {
    const results = []

    for (const invoiceId of invoiceIds) {
      try {
        await this.sendInvoiceEmail(invoiceId)
        results.push({ invoiceId, success: true })
      } catch (error) {
        results.push({ invoiceId, success: false, error: String(error) })
      }
    }

    return results
  },

  // إرسال فواتير غير المدفوعة تلقائياً
  async sendOverdueInvoiceReminders(hotelId: string) {
    try {
      const overdueInvoices = await prisma.invoice.findMany({
        where: {
          hotelId,
          status: "OVERDUE",
          paidDate: null,
        },
      })

      console.log("[v0] وجدنا", overdueInvoices.length, "فواتير متأخرة الدفع")

      return await this.sendBulkInvoices(
        hotelId,
        overdueInvoices.map((inv) => inv.id),
      )
    } catch (error) {
      console.error("[v0] خطأ في إرسال تذكيرات الفواتير:", error)
      throw error
    }
  },

  // توليد محتوى البريد
  generateInvoiceEmailContent(invoice: Invoice & { booking?: any; user?: any; hotel?: any }) {
    const invoiceDate = new Date(invoice.issueDate).toLocaleDateString("ar-EG")
    const dueDate = new Date(invoice.dueDate).toLocaleDateString("ar-EG")

    return `
      <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;">
        <h1 style="text-align: center; color: #333;">فاتورة</h1>
        
        <div style="margin: 20px 0; border-bottom: 2px solid #ddd; padding-bottom: 10px;">
          <p><strong>رقم الفاتورة:</strong> ${invoice.invoiceNumber}</p>
          <p><strong>تاريخ الإصدار:</strong> ${invoiceDate}</p>
          <p><strong>تاريخ الاستحقاق:</strong> ${dueDate}</p>
        </div>

        <div style="margin: 20px 0;">
          <p><strong>بيانات العميل:</strong></p>
          <p>${invoice.user?.firstName} ${invoice.user?.lastName}</p>
          <p>${invoice.user?.email}</p>
          <p>${invoice.user?.phone}</p>
        </div>

        <div style="margin: 20px 0;">
          <p><strong>بيانات الفندق:</strong></p>
          <p>${invoice.hotel?.name}</p>
          <p>${invoice.hotel?.address}</p>
          <p>${invoice.hotel?.phone}</p>
        </div>

        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
          <tr style="background-color: #f5f5f5;">
            <th style="border: 1px solid #ddd; padding: 10px; text-align: right;">البند</th>
            <th style="border: 1px solid #ddd; padding: 10px; text-align: right;">المبلغ</th>
          </tr>
          <tr>
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">الإجمالي</td>
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">${invoice.subtotal}</td>
          </tr>
          <tr>
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">الضريبة</td>
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">${invoice.tax}</td>
          </tr>
          <tr>
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">الخصم</td>
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">-${invoice.discount}</td>
          </tr>
          <tr style="background-color: #333; color: white; font-size: 18px; font-weight: bold;">
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">الإجمالي النهائي</td>
            <td style="border: 1px solid #ddd; padding: 10px; text-align: right;">${invoice.totalAmount}</td>
          </tr>
        </table>

        <p style="margin-top: 20px; padding: 10px; background-color: #f9f9f9;">
          <strong>شروط الدفع:</strong> يرجى الدفع في موعد أقصاه ${dueDate}
        </p>
      </div>
    `
  },

  // الحصول على إحصائيات الفواتير
  async getInvoiceStats(hotelId: string) {
    const stats = await prisma.invoice.groupBy({
      by: ["status"],
      where: { hotelId },
      _count: true,
      _sum: { totalAmount: true },
    })

    return stats
  },
}
