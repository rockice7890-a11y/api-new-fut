import { prisma } from "@/lib/prisma"

export const payrollService = {
  async createPayroll(hotelId: string, staffId: string, baseSalary: number, bonuses = 0, deductions = 0) {
    const payrollNumber = `PAYROLL-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`
    const netSalary = baseSalary + bonuses - deductions

    const payPeriodStart = new Date()
    payPeriodStart.setDate(1)

    const payPeriodEnd = new Date()
    payPeriodEnd.setMonth(payPeriodEnd.getMonth() + 1)
    payPeriodEnd.setDate(0)

    return prisma.payroll.create({
      data: {
        payrollNumber,
        hotelId,
        staffId,
        baseSalary,
        bonuses,
        deductions,
        netSalary,
        payPeriodStart,
        payPeriodEnd,
        status: "PENDING",
      },
    })
  },

  async processPayroll(payrollId: string) {
    return prisma.payroll.update({
      where: { id: payrollId },
      data: {
        status: "PROCESSED",
      },
    })
  },

  async markAsPaid(payrollId: string) {
    return prisma.payroll.update({
      where: { id: payrollId },
      data: {
        status: "PAID",
        paidDate: new Date(),
      },
    })
  },

  async getHotelPayroll(hotelId: string, skip = 0, take = 10) {
    return prisma.payroll.findMany({
      where: { hotelId },
      skip,
      take,
      include: { staff: true },
      orderBy: { createdAt: "desc" },
    })
  },

  async getStaffPayroll(staffId: string) {
    return prisma.payroll.findMany({
      where: { staffId },
      include: { hotel: true },
      orderBy: { payPeriodStart: "desc" },
    })
  },
}
