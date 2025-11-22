import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { successResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const page = Number.parseInt(req.nextUrl.searchParams.get("page") || "1")
    const pageSize = Number.parseInt(req.nextUrl.searchParams.get("pageSize") || "10")

    const reviews = await prisma.review.findMany({
      where: { hotelId: id },
      include: {
        user: { select: { firstName: true, lastName: true } },
      },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    })

    const total = await prisma.review.count({ where: { hotelId: id } })

    return NextResponse.json(successResponse({ reviews, total, page, pageSize }, "Reviews retrieved"))
  } catch (error: any) {
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
