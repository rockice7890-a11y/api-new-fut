import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ["ADMIN"])
  if (!auth.isValid) return auth.response!

  try {
    const search = req.nextUrl.searchParams.get("search")
    const role = req.nextUrl.searchParams.get("role")
    const page = Number.parseInt(req.nextUrl.searchParams.get("page") || "1")
    const pageSize = Number.parseInt(req.nextUrl.searchParams.get("pageSize") || "10")

    const where: any = {}
    if (search) {
      where.OR = [
        { email: { contains: search, mode: "insensitive" } },
        { firstName: { contains: search, mode: "insensitive" } },
        { lastName: { contains: search, mode: "insensitive" } },
      ]
    }
    if (role) where.role = role

    const users = await prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        createdAt: true,
      },
      skip: (page - 1) * pageSize,
      take: pageSize,
      orderBy: { createdAt: "desc" },
    })

    const total = await prisma.user.count({ where })

    return NextResponse.json(successResponse({ users, total, page, pageSize }, "Users retrieved"))
  } catch (error: any) {
    return NextResponse.json({ status: "error", message: error.message }, { status: 500 })
  }
}
