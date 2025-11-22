import type { NextRequest } from "next/server"
import { verifyAuth } from "@/lib/auth"
import { prisma } from "@/lib/prisma"
import { apiResponse } from "@/lib/api-response"

export const dynamic = 'force-dynamic'

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const auth = await verifyAuth(request)
    if (!auth) return apiResponse.unauthorized()

    const { id } = await params

    await prisma.bookingService.delete({
      where: { id },
    })

    return apiResponse.success(null, "Service removed from booking successfully")
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error)
    return apiResponse.error(`Failed to remove service from booking: ${errorMessage}`)
  }
}
