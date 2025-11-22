import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Schema for updating device token
const updateTokenSchema = z.object({
  deviceToken: z.string().min(1),
})

// PUT - Update device token
export async function PUT(req: NextRequest, { params }: { params: Promise<{ deviceId: string }> }) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = updateTokenSchema.parse(body)

    const { deviceId } = await params

    // Verify device belongs to user
    const device = await prisma.userDevice.findFirst({
      where: {
        deviceId: deviceId,
        userId: auth.payload.userId
      }
    })

    if (!device) {
      return NextResponse.json(
        failResponse(null, "Device not found", "ERROR"),
        { status: 404 }
      )
    }

    // Update device token
    const updatedDevice = await prisma.userDevice.update({
      where: { id: device.id },
      data: {
        deviceToken: validated.deviceToken,
        lastSeenAt: new Date(),
        isActive: true
      }
    })

    return successResponse({
      message: "Device token updated successfully",
      device: {
        id: updatedDevice.id,
        deviceId: updatedDevice.deviceId,
        deviceType: updatedDevice.deviceType,
        deviceName: updatedDevice.deviceName,
        deviceModel: updatedDevice.deviceModel,
        appVersion: updatedDevice.appVersion,
        osVersion: updatedDevice.osVersion,
        notificationsEnabled: updatedDevice.notificationsEnabled,
        soundEnabled: updatedDevice.soundEnabled,
        vibrationEnabled: updatedDevice.vibrationEnabled,
        lastSeenAt: updatedDevice.lastSeenAt,
        createdAt: updatedDevice.createdAt
      }
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid token data: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("Update device token error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to update device token", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}

// DELETE - Remove device
export async function DELETE(req: NextRequest, { params }: { params: Promise<{ deviceId: string }> }) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { deviceId } = await params

    // Verify device belongs to user
    const device = await prisma.userDevice.findFirst({
      where: {
        deviceId: deviceId,
        userId: auth.payload.userId
      }
    })

    if (!device) {
      return NextResponse.json(
        failResponse(null, "Device not found", "ERROR"),
        { status: 404 }
      )
    }

    // Soft delete (deactivate)
    await prisma.userDevice.update({
      where: { id: device.id },
      data: {
        isActive: false
      }
    })

    return successResponse({
      message: "Device removed successfully"
    })

  } catch (error) {
    console.error("Remove device error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to remove device", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}