import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Schema for device registration
const registerDeviceSchema = z.object({
  deviceId: z.string().min(1).max(255),
  deviceType: z.string().min(1).max(50), // flutter, ios, android, web
  deviceToken: z.string().optional(),
  deviceName: z.string().optional(),
  deviceModel: z.string().optional(),
  appVersion: z.string().optional(),
  osVersion: z.string().optional(),
  notificationsEnabled: z.boolean().default(true),
  soundEnabled: z.boolean().default(true),
  vibrationEnabled: z.boolean().default(true),
})

// POST - Register new device
export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = registerDeviceSchema.parse(body)

    // Check if device already exists for this user
    const existingDevice = await prisma.userDevice.findFirst({
      where: {
        userId: auth.payload.userId,
        deviceId: validated.deviceId
      }
    })

    if (existingDevice) {
      // Update existing device
      const updatedDevice = await prisma.userDevice.update({
        where: { id: existingDevice.id },
        data: {
          deviceToken: validated.deviceToken,
          deviceName: validated.deviceName,
          deviceModel: validated.deviceModel,
          appVersion: validated.appVersion,
          osVersion: validated.osVersion,
          notificationsEnabled: validated.notificationsEnabled,
          soundEnabled: validated.soundEnabled,
          vibrationEnabled: validated.vibrationEnabled,
          lastSeenAt: new Date(),
          isActive: true
        }
      })

      return successResponse({
        message: "Device updated successfully",
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
    } else {
      // Create new device
      const newDevice = await prisma.userDevice.create({
        data: {
          userId: auth.payload.userId,
          deviceId: validated.deviceId,
          deviceType: validated.deviceType,
          deviceToken: validated.deviceToken,
          deviceName: validated.deviceName,
          deviceModel: validated.deviceModel,
          appVersion: validated.appVersion,
          osVersion: validated.osVersion,
          notificationsEnabled: validated.notificationsEnabled,
          soundEnabled: validated.soundEnabled,
          vibrationEnabled: validated.vibrationEnabled,
          isActive: true,
          lastSeenAt: new Date()
        }
      })

      return successResponse({
        message: "Device registered successfully",
        device: {
          id: newDevice.id,
          deviceId: newDevice.deviceId,
          deviceType: newDevice.deviceType,
          deviceName: newDevice.deviceName,
          deviceModel: newDevice.deviceModel,
          appVersion: newDevice.appVersion,
          osVersion: newDevice.osVersion,
          notificationsEnabled: newDevice.notificationsEnabled,
          soundEnabled: newDevice.soundEnabled,
          vibrationEnabled: newDevice.vibrationEnabled,
          lastSeenAt: newDevice.lastSeenAt,
          createdAt: newDevice.createdAt
        }
      })
    }

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid device data: " + JSON.stringify(error.errors), "VALIDATION_ERROR"),
        { status: 400 }
      )
    }
    console.error("Register device error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to register device", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}

// GET - Get user's devices
export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { searchParams } = new URL(req.url)
    const includeInactive = searchParams.get("includeInactive") === "true"

    // Build where clause
    const where: any = {
      userId: auth.payload.userId
    }

    if (!includeInactive) {
      where.isActive = true
    }

    // Get user devices
    const devices = await prisma.userDevice.findMany({
      where,
      orderBy: [
        { isActive: 'desc' },
        { lastSeenAt: 'desc' }
      ]
    })

    // Get statistics
    const stats = {
      total: devices.length,
      active: devices.filter(d => d.isActive).length,
      byType: devices.reduce((acc, device) => {
        acc[device.deviceType] = (acc[device.deviceType] || 0) + 1
        return acc
      }, {} as Record<string, number>),
      withTokens: devices.filter(d => d.deviceToken).length,
      notificationsEnabled: devices.filter(d => d.notificationsEnabled).length
    }

    return successResponse({
      devices: devices.map(d => ({
        id: d.id,
        deviceId: d.deviceId,
        deviceType: d.deviceType,
        deviceName: d.deviceName,
        deviceModel: d.deviceModel,
        deviceToken: d.deviceToken ? "***" + d.deviceToken.slice(-4) : null, // Partial masking
        appVersion: d.appVersion,
        osVersion: d.osVersion,
        notificationsEnabled: d.notificationsEnabled,
        soundEnabled: d.soundEnabled,
        vibrationEnabled: d.vibrationEnabled,
        lastSeenAt: d.lastSeenAt,
        isActive: d.isActive,
        createdAt: d.createdAt
      })),
      statistics: stats
    })

  } catch (error) {
    console.error("Get user devices error:", error)
    return NextResponse.json(
        failResponse(null, "Failed to get user devices", "INTERNAL_ERROR"),
        { status: 500 }
      )
  }
}

// DELETE endpoint to remove a device
export async function DELETE(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const { searchParams } = new URL(req.url)
    const deviceId = searchParams.get("deviceId")

    if (!deviceId) {
      return NextResponse.json(
        failResponse(null, "Device ID is required", "ERROR"),
        { status: 400 }
      )
    }

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
      where: {
        id: device.id
      },
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