import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

// Schema for registering user devices
const registerDeviceSchema = z.object({
  deviceId: z.string().min(1),
  deviceToken: z.string().optional(),
  deviceType: z.enum(["ios", "android", "web"]),
  deviceName: z.string().optional(),
  deviceModel: z.string().optional(),
  appVersion: z.string().optional(),
  osVersion: z.string().optional(),
  notificationsEnabled: z.boolean().default(true),
  soundEnabled: z.boolean().default(true),
  vibrationEnabled: z.boolean().default(true)
})

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = registerDeviceSchema.parse(body)

    // Check if device already exists
    const existingDevice = await prisma.userDevice.findUnique({
      where: {
        deviceId: validated.deviceId
      }
    })

    let device

    if (existingDevice) {
      // Update existing device
      device = await prisma.userDevice.update({
        where: {
          id: existingDevice.id
        },
        data: {
          userId: auth.payload.userId, // Ensure it belongs to current user
          deviceToken: validated.deviceToken,
          deviceType: validated.deviceType,
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
    } else {
      // Create new device
      device = await prisma.userDevice.create({
        data: {
          userId: auth.payload.userId,
          deviceId: validated.deviceId,
          deviceToken: validated.deviceToken,
          deviceType: validated.deviceType,
          deviceName: validated.deviceName,
          deviceModel: validated.deviceModel,
          appVersion: validated.appVersion,
          osVersion: validated.osVersion,
          notificationsEnabled: validated.notificationsEnabled,
          soundEnabled: validated.soundEnabled,
          vibrationEnabled: validated.vibrationEnabled
        }
      })
    }

    // Get user's device count
    const deviceCount = await prisma.userDevice.count({
      where: {
        userId: auth.payload.userId,
        isActive: true
      }
    })

    return successResponse({
      device: {
        id: device.id,
        deviceId: device.deviceId,
        deviceType: device.deviceType,
        deviceName: device.deviceName,
        deviceModel: device.deviceModel,
        notificationsEnabled: device.notificationsEnabled,
        soundEnabled: device.soundEnabled,
        vibrationEnabled: device.vibrationEnabled,
        lastSeenAt: device.lastSeenAt,
        isActive: device.isActive
      },
      userDeviceCount: deviceCount,
      message: "Device registered successfully"
    })

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