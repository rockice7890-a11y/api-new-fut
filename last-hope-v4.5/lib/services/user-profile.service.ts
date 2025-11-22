import { prisma } from "@/lib/prisma"
import { z } from "zod"

export const updateUserProfileSchema = z.object({
  profileImage: z.string().url().optional(),
  coverImage: z.string().url().optional(),
  bio: z.string().max(500).optional(),
  company: z.string().optional(),
  jobTitle: z.string().optional(),
  location: z.string().optional(),
  website: z.string().url().optional(),
  socialLinks: z
    .object({
      twitter: z.string().optional(),
      facebook: z.string().optional(),
      instagram: z.string().optional(),
      linkedin: z.string().optional(),
    })
    .optional(),
})

export class UserProfileService {
  // Get user profile
  static async getUserProfile(userId: string) {
    const profile = await prisma.userProfile.findUnique({
      where: { userId },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            role: true,
            createdAt: true,
          },
        },
      },
    })

    if (!profile) {
      const user = await prisma.user.findUnique({ where: { id: userId } })
      if (!user) throw new Error("User not found")

      // Create default profile
      return await prisma.userProfile.create({
        data: { userId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
              phone: true,
              role: true,
              createdAt: true,
            },
          },
        },
      })
    }

    return profile
  }

  // Update user profile
  static async updateUserProfile(userId: string, data: z.infer<typeof updateUserProfileSchema>) {
    const validData = updateUserProfileSchema.parse(data)

    const profile = await prisma.userProfile.upsert({
      where: { userId },
      update: {
        ...validData,
        socialLinks: validData.socialLinks ? JSON.stringify(validData.socialLinks) : undefined,
      },
      create: {
        userId,
        ...validData,
        socialLinks: validData.socialLinks ? JSON.stringify(validData.socialLinks) : undefined,
      },
      include: { user: true },
    })

    return profile
  }

  // Update user avatar
  static async updateUserAvatar(userId: string, avatarUrl: string) {
    const user = await prisma.user.update({
      where: { id: userId },
      data: { avatar: avatarUrl },
    })

    await prisma.userProfile.upsert({
      where: { userId },
      update: { profileImage: avatarUrl },
      create: { userId, profileImage: avatarUrl },
    })

    return user
  }

  // Get hotel manager profile
  static async getManagerProfile(managerId: string) {
    let profile = await prisma.hotelManagerProfile.findFirst({
      where: { managerId },
    })

    if (!profile) {
      profile = await prisma.hotelManagerProfile.create({
        data: { managerId },
      })
    }

    return profile
  }

  // Update manager profile
  static async updateManagerProfile(managerId: string, data: any) {
    // First, try to find existing profile
    const existingProfile = await prisma.hotelManagerProfile.findFirst({
      where: { managerId }
    })

    if (existingProfile) {
      return await prisma.hotelManagerProfile.update({
        where: { id: existingProfile.id },
        data: data,
      })
    } else {
      return await prisma.hotelManagerProfile.create({
        data: { managerId, ...data },
      })
    }
  }
}
