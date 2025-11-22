import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { updateProfileSchema, changePasswordSchema } from "@/lib/validation"
import bcrypt from "bcryptjs"

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const user = await prisma.user.findUnique({
      where: { id: auth.payload.userId },
      include: {
        preferences: true,
        loyaltyPoints: true,
        userProfile: true,
        blockInfo: true,
        _count: {
          select: {
            bookings: true,
            reviews: true,
            wishlist: true,
          },
        },
      },
    })

    if (!user) {
      return NextResponse.json(
        failResponse(null, "User not found", "USER_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Remove sensitive data
    const { password, ...userWithoutPassword } = user

    return NextResponse.json(
      successResponse(userWithoutPassword, "User profile retrieved successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get User Profile Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch user profile", "FETCH_USER_ERROR"), 
      { status: 500 }
    )
  }
}

export async function PUT(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = updateProfileSchema.parse(body)

    // Update user basic info
    const updateData: any = {}
    if (validated.firstName !== undefined) updateData.firstName = validated.firstName
    if (validated.lastName !== undefined) updateData.lastName = validated.lastName
    if (validated.phone !== undefined) updateData.phone = validated.phone
    if (validated.bio !== undefined) updateData.bio = validated.bio
    if (validated.avatar !== undefined) updateData.avatar = validated.avatar

    const updatedUser = await prisma.user.update({
      where: { id: auth.payload.userId },
      data: updateData,
      include: {
        preferences: true,
        loyaltyPoints: true,
        userProfile: true,
        _count: {
          select: {
            bookings: true,
            reviews: true,
            wishlist: true,
          },
        },
      },
    })

    // Remove sensitive data
    const { password, ...userWithoutPassword } = updatedUser

    return NextResponse.json(
      successResponse(userWithoutPassword, "Profile updated successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Update User Profile Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to update profile", "UPDATE_PROFILE_ERROR"), 
      { status: 500 }
    )
  }
}

export async function PATCH(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const { action, ...data } = body

    switch (action) {
      case 'change_password':
        const passwordData = changePasswordSchema.parse(data)
        
        // Verify current password
        const user = await prisma.user.findUnique({
          where: { id: auth.payload.userId },
          select: { password: true },
        })

        if (!user) {
          return NextResponse.json(
            failResponse(null, "User not found", "USER_NOT_FOUND"),
            { status: 404 }
          )
        }

        const isCurrentPasswordValid = await bcrypt.compare(passwordData.currentPassword, user.password)
        if (!isCurrentPasswordValid) {
          return NextResponse.json(
            failResponse(null, "Current password is incorrect", "INVALID_CURRENT_PASSWORD"),
            { status: 400 }
          )
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(passwordData.newPassword, 12)

        // Update password
        await prisma.user.update({
          where: { id: auth.payload.userId },
          data: { password: hashedNewPassword },
        })

        return NextResponse.json(
          successResponse(null, "Password changed successfully"),
          { status: 200 }
        )

      case 'update_preferences':
        const { emailNotifications, smsNotifications, marketingEmails, preferredCurrency, language } = data

        // Update or create user preferences
        const preferences = await prisma.userPreference.upsert({
          where: { userId: auth.payload.userId },
          update: {
            emailNotifications: emailNotifications ?? undefined,
            smsNotifications: smsNotifications ?? undefined,
            marketingEmails: marketingEmails ?? undefined,
            preferredCurrency: preferredCurrency ?? undefined,
            language: language ?? undefined,
          },
          create: {
            userId: auth.payload.userId,
            emailNotifications: emailNotifications ?? true,
            smsNotifications: smsNotifications ?? false,
            marketingEmails: marketingEmails ?? true,
            preferredCurrency: preferredCurrency ?? 'USD',
            language: language ?? 'en',
          },
        })

        return NextResponse.json(
          successResponse(preferences, "Preferences updated successfully"),
          { status: 200 }
        )

      case 'update_profile':
        const { profileImage, coverImage, bio, company, jobTitle, location, website, socialLinks } = data

        // Update or create user profile
        const profile = await prisma.userProfile.upsert({
          where: { userId: auth.payload.userId },
          update: {
            profileImage: profileImage ?? undefined,
            coverImage: coverImage ?? undefined,
            bio: bio ?? undefined,
            company: company ?? undefined,
            jobTitle: jobTitle ?? undefined,
            location: location ?? undefined,
            website: website ?? undefined,
            socialLinks: socialLinks ? JSON.stringify(socialLinks) : undefined,
          },
          create: {
            userId: auth.payload.userId,
            profileImage: profileImage ?? null,
            coverImage: coverImage ?? null,
            bio: bio ?? null,
            company: company ?? null,
            jobTitle: jobTitle ?? null,
            location: location ?? null,
            website: website ?? null,
            socialLinks: socialLinks ? JSON.stringify(socialLinks) : null,
          },
        })

        return NextResponse.json(
          successResponse(profile, "Profile updated successfully"),
          { status: 200 }
        )

      default:
        return NextResponse.json(
          failResponse(null, "Invalid action", "INVALID_ACTION"),
          { status: 400 }
        )
    }
  } catch (error: any) {
    console.error("[User Action Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Action failed", "ACTION_ERROR"), 
      { status: 500 }
    )
  }
}

export async function DELETE(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    // Check for active bookings
    const activeBookings = await prisma.booking.count({
      where: {
        userId: auth.payload.userId,
        status: {
          in: ['PENDING', 'CONFIRMED', 'CHECKED_IN'],
        },
      },
    })

    if (activeBookings > 0) {
      return NextResponse.json(
        failResponse(null, "Cannot delete account with active bookings", "HAS_ACTIVE_BOOKINGS"),
        { status: 400 }
      )
    }

    // Soft delete - deactivate account instead of hard delete
    await prisma.user.update({
      where: { id: auth.payload.userId },
      data: {
        email: `deleted_${Date.now()}_${auth.payload.email}`,
        firstName: 'Deleted',
        lastName: 'User',
        password: '',
        phone: null,
        bio: null,
        avatar: null,
        role: 'USER',
      },
    })

    return NextResponse.json(
      successResponse(null, "Account deactivated successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Delete User Account Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to delete account", "DELETE_ACCOUNT_ERROR"), 
      { status: 500 }
    )
  }
}
