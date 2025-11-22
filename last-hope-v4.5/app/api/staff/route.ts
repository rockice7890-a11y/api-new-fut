import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const staffSchema = z.object({
  userId: z.string(),
  hotelId: z.string(),
  department: z.string(),
  salary: z.number().min(0).optional(),
  hourlyRate: z.number().min(0).optional(),
  permissions: z.array(z.string()).optional(),
  isActive: z.boolean().optional(),
})

const updateStaffSchema = z.object({
  department: z.string().optional(),
  salary: z.number().min(0).optional(),
  hourlyRate: z.number().min(0).optional(),
  permissions: z.array(z.string()).optional(),
  isActive: z.boolean().optional(),
})

// Get hotel staff (Manager or Admin only)
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ['HOTEL_MANAGER', 'ADMIN'])
  if (!auth.isValid) return auth.response!

  try {
    const { searchParams } = new URL(req.url)
    const hotelId = searchParams.get('hotelId')
    const department = searchParams.get('department')
    const isActive = searchParams.get('isActive')
    const page = parseInt(searchParams.get('page') || '1')
    const pageSize = parseInt(searchParams.get('pageSize') || '20')

    const whereConditions: any = {
      role: { in: ['HOTEL_MANAGER', 'ADMIN'] }
    }

    // Filter by hotel if manager (not admin)
    let hotelIds: string[] = []
    if (auth.payload.role === 'HOTEL_MANAGER' && !hotelId) {
      const userHotels = await prisma.hotel.findMany({
        where: { managerId: auth.payload.userId },
        select: { id: true },
      })
      hotelIds = userHotels.map(h => h.id)
    } else if (hotelId) {
      hotelIds = [hotelId]
    }

    // Get staff members with employee permissions for the hotel
    const [staff, totalCount] = await Promise.all([
      prisma.user.findMany({
        where: whereConditions,
        include: {
          employeePermissions: {
            where: hotelIds.length > 0 ? {
              hotelId: { in: hotelIds }
            } : undefined,
            select: {
              id: true,
              department: true,
              permission: true,
              accessLevel: true,
              isActive: true,
              grantedAt: true,
              hotelId: true,
            },
          },
          payroll: {
            where: { 
              status: 'PENDING',
              ...(hotelIds.length > 0 ? { hotelId: { in: hotelIds } } : {})
            },
            select: {
              id: true,
              baseSalary: true,
              payPeriodStart: true,
              payPeriodEnd: true,
            },
          },
          hotels: {
            where: hotelIds.length > 0 ? {
              id: { in: hotelIds }
            } : undefined,
            select: {
              id: true,
              name: true,
              address: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
      prisma.user.count({ where: whereConditions }),
    ])

    return NextResponse.json(
      successResponse({
        staff,
        pagination: {
          page,
          pageSize,
          totalCount,
          totalPages: Math.ceil(totalCount / pageSize),
          hasNext: page * pageSize < totalCount,
          hasPrev: page > 1,
        },
      }),
      { status: 200 }
    )

  } catch (error) {
    console.error("Get staff error:", error)
    return NextResponse.json(
      failResponse(null, "Internal server error", "GET_STAFF_ERROR"),
      { status: 500 }
    )
  }
}

// Add staff member (Manager or Admin only)
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ['HOTEL_MANAGER', 'ADMIN'])
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = staffSchema.parse(body)

    // Verify user exists
    const user = await prisma.user.findUnique({ where: { id: validated.userId } })

    if (!user) {
      return NextResponse.json(
        failResponse(null, "User not found", "USER_NOT_FOUND"),
        { status: 404 }
      )
    }

    // Verify hotel access (for managers)
    if (auth.payload.role === 'HOTEL_MANAGER') {
      const hotel = await prisma.hotel.findFirst({
        where: {
          id: validated.hotelId,
          managerId: auth.payload.userId,
        },
      })

      if (!hotel) {
        return NextResponse.json(
          failResponse(null, "Hotel not found or access denied", "ACCESS_DENIED"),
          { status: 403 }
        )
      }
    }

    // Check if user already has employee permissions for this hotel
    const existingPermission = await prisma.employeePermission.findFirst({
      where: {
        employeeId: validated.userId,
        hotelId: validated.hotelId,
        isActive: true,
      },
    })

    if (existingPermission) {
      return NextResponse.json(
        failResponse(null, "User already has employee permissions at this hotel", "EMPLOYEE_EXISTS"),
        { status: 409 }
      )
    }

    // Create employee permission
    const employeePermission = await prisma.employeePermission.create({
      data: {
        employeeId: validated.userId,
        hotelId: validated.hotelId,
        department: validated.department as any,
        permission: 'STAFF_ACCESS',
        accessLevel: 'EDIT',
        scope: 'HOTEL',
        grantedBy: auth.payload.userId,
        isActive: validated.isActive ?? true,
      },
      include: {
        employee: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true,
            phone: true,
            avatar: true,
            role: true,
          },
        },
      },
    })

    // Update user role to HOTEL_MANAGER if not already elevated
    if (user.role === 'USER') {
      await prisma.user.update({
        where: { id: validated.userId },
        data: { role: 'HOTEL_MANAGER' },
      })
    }

    // Send notification to the new staff member
    await prisma.notification.create({
      data: {
        userId: validated.userId,
        type: 'SYSTEM_ALERT',
        title: 'Welcome to the Team!',
        message: `You have been added as staff member`,
        data: JSON.stringify({
          hotelId: validated.hotelId,
          department: validated.department,
        }),
      },
    })

    // Create payroll record if salary is provided
    if (validated.salary) {
      await prisma.payroll.create({
        data: {
          payrollNumber: `PAY-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`,
          hotelId: validated.hotelId,
          staffId: validated.userId,
          baseSalary: validated.salary,
          netSalary: validated.salary,
          payPeriodStart: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
          payPeriodEnd: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0),
        },
      })
    }

    return NextResponse.json(
      successResponse(employeePermission, "Staff member added successfully"),
      { status: 201 }
    )

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        failResponse(null, "Invalid staff data", "VALIDATION_ERROR"),
        { status: 400 }
      )
    }

    console.error("Create staff error:", error)
    return NextResponse.json(
      failResponse(null, "Internal server error", "CREATE_STAFF_ERROR"),
      { status: 500 }
    )
  }
}