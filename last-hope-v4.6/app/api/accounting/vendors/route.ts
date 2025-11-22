import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/prisma"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { addSecurityHeaders } from "@/lib/security"
import { z } from "zod"

export const dynamic = 'force-dynamic'

const createVendorSchema = z.object({
  name: z.string().min(1).max(200),
  companyName: z.string().max(200).optional(),
  taxId: z.string().max(100).optional(),
  registrationNumber: z.string().max(100).optional(),
  email: z.string().email().optional(),
  phone: z.string().max(50).optional(),
  website: z.string().url().optional(),
  address: z.string().max(500).optional(),
  city: z.string().max(100).optional(),
  country: z.string().max(100).optional(),
  paymentTerms: z.string().max(100).optional(),
  currency: z.string().default('USD'),
  creditLimit: z.number().min(0).default(0),
  bankAccount: z.string().max(500).optional(),
  iban: z.string().max(50).optional(),
  swiftCode: z.string().max(20).optional(),
  rating: z.number().min(0).max(5).optional(),
  reliabilityScore: z.number().min(0).max(100).optional()
})

// GET /api/accounting/vendors - Get vendors
export async function GET(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const page = parseInt(searchParams.get('page') || '1')
    const pageSize = parseInt(searchParams.get('pageSize') || '20')
    const search = searchParams.get('search')
    const isActive = searchParams.get('isActive')

    const where: any = {}
    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { companyName: { contains: search, mode: 'insensitive' } }
      ]
    }
    if (isActive !== null && isActive !== undefined) {
      where.isActive = isActive === 'true'
    }

    const [vendors, total] = await Promise.all([
      prisma.vendor.findMany({
        where,
        orderBy: { name: 'asc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      }),
      prisma.vendor.count({ where })
    ])

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(
          {
            vendors,
            pagination: {
              page,
              pageSize,
              total,
              totalPages: Math.ceil(total / pageSize)
            }
          },
          "Vendors retrieved successfully"
        )
      )
    )
  } catch (error: any) {
    console.error("[Get Vendors Error]", error)
    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to fetch vendors", "FETCH_VENDORS_ERROR"),
        { status: 500 }
      )
    )
  }
}

// POST /api/accounting/vendors - Create new vendor
export async function POST(req: NextRequest) {
  const auth = await withAuth(req, ['ADMIN', 'HOTEL_MANAGER', 'ACCOUNTANT'])
  if (!auth.isValid) return auth.response!

  try {
    const body = await req.json()
    const validated = createVendorSchema.parse(body)

    // Check for duplicate tax ID if provided
    if (validated.taxId) {
      const existingVendor = await prisma.vendor.findFirst({
        where: { taxId: validated.taxId }
      })
      
      if (existingVendor) {
        return addSecurityHeaders(
          NextResponse.json(
            failResponse(null, "Vendor with this tax ID already exists", "VENDOR_EXISTS"),
            { status: 409 }
          )
        )
      }
    }

    const vendor = await prisma.vendor.create({
      data: validated
    })

    // Create audit log
    const clientIP = req.headers.get("x-forwarded-for") || "unknown"
    await prisma.auditLog.create({
      data: {
        userId: auth.payload.userId,
        action: 'CREATE',
        resource: 'VENDOR',
        resourceId: vendor.id,
        endpoint: '/api/accounting/vendors',
        method: 'POST',
        ipAddress: clientIP,
        userAgent: req.headers.get('user-agent') || '',
        newValues: JSON.stringify({
          name: vendor.name,
          companyName: vendor.companyName,
          email: vendor.email
        }),
        success: true
      }
    })

    return addSecurityHeaders(
      NextResponse.json(
        successResponse(vendor, "Vendor created successfully"),
        { status: 201 }
      )
    )
  } catch (error: any) {
    console.error("[Create Vendor Error]", error)
    
    if (error.name === 'ZodError') {
      return addSecurityHeaders(
        NextResponse.json(
          failResponse({ errors: error.errors }, "Invalid vendor data", "VALIDATION_ERROR"),
          { status: 400 }
        )
      )
    }

    return addSecurityHeaders(
      NextResponse.json(
        failResponse(null, error.message || "Failed to create vendor", "CREATE_VENDOR_ERROR"),
        { status: 500 }
      )
    )
  }
}
