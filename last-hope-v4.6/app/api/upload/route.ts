import { type NextRequest, NextResponse } from "next/server"
import { withAuth } from "@/lib/middleware"
import { successResponse, failResponse } from "@/lib/api-response"
import { writeFile, mkdir } from 'fs/promises'
import { join } from 'path'
import { randomUUID } from 'crypto'

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const formData = await req.formData()
    const file = formData.get('file') as File
    const type = formData.get('type') as string || 'general' // hotel, room, user, general
    const entityId = formData.get('entityId') as string // Optional: hotel ID, room ID, etc.

    if (!file) {
      return NextResponse.json(
        failResponse(null, "No file provided", "NO_FILE"),
        { status: 400 }
      )
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif']
    if (!allowedTypes.includes(file.type)) {
      return NextResponse.json(
        failResponse(null, "Invalid file type. Only images are allowed", "INVALID_FILE_TYPE"),
        { status: 400 }
      )
    }

    // Validate file size (5MB limit)
    const maxSize = 5 * 1024 * 1024 // 5MB
    if (file.size > maxSize) {
      return NextResponse.json(
        failResponse(null, "File size too large. Maximum 5MB allowed", "FILE_TOO_LARGE"),
        { status: 400 }
      )
    }

    // Create unique filename
    const fileExtension = file.name.split('.').pop()
    const fileName = `${randomUUID()}.${fileExtension}`
    
    // Create directory structure based on type
    const uploadDir = join(process.cwd(), 'public', 'uploads', type)
    await mkdir(uploadDir, { recursive: true })

    const filePath = join(uploadDir, fileName)
    const publicUrl = `/uploads/${type}/${fileName}`

    // Save file
    const bytes = await file.arrayBuffer()
    const buffer = Buffer.from(bytes)
    await writeFile(filePath, buffer)

    // Return upload result
    const uploadResult = {
      fileName,
      originalName: file.name,
      size: file.size,
      type: file.type,
      url: publicUrl,
      entityId,
      uploadedAt: new Date().toISOString(),
    }

    return NextResponse.json(
      successResponse(uploadResult, "File uploaded successfully"),
      { status: 201 }
    )

  } catch (error: any) {
    console.error("[File Upload Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to upload file", "UPLOAD_ERROR"), 
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  const auth = await withAuth(req)
  if (!auth.isValid) return auth.response!

  try {
    const searchParams = req.nextUrl.searchParams
    const type = searchParams.get("type")
    const entityId = searchParams.get("entityId")
    const page = Number.parseInt(searchParams.get("page") || "1")
    const pageSize = Number.parseInt(searchParams.get("pageSize") || "20")

    // This would typically come from a file metadata table
    // For now, we'll return a simple structure
    const files = {
      total: 0,
      files: [],
      page,
      pageSize,
    }

    return NextResponse.json(
      successResponse(files, "Files retrieved successfully"),
      { status: 200 }
    )
  } catch (error: any) {
    console.error("[Get Files Error]", error)
    return NextResponse.json(
      failResponse(null, error.message || "Failed to fetch files", "FETCH_FILES_ERROR"), 
      { status: 500 }
    )
  }
}
