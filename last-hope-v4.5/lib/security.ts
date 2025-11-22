import { type NextRequest, NextResponse } from "next/server"
import { generateCSRFToken, verifyCSRFToken, hashEmail } from "./crypto-utils"

export function sanitizeInput(input: string): string {
  return input
    .replace(/[<>]/g, "")
    .replace(/javascript:/gi, "")
    .substring(0, 1000)
}

export { generateCSRFToken, verifyCSRFToken, hashEmail }

export interface CORSOptions {
  origin: string[] | string
  methods: string[]
  allowedHeaders: string[]
  credentials: boolean
}

export function handleCORS(req: NextRequest, options: CORSOptions): NextResponse | null {
  const origin = req.headers.get("origin") || ""
  const allowedOrigins = Array.isArray(options.origin) ? options.origin : [options.origin]

  if (allowedOrigins.includes(origin) || allowedOrigins.includes("*")) {
    const response = new NextResponse(null, { status: 200 })
    response.headers.set("Access-Control-Allow-Origin", origin)
    response.headers.set("Access-Control-Allow-Methods", options.methods.join(", "))
    response.headers.set("Access-Control-Allow-Headers", options.allowedHeaders.join(", "))
    if (options.credentials) response.headers.set("Access-Control-Allow-Credentials", "true")
    return response
  }

  return null
}

export function addSecurityHeaders(response: NextResponse): NextResponse {
  response.headers.set("X-Content-Type-Options", "nosniff")
  response.headers.set("X-Frame-Options", "DENY")
  response.headers.set("X-XSS-Protection", "1; mode=block")
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
  response.headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
  response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
  return response
}
