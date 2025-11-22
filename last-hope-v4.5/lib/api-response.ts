// Standardized API response format (JSend) - Fixed Version
export type ApiResponse<T = any> = {
  status: "success" | "fail" | "error"
  data?: T
  message?: string
  code?: string
  meta?: {
    timestamp: string
    requestId?: string
    pagination?: {
      page: number
      limit: number
      total: number
      totalPages: number
    }
    version?: string
  }
}

// Legacy apiResponse object - now returns Response objects for Next.js compatibility
export const apiResponse = {
  success<T>(data: T, message?: string): Response {
    return Response.json(
      {
        status: "success",
        data,
        message,
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 200 }
    )
  },

  fail(data: any, message?: string, code?: string): Response {
    return Response.json(
      {
        status: "fail",
        data,
        message,
        code,
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 400 }
    )
  },

  error(messageOrError: string | Error, code?: string): Response {
    const message = messageOrError instanceof Error ? messageOrError.message : messageOrError
    return Response.json(
      {
        status: "error",
        message,
        code,
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 500 }
    )
  },

  unauthorized(message: string = "Unauthorized"): Response {
    return Response.json(
      {
        status: "error",
        message,
        code: "AUTH_001",
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 401 }
    )
  },

  forbidden(message: string = "Forbidden"): Response {
    return Response.json(
      {
        status: "error",
        message,
        code: "AUTH_010",
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 403 }
    )
  },

  badRequest(message: string = "Bad Request", data?: any): Response {
    return Response.json(
      {
        status: "fail",
        data,
        message,
        code: "VALID_001",
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 400 }
    )
  },

  notFound(message: string = "Not Found"): Response {
    return Response.json(
      {
        status: "error",
        message,
        code: "BIZ_001",
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 404 }
    )
  },

  tooManyRequests(message: string = "Too Many Requests"): Response {
    return Response.json(
      {
        status: "error",
        message,
        code: "RATE_001",
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status: 429 }
    )
  }
}

// Response creators for Next.js API routes (alias for backward compatibility)
export const apiResponseHandlers = apiResponse

// Keep the old interfaces for type definitions
export const successResponse = apiResponse.success
export const failResponse = apiResponse.fail
export const errorResponse = apiResponse.error