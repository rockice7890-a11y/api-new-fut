/**
 * Standardized API Response System (JSend Format)
 * Improved version with consistent formatting and error handling
 */

import { NextRequest, NextResponse } from "next/server"
import { addSecurityHeaders } from "./security"

// Core response type
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

// Error codes enum
export enum ErrorCodes {
  // Authentication
  UNAUTHORIZED = "AUTH_001",
  INVALID_CREDENTIALS = "AUTH_002",
  TOKEN_EXPIRED = "AUTH_003",
  TOKEN_INVALID = "AUTH_004",
  REFRESH_TOKEN_MISSING = "AUTH_005",
  
  // Authorization
  FORBIDDEN = "AUTH_010",
  INSUFFICIENT_PERMISSIONS = "AUTH_011",
  ROLE_INSUFFICIENT = "AUTH_012",
  
  // Validation
  VALIDATION_ERROR = "VALID_001",
  MISSING_REQUIRED_FIELD = "VALID_002",
  INVALID_FORMAT = "VALID_003",
  VALUE_OUT_OF_RANGE = "VALID_004",
  
  // Business Logic
  NOT_FOUND = "BIZ_001",
  ALREADY_EXISTS = "BIZ_002",
  NOT_AVAILABLE = "BIZ_003",
  CONFLICT = "BIZ_004",
  INVALID_STATUS = "BIZ_005",
  
  // Payment
  PAYMENT_FAILED = "PAY_001",
  INSUFFICIENT_FUNDS = "PAY_002",
  INVALID_PAYMENT_METHOD = "PAY_003",
  
  // Rate Limiting
  RATE_LIMIT_EXCEEDED = "RATE_001",
  TOO_MANY_REQUESTS = "RATE_002",
  
  // Server
  INTERNAL_ERROR = "SRV_001",
  SERVICE_UNAVAILABLE = "SRV_002",
  DATABASE_ERROR = "SRV_003",
  
  // Hotel System
  HOTEL_NOT_FOUND = "HOTEL_001",
  ROOM_NOT_AVAILABLE = "HOTEL_002",
  BOOKING_NOT_FOUND = "HOTEL_003",
  INVALID_DATES = "HOTEL_004"
}

// Base API Response Handler Class
class ApiResponseHandler {
  private addCommonHeaders(response: NextResponse): NextResponse {
    return addSecurityHeaders(response)
  }

  // Success Responses
  success<T>(data: T, message?: string, meta?: any): NextResponse {
    const response = NextResponse.json({
      status: "success",
      data,
      message: message || "Operation completed successfully",
      meta: {
        timestamp: new Date().toISOString(),
        version: process.env.APP_VERSION || "1.0.0",
        ...meta
      }
    })
    
    return this.addCommonHeaders(response)
  }

  // Success with Pagination
  successPaginated<T>(
    data: T,
    pagination: { page: number; limit: number; total: number },
    message?: string
  ): NextResponse {
    const totalPages = Math.ceil(pagination.total / pagination.limit)
    
    return this.success(data, message, {
      pagination: {
        ...pagination,
        totalPages
      }
    })
  }

  // Fail Responses (Client Errors 4xx)
  fail(data: any, message?: string, code?: ErrorCodes | string, status: number = 400): NextResponse {
    const response = NextResponse.json(
      {
        status: "fail",
        data,
        message: message || "Bad Request",
        code: code || ErrorCodes.VALIDATION_ERROR,
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status }
    )
    
    return this.addCommonHeaders(response)
  }

  // Error Responses (Server Errors 5xx)
  error(messageOrError: string | Error, code?: ErrorCodes | string, status: number = 500): NextResponse {
    const message = messageOrError instanceof Error ? messageOrError.message : messageOrError
    
    const response = NextResponse.json(
      {
        status: "error",
        message,
        code: code || ErrorCodes.INTERNAL_ERROR,
        meta: {
          timestamp: new Date().toISOString(),
          version: process.env.APP_VERSION || "1.0.0"
        }
      },
      { status }
    )
    
    return this.addCommonHeaders(response)
  }

  // Specialized Response Methods
  
  // 400 Bad Request
  badRequest(message: string = "Bad Request", data?: any): NextResponse {
    return this.fail(data, message, ErrorCodes.VALIDATION_ERROR, 400)
  }

  // 401 Unauthorized
  unauthorized(message: string = "Unauthorized"): NextResponse {
    return this.error(message, ErrorCodes.UNAUTHORIZED, 401)
  }

  // 403 Forbidden
  forbidden(message: string = "Forbidden"): NextResponse {
    return this.error(message, ErrorCodes.FORBIDDEN, 403)
  }

  // 404 Not Found
  notFound(message: string = "Resource not found", code?: string): NextResponse {
    return this.error(message, code || ErrorCodes.NOT_FOUND, 404)
  }

  // 409 Conflict
  conflict(message: string = "Conflict", code?: string): NextResponse {
    return this.fail(null, message, code || ErrorCodes.CONFLICT, 409)
  }

  // 422 Unprocessable Entity (Validation)
  unprocessableEntity(message: string = "Validation failed", data?: any): NextResponse {
    return this.fail(data, message, ErrorCodes.VALIDATION_ERROR, 422)
  }

  // 429 Too Many Requests
  tooManyRequests(message: string = "Rate limit exceeded"): NextResponse {
    return this.error(message, ErrorCodes.RATE_LIMIT_EXCEEDED, 429)
  }

  // 500 Internal Server Error
  internalError(message: string = "Internal server error", error?: Error): NextResponse {
    if (error) {
      console.error("[Internal Error]", error)
    }
    return this.error(message, ErrorCodes.INTERNAL_ERROR, 500)
  }

  // 503 Service Unavailable
  serviceUnavailable(message: string = "Service temporarily unavailable"): NextResponse {
    return this.error(message, ErrorCodes.SERVICE_UNAVAILABLE, 503)
  }

  // Redirect responses
  redirect(location: string, status: number = 302): NextResponse {
    return NextResponse.redirect(location, { status })
  }

  // File responses
  file(data: ArrayBuffer, filename?: string, mimeType?: string): NextResponse {
    const headers: HeadersInit = {}
    
    if (filename) {
      headers["Content-Disposition"] = `attachment; filename="${filename}"`
    }
    
    if (mimeType) {
      headers["Content-Type"] = mimeType
    }
    
    return new NextResponse(data, { headers: this.addCommonHeaders(new NextResponse(null)).headers })
  }

  // Stream responses
  stream(readable: ReadableStream): NextResponse {
    return new NextResponse(readable, {
      headers: this.addCommonHeaders(new NextResponse(null)).headers
    })
  }
}

// Export singleton instance
export const apiResponse = new ApiResponseHandler()

// Export individual methods for backward compatibility
export const successResponse = apiResponse.success.bind(apiResponse)
export const failResponse = apiResponse.fail.bind(apiResponse)
export const errorResponse = apiResponse.error.bind(apiResponse)

// Utility functions
export function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

export function validateResponseSchema<T>(response: ApiResponse<T>): boolean {
  const required = ["status", "meta"]
  return required.every(field => field in response)
}

// Middleware helper for request ID generation
export function addRequestId(request: NextRequest): NextRequest {
  const requestId = generateRequestId()
  request.headers.set('x-request-id', requestId)
  return request
}

// Response formatter for consistent logging
export function formatResponseForLogging(response: NextResponse): any {
  return {
    status: response.status,
    statusText: response.statusText,
    headers: Object.fromEntries(response.headers.entries())
  }
}