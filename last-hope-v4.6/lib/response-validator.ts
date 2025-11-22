/**
 * API Response Validation Middleware
 * Validates all API responses follow the standardized format
 */

import { NextRequest, NextResponse } from "next/server"
import { ApiResponse, validateResponseSchema } from "./api-response-improved"

export interface ResponseValidatorConfig {
  strictValidation: boolean
  allowCustomFields: boolean
  logValidationErrors: boolean
  responseSizeLimit: number // in bytes
}

const DEFAULT_CONFIG: ResponseValidatorConfig = {
  strictValidation: process.env.NODE_ENV === "production",
  allowCustomFields: true,
  logValidationErrors: true,
  responseSizeLimit: 1024 * 1024 * 10 // 10MB
}

export class ResponseValidator {
  private config: ResponseValidatorConfig

  constructor(config: Partial<ResponseValidatorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Validate API response format
   */
  validateResponse<T>(response: NextResponse, data: any): boolean {
    try {
      // Check response has required status
      if (!response.ok) {
        // For error responses, we still need basic validation
        const body = this.getResponseBody(response, data)
        if (!body || !body.status) {
          this.logValidationError("Missing status field in error response")
          return false
        }
        return true
      }

      // For success responses, validate full schema
      const body = this.getResponseBody(response, data)
      
      if (!body) {
        this.logValidationError("Response body is empty")
        return false
      }

      // Check required fields
      if (!this.validateRequiredFields(body)) {
        return false
      }

      // Check data type consistency
      if (!this.validateDataTypes(body)) {
        return false
      }

      // Validate response size
      if (!this.validateResponseSize(body)) {
        return false
      }

      return true

    } catch (error) {
      this.logValidationError(`Validation error: ${error}`)
      return false
    }
  }

  /**
   * Middleware for validating responses
   */
  middleware(handler: (req: NextRequest) => Promise<NextResponse>) {
    return async (req: NextRequest): Promise<NextResponse> => {
      try {
        const response = await handler(req)
        
        // Skip validation for non-API routes
        if (!req.nextUrl.pathname.startsWith('/api/')) {
          return response
        }

        // Get response data for validation
        const bodyText = await response.text()
        let responseData: any = null

        try {
          responseData = JSON.parse(bodyText)
        } catch {
          // If response is not JSON, it's not our API response format
          if (this.config.logValidationErrors) {
            console.warn(`[ResponseValidator] Non-JSON response at ${req.nextUrl.pathname}`)
          }
          return response
        }

        const isValid = this.validateResponse(response, responseData)
        
        if (!isValid && this.config.strictValidation) {
          // In production, replace with proper error response
          console.error(`[ResponseValidator] Invalid response format at ${req.nextUrl.pathname}`)
          
          return NextResponse.json({
            status: "error",
            message: "Response format validation failed",
            code: "SRV_004",
            meta: {
              timestamp: new Date().toISOString()
            }
          }, { status: 500 })
        }

        // Recreate response with validated data
        const newResponse = new NextResponse(bodyText, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers
        })

        return newResponse

      } catch (error) {
        console.error(`[ResponseValidator] Middleware error:`, error)
        return handler(req) // Fallback to original handler
      }
    }
  }

  /**
   * Validate response schema (for development/testing)
   */
  validateSchema<T>(response: ApiResponse<T>): boolean {
    const result = validateResponseSchema(response)
    
    if (!result && this.config.logValidationErrors) {
      console.error('[ResponseValidator] Schema validation failed:', response)
    }

    return result
  }

  private getResponseBody(response: NextResponse, data: any): any {
    // For testing/development purposes
    if (data) return data
    
    // Try to read body from headers (if available)
    try {
      return JSON.parse(response.headers.get('x-response-body') || '{}')
    } catch {
      return null
    }
  }

  private validateRequiredFields(body: any): boolean {
    const required = ['status']
    
    for (const field of required) {
      if (!(field in body)) {
        this.logValidationError(`Missing required field: ${field}`)
        return false
      }
    }

    // Validate status values
    const validStatuses = ['success', 'fail', 'error']
    if (!validStatuses.includes(body.status)) {
      this.logValidationError(`Invalid status value: ${body.status}`)
      return false
    }

    return true
  }

  private validateDataTypes(body: any): boolean {
    // Validate meta structure if present
    if (body.meta && typeof body.meta !== 'object') {
      this.logValidationError('Meta field must be an object')
      return false
    }

    // Validate pagination structure if present
    if (body.meta?.pagination) {
      const pagination = body.meta.pagination
      const requiredFields = ['page', 'limit', 'total', 'totalPages']
      
      for (const field of requiredFields) {
        if (!(field in pagination)) {
          this.logValidationError(`Missing pagination field: ${field}`)
          return false
        }
        
        if (typeof pagination[field] !== 'number') {
          this.logValidationError(`Pagination field ${field} must be a number`)
          return false
        }
      }
    }

    return true
  }

  private validateResponseSize(body: any): boolean {
    try {
      const bodyString = JSON.stringify(body)
      const sizeInBytes = new Blob([bodyString]).size

      if (sizeInBytes > this.config.responseSizeLimit) {
        this.logValidationError(`Response size ${sizeInBytes} exceeds limit ${this.config.responseSizeLimit}`)
        return false
      }

      return true
    } catch (error) {
      this.logValidationError(`Failed to check response size: ${error}`)
      return false
    }
  }

  private logValidationError(message: string): void {
    if (this.config.logValidationErrors) {
      console.error(`[ResponseValidator] ${message}`)
    }
  }
}

// Export singleton instance
export const responseValidator = new ResponseValidator()

// Utility functions for testing
export function createTestResponse<T>(data: T, status: 'success' | 'fail' | 'error' = 'success'): ApiResponse<T> {
  return {
    status,
    data: status === 'success' ? data : undefined,
    message: `${status} test response`,
    meta: {
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    }
  }
}

export function validateTestResponse<T>(response: ApiResponse<T>): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  
  // Check status field
  if (!response.status) {
    errors.push('Missing status field')
  } else if (!['success', 'fail', 'error'].includes(response.status)) {
    errors.push(`Invalid status value: ${response.status}`)
  }

  // Check meta structure
  if (!response.meta) {
    errors.push('Missing meta field')
  } else {
    if (!response.meta.timestamp) {
      errors.push('Missing timestamp in meta')
    }
    if (!response.meta.version) {
      errors.push('Missing version in meta')
    }
  }

  // Check data consistency
  if (response.status === 'success' && response.data === undefined) {
    errors.push('Success response must have data field')
  }

  return {
    valid: errors.length === 0,
    errors
  }
}