# API Response System - دليل المطور

## 📋 نظرة عامة

تم تحسين نظام الاستجابات في API ليكون أكثر تنظيماً واتساقاً. هذا الدليل يوضح كيفية استخدام النظام الجديد.

## 🎯 المشاكل التي تم حلها

1. **عدم التوافق في الاستخدام** - استخدام mixed patterns
2. **تنسيق مشوه** - استجابات غير منظمة
3. **عدم توحيد error codes** - أكواد خطأ متباينة
4. **عدم وجود metadata** - معلومات إضافية مفقودة
5. **عدم وجود pagination support** - دعم الترقيم المفقود

## 🚀 الملفات الجديدة

### 1. `lib/api-response-improved.ts` (الأساسي)
- نظام استجابات محسن ومفصل
- Error codes منظمة
- دعم pagination
- Middleware للتسجيل

### 2. `lib/response-validator.ts`
- التحقق من صحة الاستجابات
- Validation middleware
- Testing utilities

### 3. `lib/api-response.ts` (محدث)
- نسخة محسّنة من النظام القديم
- backward compatibility
- Fixed formatting

## 📝 أمثلة الاستخدام

### ✅ الطريقة الصحيحة (الجديدة)

```typescript
import { apiResponse, ErrorCodes } from "@/lib/api-response-improved"

export async function POST(req: NextRequest) {
  try {
    // Logic here...
    
    const user = await prisma.user.findUnique({
      where: { id: userId }
    })

    if (!user) {
      return apiResponse.notFound("User not found", "BIZ_001")
    }

    return apiResponse.success(
      { user: sanitizedUser },
      "User retrieved successfully"
    )

  } catch (error) {
    return apiResponse.internalError("Operation failed", error)
  }
}
```

### ❌ الطريقة الخاطئة (القديم)

```typescript
export async function POST(req: NextRequest) {
  try {
    // Logic here...
    
    return NextResponse.json({
      status: "success",
      data: user,
      message: "Success"
    })

  } catch (error) {
    return NextResponse.json({
      status: "error", 
      message: "Failed"
    }, { status: 500 })
  }
}
```

## 🔢 Error Codes المنظمة

```typescript
// Authentication
ErrorCodes.UNAUTHORIZED = "AUTH_001"
ErrorCodes.INVALID_CREDENTIALS = "AUTH_002"
ErrorCodes.TOKEN_EXPIRED = "AUTH_003"

// Authorization  
ErrorCodes.FORBIDDEN = "AUTH_010"
ErrorCodes.INSUFFICIENT_PERMISSIONS = "AUTH_011"

// Validation
ErrorCodes.VALIDATION_ERROR = "VALID_001"
ErrorCodes.MISSING_REQUIRED_FIELD = "VALID_002"

// Business Logic
ErrorCodes.NOT_FOUND = "BIZ_001"
ErrorCodes.ALREADY_EXISTS = "BIZ_002"
ErrorCodes.NOT_AVAILABLE = "BIZ_003"

// Hotel System
ErrorCodes.HOTEL_NOT_FOUND = "HOTEL_001"
ErrorCodes.ROOM_NOT_AVAILABLE = "HOTEL_002"
ErrorCodes.BOOKING_NOT_FOUND = "HOTEL_003"
```

## 📊 Pagination Support

```typescript
// Response مع pagination
return apiResponse.successPaginated(
  data, 
  { page: 1, limit: 10, total: 100 },
  "Data retrieved successfully"
)

// Response format:
// {
//   status: "success",
//   data: { items: [...] },
//   message: "...",
//   meta: {
//     timestamp: "2025-11-22T15:38:11Z",
//     pagination: {
//       page: 1,
//       limit: 10,
//       total: 100,
//       totalPages: 10
//     }
//   }
// }
```

## 🛡️ Error Handling المتقدم

```typescript
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    
    // Validation with detailed errors
    const validated = createBookingSchema.parse(body)
    
    // Business logic
    
  } catch (error) {
    // Handle specific error types
    if (error.name === "ZodError") {
      return apiResponse.unprocessableEntity(
        "Invalid input data",
        { validationErrors: error.errors }
      )
    }
    
    if (error.code === "P2002") {
      return apiResponse.conflict(
        "Resource already exists",
        "BIZ_002"
      )
    }
    
    // Generic error
    return apiResponse.internalError(
      "Operation failed",
      error
    )
  }
}
```

## 🔧 Available Response Types

### Success Responses
```typescript
// Basic success
apiResponse.success(data, message)

// With metadata
apiResponse.success(data, message, { custom: "metadata" })

// Paginated success
apiResponse.successPaginated(data, pagination, message)
```

### Fail Responses (4xx)
```typescript
apiResponse.fail(data, message, code, status)
apiResponse.badRequest(message, data)
apiResponse.unauthorized(message)
apiResponse.forbidden(message)
apiResponse.notFound(message, code)
apiResponse.conflict(message, code)
apiResponse.unprocessableEntity(message, data)
```

### Error Responses (5xx)
```typescript
apiResponse.error(message, code, status)
apiResponse.tooManyRequests(message)
apiResponse.internalError(message, error)
apiResponse.serviceUnavailable(message)
```

## 📋 Response Structure

```typescript
{
  status: "success" | "fail" | "error",
  data?: any,
  message?: string,
  code?: string,
  meta: {
    timestamp: string,
    requestId?: string,
    pagination?: {
      page: number,
      limit: number, 
      total: number,
      totalPages: number
    },
    version?: string
  }
}
```

## 🧪 Testing

```typescript
import { responseValidator, createTestResponse, validateTestResponse } from "@/lib/response-validator"

// Validate response
const testResponse = createTestResponse({ test: "data" })
const validation = validateTestResponse(testResponse)

if (!validation.valid) {
  console.error("Validation errors:", validation.errors)
}
```

## 🔄 Migration من النظام القديم

### Step 1: تحديث Imports
```typescript
// القديم
import { successResponse, failResponse } from "@/lib/api-response"

// الجديد  
import { apiResponse, ErrorCodes } from "@/lib/api-response-improved"
```

### Step 2: تحديث Response Calls
```typescript
// القديم
return NextResponse.json(failResponse(null, "Not found", "NOT_FOUND"))

// الجديد
return apiResponse.notFound("User not found", "BIZ_001")
```

### Step 3: إضافة Error Codes
```typescript
// استخدم ErrorCodes enum بدلاً من strings
return apiResponse.badRequest("Invalid data", "VALID_001")
// بدلاً من
return apiResponse.badRequest("Invalid data", "random_string")
```

## 🎯 Best Practices

1. **استخدم Error Codes المنظمة** - تجنب إنشاء أكواد مخصصة
2. **أضف Request IDs** - للتتبع في logs
3. **استخدم Structured Logging** - Console logs منظمة
4. **Validate Request Data** - استقبل Zod schemas
5. **Handle Specific Errors** - Don't catch-all errors
6. **Add Response Headers** - Custom headers للمعلومات الإضافية

## 🚨 Common Mistakes to Avoid

1. **Mixed Response Patterns** - استخدم النظام الموحد
2. **Missing Error Handling** - Always use try-catch
3. **No Error Codes** - استخدم ErrorCodes enum
4. **Exposing Sensitive Data** - لا تعرض بيانات حساسة
5. **No Logging** - لا تنس Console logs

## 📈 Performance Tips

1. **Use ResponseValidator middleware** في Production
2. **Set Response Size Limits** - لتجنب large payloads
3. **Optimize Database Queries** - استعلامات محسّنة
4. **Use Caching** - للبيانات المتكررة
5. **Monitor Response Times** - مراقبة أوقات الاستجابة