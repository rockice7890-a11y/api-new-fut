import { z } from "zod"

const passwordSchema = z
  .string()
  .min(12, "Password must be at least 12 characters")
  .regex(/[A-Z]/, "Password must contain uppercase letter")
  .regex(/[a-z]/, "Password must contain lowercase letter")
  .regex(/[0-9]/, "Password must contain number")
  .regex(/[!@#$%^&*]/, "Password must contain special character (!@#$%^&*)")

export const registerSchema = z.object({
  email: z.string().email("Invalid email").max(255),
  password: passwordSchema,
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
})

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
})

export const createHotelSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  address: z.string().min(1),
  city: z.string().min(1),
  state: z.string().optional(),
  country: z.string().min(1),
  latitude: z.number().optional(),
  longitude: z.number().optional(),
  phone: z.string().optional(),
  email: z.string().email().optional(),
  amenities: z.array(z.string()).optional(),
  images: z.array(z.string()).optional(),
  policies: z.string().optional(),
  checkInTime: z.string().optional(),
  checkOutTime: z.string().optional(),
})

export const createBookingSchema = z.object({
  hotelId: z.string(),
  roomId: z.string(),
  checkInDate: z.string().datetime(),
  checkOutDate: z.string().datetime(),
  guests: z.number().min(1),
  guestName: z.string().min(1),
  guestEmail: z.string().email(),
  guestPhone: z.string().min(10),
  specialRequests: z.string().optional(),
})

export const updateBookingSchema = z.object({
  status: z.enum(['PENDING', 'CONFIRMED', 'CANCELLED', 'COMPLETED', 'CHECKED_IN', 'CHECKED_OUT']).optional(),
  specialRequests: z.string().optional(),
  guestName: z.string().optional(),
  guestEmail: z.string().email().optional(),
  guestPhone: z.string().optional(),
})

export const createRoomSchema = z.object({
  hotelId: z.string(),
  roomType: z.string().min(1),
  roomNumber: z.string().optional(),
  capacity: z.number().min(1),
  beds: z.number().min(1),
  basePrice: z.number().min(0),
  description: z.string().optional(),
  amenities: z.array(z.string()).optional(),
  images: z.array(z.string()).optional(),
})

export const updateRoomSchema = z.object({
  roomType: z.string().optional(),
  roomNumber: z.string().optional(),
  capacity: z.number().min(1).optional(),
  beds: z.number().min(1).optional(),
  basePrice: z.number().min(0).optional(),
  status: z.enum(['AVAILABLE', 'OCCUPIED', 'MAINTENANCE', 'RESERVED']).optional(),
  description: z.string().optional(),
  amenities: z.array(z.string()).optional(),
  images: z.array(z.string()).optional(),
})

export const createReviewSchema = z.object({
  hotelId: z.string(),
  bookingId: z.string().optional(),
  rating: z.number().min(1).max(5),
  comment: z.string().min(10),
  cleanliness: z.number().min(1).max(5).optional(),
  comfort: z.number().min(1).max(5).optional(),
  service: z.number().min(1).max(5).optional(),
  value: z.number().min(1).max(5).optional(),
})

export const updateReviewSchema = z.object({
  rating: z.number().min(1).max(5).optional(),
  comment: z.string().min(10).optional(),
  cleanliness: z.number().min(1).max(5).optional(),
  comfort: z.number().min(1).max(5).optional(),
  service: z.number().min(1).max(5).optional(),
  value: z.number().min(1).max(5).optional(),
})

export const createPaymentSchema = z.object({
  bookingId: z.string(),
  amount: z.number().min(0),
  currency: z.string().default('USD'),
  method: z.enum(['card', 'bank', 'wallet']),
  stripeId: z.string().optional(),
})

export const updatePaymentSchema = z.object({
  status: z.enum(['pending', 'completed', 'failed', 'refunded']).optional(),
  transactionId: z.string().optional(),
  paidAt: z.string().datetime().optional(),
  refundedAt: z.string().datetime().optional(),
})

export const updateProfileSchema = z.object({
  firstName: z.string().min(1).max(100).optional(),
  lastName: z.string().min(1).max(100).optional(),
  phone: z.string().optional(),
  bio: z.string().max(500).optional(),
  avatar: z.string().url().optional(),
})

export const changePasswordSchema = z.object({
  currentPassword: z.string(),
  newPassword: passwordSchema,
})

export const createNotificationSchema = z.object({
  userId: z.string(),
  type: z.enum([
    'BOOKING_CONFIRMED',
    'BOOKING_CANCELLED', 
    'REVIEW_RECEIVED',
    'SPECIAL_OFFER',
    'PAYMENT_REMINDER',
    'CHECK_IN_REMINDER',
    'SYSTEM_ALERT'
  ]),
  title: z.string().min(1),
  message: z.string().min(1),
  data: z.string().optional(),
})

export const searchHotelsSchema = z.object({
  city: z.string().optional(),
  country: z.string().optional(),
  minPrice: z.number().min(0).optional(),
  maxPrice: z.number().min(0).optional(),
  minRating: z.number().min(0).max(5).optional(),
  amenities: z.array(z.string()).optional(),
  checkIn: z.string().datetime().optional(),
  checkOut: z.string().datetime().optional(),
  guests: z.number().min(1).optional(),
  page: z.number().min(1).default(1),
  pageSize: z.number().min(1).max(100).default(10),
})

export const createDiscountSchema = z.object({
  hotelId: z.string(),
  code: z.string().min(1),
  type: z.enum(['PERCENTAGE', 'FIXED_AMOUNT', 'EARLY_BIRD', 'LOYALTY', 'SEASONAL']),
  value: z.number().min(0),
  description: z.string().optional(),
  minStay: z.number().min(1).optional(),
  maxStay: z.number().min(1).optional(),
  minPrice: z.number().min(0).optional(),
  maxPrice: z.number().min(0).optional(),
  validFrom: z.string().datetime(),
  validUntil: z.string().datetime(),
  usageLimit: z.number().min(1).optional(),
})

export const updateDiscountSchema = z.object({
  code: z.string().min(1).optional(),
  type: z.enum(['PERCENTAGE', 'FIXED_AMOUNT', 'EARLY_BIRD', 'LOYALTY', 'SEASONAL']).optional(),
  value: z.number().min(0).optional(),
  description: z.string().optional(),
  minStay: z.number().min(1).optional(),
  maxStay: z.number().min(1).optional(),
  minPrice: z.number().min(0).optional(),
  maxPrice: z.number().min(0).optional(),
  validFrom: z.string().datetime().optional(),
  validUntil: z.string().datetime().optional(),
  usageLimit: z.number().min(1).optional(),
})

export const createServiceSchema = z.object({
  hotelId: z.string(),
  name: z.string().min(1),
  description: z.string().optional(),
  price: z.number().min(0),
  icon: z.string().optional(),
  isActive: z.boolean().default(true),
})

export const updateServiceSchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  price: z.number().min(0).optional(),
  icon: z.string().optional(),
  isActive: z.boolean().optional(),
})
