/**
 * QR Code Generation Utilities
 * Generates QR codes for different booking-related operations
 */

export interface QRCodeData {
  bookingId: string;
  userId: string;
  type: 'BOOKING_CONFIRMATION' | 'CHECK_IN' | 'CHECK_OUT' | 'INVOICE' | 'ROOM_ACCESS' | 'PAYMENT_RECEIPT';
  timestamp: number;
  hash: string;
}

export interface QRCodeOptions {
  size?: number;
  errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
  margin?: number;
  color?: {
    dark?: string;
    light?: string;
  };
}

/**
 * Generate QR Code for booking operations
 */
export function generateQRCode(data: QRCodeData, options?: QRCodeOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    // In a real implementation, you would use a QR code library like qrcode.js
    // For now, returning the data string that can be converted to QR
    const qrDataString = JSON.stringify(data)
    resolve(qrDataString)
  })
}

/**
 * Create booking confirmation QR code
 */
export async function createBookingConfirmationQR(bookingId: string, userId: string): Promise<QRCodeData> {
  const qrData: QRCodeData = {
    bookingId,
    userId,
    type: 'BOOKING_CONFIRMATION',
    timestamp: Date.now(),
    hash: generateHash()
  }

  return qrData
}

/**
 * Create check-in QR code
 */
export async function createCheckInQR(bookingId: string, userId: string): Promise<QRCodeData> {
  const qrData: QRCodeData = {
    bookingId,
    userId,
    type: 'CHECK_IN',
    timestamp: Date.now(),
    hash: generateHash()
  }

  return qrData
}

/**
 * Create check-out QR code
 */
export async function createCheckOutQR(bookingId: string, userId: string): Promise<QRCodeData> {
  const qrData: QRCodeData = {
    bookingId,
    userId,
    type: 'CHECK_OUT',
    timestamp: Date.now(),
    hash: generateHash()
  }

  return qrData
}

/**
 * Create invoice QR code
 */
export async function createInvoiceQR(bookingId: string, userId: string): Promise<QRCodeData> {
  const qrData: QRCodeData = {
    bookingId,
    userId,
    type: 'INVOICE',
    timestamp: Date.now(),
    hash: generateHash()
  }

  return qrData
}

/**
 * Create room access QR code
 */
export async function createRoomAccessQR(bookingId: string, userId: string): Promise<QRCodeData> {
  const qrData: QRCodeData = {
    bookingId,
    userId,
    type: 'ROOM_ACCESS',
    timestamp: Date.now(),
    hash: generateHash()
  }

  return qrData
}

/**
 * Create payment receipt QR code
 */
export async function createPaymentReceiptQR(bookingId: string, userId: string): Promise<QRCodeData> {
  const qrData: QRCodeData = {
    bookingId,
    userId,
    type: 'PAYMENT_RECEIPT',
    timestamp: Date.now(),
    hash: generateHash()
  }

  return qrData
}

/**
 * Validate QR code data
 */
export function validateQRCodeData(data: any): data is QRCodeData {
  return (
    typeof data === 'object' &&
    typeof data.bookingId === 'string' &&
    typeof data.userId === 'string' &&
    typeof data.type === 'string' &&
    ['BOOKING_CONFIRMATION', 'CHECK_IN', 'CHECK_OUT', 'INVOICE', 'ROOM_ACCESS', 'PAYMENT_RECEIPT'].includes(data.type) &&
    typeof data.timestamp === 'number' &&
    typeof data.hash === 'string'
  )
}

/**
 * Get QR code type display name
 */
export function getQRCodeTypeDisplayName(type: QRCodeData['type']): string {
  const typeNames: Record<QRCodeData['type'], string> = {
    BOOKING_CONFIRMATION: 'Booking Confirmation',
    CHECK_IN: 'Check-In',
    CHECK_OUT: 'Check-Out',
    INVOICE: 'Invoice',
    ROOM_ACCESS: 'Room Access',
    PAYMENT_RECEIPT: 'Payment Receipt'
  }
  
  return typeNames[type] || type
}

/**
 * Generate random hash
 */
function generateHash(): string {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15)
}

/**
 * Convert QR code data to URL for sharing
 */
export function createQRCodeShareableURL(data: QRCodeData): string {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://your-app.com'
  const encodedData = btoa(JSON.stringify(data))
  return `${baseUrl}/qr/validate?data=${encodedData}`
}

/**
 * Parse QR code from URL
 */
export function parseQRCodeFromURL(url: string): QRCodeData | null {
  try {
    const urlObj = new URL(url)
    const dataParam = urlObj.searchParams.get('data')
    
    if (!dataParam) return null
    
    const decodedData = atob(dataParam)
    const parsed = JSON.parse(decodedData)
    
    if (validateQRCodeData(parsed)) {
      return parsed
    }
    
    return null
  } catch (error) {
    console.error('Error parsing QR code from URL:', error)
    return null
  }
}