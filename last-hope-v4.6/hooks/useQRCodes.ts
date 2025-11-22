import { useState, useCallback } from 'react'
import { QRCodeData } from '@/lib/qr-code-utils'

interface QRCode {
  id: string
  type: string
  code: string
  data: QRCodeData
  expiresAt: string
  isUsed: boolean
  usedAt?: string
  scanCount: number
  lastScannedAt?: string
  createdAt: string
  booking?: {
    id: string
    bookingReference: string
    status: string
    hotel: {
      id: string
      name: string
    }
    room: {
      id: string
      roomNumber: string
      roomType: string
    }
  }
}

interface UseQRCodesReturn {
  qrCodes: QRCode[]
  loading: boolean
  error: string | null
  generateQRCode: (bookingId: string, type: string, expiresIn?: number) => Promise<QRCode | null>
  scanQRCode: (code: string, location?: string) => Promise<any>
  getQRCodes: (filters?: {
    bookingId?: string
    type?: string
    includeExpired?: boolean
  }) => Promise<void>
  refreshQRCodes: () => Promise<void>
}

export function useQRCodes(): UseQRCodesReturn {
  const [qrCodes, setQrCodes] = useState<QRCode[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Generate QR Code
  const generateQRCode = useCallback(async (
    bookingId: string, 
    type: string, 
    expiresIn: number = 3600
  ): Promise<QRCode | null> => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/qr-codes/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          bookingId,
          type,
          expiresIn
        })
      })

      if (!response.ok) {
        throw new Error('Failed to generate QR code')
      }

      const data = await response.json()

      if (data.status === 'success') {
        const newQRCode = data.data.qrCode
        setQrCodes(prev => [newQRCode, ...prev])
        return newQRCode
      } else {
        throw new Error(data.message || 'Failed to generate QR code')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      console.error('Generate QR code error:', err)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  // Scan QR Code
  const scanQRCode = useCallback(async (code: string, location?: string): Promise<any> => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/qr-codes/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          code,
          location,
          scannerType: 'guest'
        })
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.message || 'Failed to scan QR code')
      }

      const data = await response.json()

      if (data.status === 'success') {
        // Refresh QR codes list to show updated scan counts
        await refreshQRCodes()
        return data.data
      } else {
        throw new Error(data.message || 'Failed to scan QR code')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      console.error('Scan QR code error:', err)
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  // Get QR Codes
  const getQRCodes = useCallback(async (filters?: {
    bookingId?: string
    type?: string
    includeExpired?: boolean
  }) => {
    try {
      setLoading(true)
      setError(null)

      const params = new URLSearchParams()
      if (filters?.bookingId) params.append('bookingId', filters.bookingId)
      if (filters?.type) params.append('type', filters.type)
      if (filters?.includeExpired) params.append('includeExpired', 'true')

      const response = await fetch(`/api/qr-codes?${params.toString()}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        throw new Error('Failed to fetch QR codes')
      }

      const data = await response.json()

      if (data.status === 'success') {
        setQrCodes(data.data.qrCodes.all)
      } else {
        throw new Error(data.message || 'Failed to fetch QR codes')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      console.error('Get QR codes error:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  // Refresh QR Codes
  const refreshQRCodes = useCallback(async () => {
    await getQRCodes()
  }, [getQRCodes])

  return {
    qrCodes,
    loading,
    error,
    generateQRCode,
    scanQRCode,
    getQRCodes,
    refreshQRCodes
  }
}