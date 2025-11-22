import React, { useState, useEffect } from 'react'
import { QRCodeData, getQRCodeTypeDisplayName } from '@/lib/qr-code-utils'

interface QRCodeDisplayProps {
  qrCodeData: QRCodeData | string
  size?: number
  title?: string
  description?: string
  showActions?: boolean
  onGenerate?: () => void
  onDownload?: () => void
  onShare?: () => void
  className?: string
}

const QRCodeDisplay: React.FC<QRCodeDisplayProps> = ({
  qrCodeData,
  size = 200,
  title,
  description,
  showActions = true,
  onGenerate,
  onDownload,
  onShare,
  className = ''
}) => {
  const [qrString, setQrString] = useState<string>('')
  const [parsedData, setParsedData] = useState<QRCodeData | null>(null)

  useEffect(() => {
    if (typeof qrCodeData === 'string') {
      try {
        const data = JSON.parse(qrCodeData) as QRCodeData
        setQrString(qrCodeData)
        setParsedData(data)
      } catch {
        setQrString(qrCodeData)
      }
    } else {
      const jsonString = JSON.stringify(qrCodeData)
      setQrString(jsonString)
      setParsedData(qrCodeData)
    }
  }, [qrCodeData])

  const displayTitle = title || (parsedData ? getQRCodeTypeDisplayName(parsedData.type) : 'QR Code')
  const displayDescription = description || (parsedData ? `For booking ${parsedData.bookingId}` : '')

  return (
    <div className={`qr-code-display ${className}`}>
      {/* QR Code Container */}
      <div className="flex flex-col items-center p-6 bg-white rounded-lg shadow-lg">
        {/* Title */}
        <h3 className="text-lg font-semibold text-gray-800 mb-2">
          {displayTitle}
        </h3>

        {/* QR Code Area */}
        <div 
          className="flex items-center justify-center bg-gray-100 rounded-lg border-2 border-gray-200"
          style={{ width: size, height: size }}
        >
          {parsedData ? (
            <div className="text-center">
              {/* In a real implementation, you would render actual QR code here */}
              <div className="w-32 h-32 bg-black mx-auto mb-2 rounded" />
              <div className="text-xs text-gray-600 break-all">
                {qrString.substring(0, 50)}...
              </div>
            </div>
          ) : (
            <div className="text-gray-500 text-sm">
              Invalid QR Data
            </div>
          )}
        </div>

        {/* Description */}
        {displayDescription && (
          <p className="text-sm text-gray-600 mt-3 text-center">
            {displayDescription}
          </p>
        )}

        {/* Type Badge */}
        {parsedData && (
          <div className="mt-3 px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-xs font-medium">
            {getQRCodeTypeDisplayName(parsedData.type)}
          </div>
        )}

        {/* Actions */}
        {showActions && (
          <div className="flex gap-2 mt-4">
            {onGenerate && (
              <button
                onClick={onGenerate}
                className="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors text-sm"
              >
                Generate New
              </button>
            )}
            
            {onDownload && (
              <button
                onClick={onDownload}
                className="px-4 py-2 bg-green-500 text-white rounded-md hover:bg-green-600 transition-colors text-sm"
              >
                Download
              </button>
            )}
            
            {onShare && (
              <button
                onClick={onShare}
                className="px-4 py-2 bg-purple-500 text-white rounded-md hover:bg-purple-600 transition-colors text-sm"
              >
                Share
              </button>
            )}
          </div>
        )}
      </div>

      {/* QR Code Data (for debugging) */}
      {process.env.NODE_ENV === 'development' && parsedData && (
        <div className="mt-4 p-3 bg-gray-50 rounded text-xs">
          <h4 className="font-semibold mb-2">QR Data:</h4>
          <pre className="text-gray-700">
            {JSON.stringify(parsedData, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

export default QRCodeDisplay