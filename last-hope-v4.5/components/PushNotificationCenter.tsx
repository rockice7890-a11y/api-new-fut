import React, { useState, useEffect } from 'react'
import { Bell, BellOff, Check, X, AlertCircle, Info, CheckCircle, AlertTriangle } from 'lucide-react'

interface Notification {
  id: string
  title: string
  body: string
  type: 'BOOKING_CONFIRMED' | 'BOOKING_CANCELLED' | 'REVIEW_RECEIVED' | 'SPECIAL_OFFER' | 'PAYMENT_REMINDER' | 'CHECK_IN_REMINDER' | 'SYSTEM_ALERT'
  priority: 'LOW' | 'NORMAL' | 'HIGH' | 'URGENT'
  isRead: boolean
  createdAt: string
  data?: Record<string, any>
}

interface PushNotificationCenterProps {
  userId?: string
  maxNotifications?: number
  showMarkAll?: boolean
  autoRefresh?: boolean
  refreshInterval?: number
  className?: string
}

const PushNotificationCenter: React.FC<PushNotificationCenterProps> = ({
  userId,
  maxNotifications = 20,
  showMarkAll = true,
  autoRefresh = false,
  refreshInterval = 30000, // 30 seconds
  className = ''
}) => {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showDropdown, setShowDropdown] = useState(false)
  const [unreadCount, setUnreadCount] = useState(0)

  // Fetch notifications
  const fetchNotifications = async () => {
    if (!userId) return

    try {
      setLoading(true)
      setError(null)

      const response = await fetch(`/api/push-notifications?limit=${maxNotifications}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        throw new Error('Failed to fetch notifications')
      }

      const data = await response.json()

      if (data.status === 'success') {
        setNotifications(data.data.notifications)
        setUnreadCount(data.data.summary.unread)
      } else {
        throw new Error(data.message || 'Failed to fetch notifications')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  // Mark notification as read
  const markAsRead = async (notificationIds: string[]) => {
    try {
      const response = await fetch('/api/push-notifications/mark-read', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ notificationIds })
      })

      if (response.ok) {
        // Update local state
        setNotifications(prev => 
          prev.map(notif => 
            notificationIds.includes(notif.id) 
              ? { ...notif, isRead: true }
              : notif
          )
        )
        setUnreadCount(prev => Math.max(0, prev - notificationIds.length))
      }
    } catch (err) {
      console.error('Failed to mark notifications as read:', err)
    }
  }

  // Mark all as read
  const markAllAsRead = async () => {
    try {
      const response = await fetch('/api/push-notifications/mark-read', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ markAll: true })
      })

      if (response.ok) {
        setNotifications(prev => prev.map(notif => ({ ...notif, isRead: true })))
        setUnreadCount(0)
      }
    } catch (err) {
      console.error('Failed to mark all notifications as read:', err)
    }
  }

  // Auto refresh
  useEffect(() => {
    if (autoRefresh && userId) {
      fetchNotifications()
      const interval = setInterval(fetchNotifications, refreshInterval)
      return () => clearInterval(interval)
    }
  }, [autoRefresh, refreshInterval, userId])

  // Get notification icon
  const getNotificationIcon = (type: Notification['type']) => {
    switch (type) {
      case 'BOOKING_CONFIRMED':
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'BOOKING_CANCELLED':
        return <X className="h-5 w-5 text-red-500" />
      case 'CHECK_IN_REMINDER':
        return <AlertTriangle className="h-5 w-5 text-orange-500" />
      case 'PAYMENT_REMINDER':
        return <AlertCircle className="h-5 w-5 text-yellow-500" />
      case 'REVIEW_RECEIVED':
        return <Info className="h-5 w-5 text-blue-500" />
      default:
        return <Bell className="h-5 w-5 text-gray-500" />
    }
  }

  // Get priority color
  const getPriorityColor = (priority: Notification['priority']) => {
    switch (priority) {
      case 'URGENT':
        return 'border-l-red-500'
      case 'HIGH':
        return 'border-l-orange-500'
      case 'NORMAL':
        return 'border-l-blue-500'
      case 'LOW':
        return 'border-l-gray-500'
      default:
        return 'border-l-gray-300'
    }
  }

  return (
    <div className={`relative ${className}`}>
      {/* Notification Bell */}
      <button
        onClick={() => setShowDropdown(!showDropdown)}
        className="relative p-2 text-gray-600 hover:text-gray-800 transition-colors"
      >
        {unreadCount > 0 ? (
          <Bell className="h-6 w-6" />
        ) : (
          <BellOff className="h-6 w-6" />
        )}
        
        {/* Unread Count Badge */}
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown */}
      {showDropdown && (
        <div className="absolute right-0 top-12 w-80 bg-white border border-gray-200 rounded-lg shadow-lg z-50">
          {/* Header */}
          <div className="p-4 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-gray-800">Notifications</h3>
              <div className="flex items-center gap-2">
                {unreadCount > 0 && showMarkAll && (
                  <button
                    onClick={markAllAsRead}
                    className="text-xs text-blue-600 hover:text-blue-800"
                  >
                    Mark all read
                  </button>
                )}
                <button
                  onClick={() => setShowDropdown(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Content */}
          <div className="max-h-96 overflow-y-auto">
            {loading ? (
              <div className="p-4 text-center text-gray-500">
                Loading notifications...
              </div>
            ) : error ? (
              <div className="p-4 text-center text-red-500">
                {error}
                <button
                  onClick={fetchNotifications}
                  className="ml-2 text-blue-600 hover:text-blue-800"
                >
                  Retry
                </button>
              </div>
            ) : notifications.length === 0 ? (
              <div className="p-4 text-center text-gray-500">
                No notifications
              </div>
            ) : (
              <div className="divide-y divide-gray-100">
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={`p-4 hover:bg-gray-50 cursor-pointer border-l-4 ${getPriorityColor(notification.priority)} ${!notification.isRead ? 'bg-blue-50' : ''}`}
                    onClick={() => !notification.isRead && markAsRead([notification.id])}
                  >
                    <div className="flex items-start gap-3">
                      {getNotificationIcon(notification.type)}
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm font-medium ${!notification.isRead ? 'text-gray-900' : 'text-gray-700'}`}>
                          {notification.title}
                        </p>
                        <p className={`text-sm ${!notification.isRead ? 'text-gray-700' : 'text-gray-500'}`}>
                          {notification.body}
                        </p>
                        <p className="text-xs text-gray-400 mt-1">
                          {new Date(notification.createdAt).toLocaleString()}
                        </p>
                      </div>
                      {!notification.isRead && (
                        <div className="w-2 h-2 bg-blue-500 rounded-full flex-shrink-0 mt-1" />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-3 border-t border-gray-200">
            <button
              onClick={fetchNotifications}
              className="w-full text-sm text-blue-600 hover:text-blue-800 text-center"
            >
              Refresh
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default PushNotificationCenter