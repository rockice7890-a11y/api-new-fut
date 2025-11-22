import { useState, useCallback, useEffect } from 'react'

interface PushNotification {
  id: string
  title: string
  body: string
  type: 'BOOKING_CONFIRMED' | 'BOOKING_CANCELLED' | 'REVIEW_RECEIVED' | 'SPECIAL_OFFER' | 'PAYMENT_REMINDER' | 'CHECK_IN_REMINDER' | 'SYSTEM_ALERT'
  priority: 'LOW' | 'NORMAL' | 'HIGH' | 'URGENT'
  data?: Record<string, any>
  isRead: boolean
  isSent: boolean
  sentAt?: string
  readAt?: string
  scheduledAt?: string
  expiresAt?: string
  createdAt: string
}

interface NotificationFilters {
  type?: PushNotification['type']
  isRead?: boolean
  isSent?: boolean
  priority?: PushNotification['priority']
  limit?: number
  offset?: number
}

interface UsePushNotificationsReturn {
  notifications: PushNotification[]
  loading: boolean
  error: string | null
  unreadCount: number
  sendNotification: (notification: {
    userId?: string
    title: string
    body: string
    type: PushNotification['type']
    data?: Record<string, any>
    priority?: PushNotification['priority']
    scheduledAt?: string
    expiresAt?: string
  }) => Promise<boolean>
  markAsRead: (notificationIds: string[]) => Promise<void>
  markAllAsRead: () => Promise<void>
  getNotifications: (filters?: NotificationFilters) => Promise<void>
  refreshNotifications: () => Promise<void>
  registerDevice: (deviceData: {
    deviceId: string
    deviceToken?: string
    deviceType: 'ios' | 'android' | 'web'
    deviceName?: string
    deviceModel?: string
    appVersion?: string
    osVersion?: string
    notificationsEnabled?: boolean
    soundEnabled?: boolean
    vibrationEnabled?: boolean
  }) => Promise<boolean>
}

export function usePushNotifications(): UsePushNotificationsReturn {
  const [notifications, setNotifications] = useState<PushNotification[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [unreadCount, setUnreadCount] = useState(0)

  // Send notification
  const sendNotification = useCallback(async (notification: {
    userId?: string
    title: string
    body: string
    type: PushNotification['type']
    data?: Record<string, any>
    priority?: PushNotification['priority']
    scheduledAt?: string
    expiresAt?: string
  }): Promise<boolean> => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/push-notifications/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(notification)
      })

      if (!response.ok) {
        throw new Error('Failed to send notification')
      }

      const data = await response.json()

      if (data.status === 'success') {
        // Refresh notifications to show the new one
        await refreshNotifications()
        return true
      } else {
        throw new Error(data.message || 'Failed to send notification')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      console.error('Send notification error:', err)
      return false
    } finally {
      setLoading(false)
    }
  }, [])

  // Mark notifications as read
  const markAsRead = useCallback(async (notificationIds: string[]) => {
    try {
      const response = await fetch('/api/push-notifications/mark-read', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ notificationIds })
      })

      if (response.ok) {
        setNotifications(prev => 
          prev.map(notif => 
            notificationIds.includes(notif.id) 
              ? { ...notif, isRead: true, readAt: new Date().toISOString() }
              : notif
          )
        )
        setUnreadCount(prev => Math.max(0, prev - notificationIds.length))
      }
    } catch (err) {
      console.error('Mark as read error:', err)
    }
  }, [])

  // Mark all as read
  const markAllAsRead = useCallback(async () => {
    try {
      const response = await fetch('/api/push-notifications/mark-read', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ markAll: true })
      })

      if (response.ok) {
        setNotifications(prev => 
          prev.map(notif => ({ 
            ...notif, 
            isRead: true, 
            readAt: new Date().toISOString() 
          }))
        )
        setUnreadCount(0)
      }
    } catch (err) {
      console.error('Mark all as read error:', err)
    }
  }, [])

  // Get notifications
  const getNotifications = useCallback(async (filters?: NotificationFilters) => {
    try {
      setLoading(true)
      setError(null)

      const params = new URLSearchParams()
      if (filters?.type) params.append('type', filters.type)
      if (filters?.isRead !== undefined) params.append('isRead', filters.isRead.toString())
      if (filters?.isSent !== undefined) params.append('isSent', filters.isSent.toString())
      if (filters?.priority) params.append('priority', filters.priority)
      if (filters?.limit) params.append('limit', filters.limit.toString())
      if (filters?.offset) params.append('offset', filters.offset.toString())

      const response = await fetch(`/api/push-notifications?${params.toString()}`, {
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
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      console.error('Get notifications error:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  // Register device
  const registerDevice = useCallback(async (deviceData: {
    deviceId: string
    deviceToken?: string
    deviceType: 'ios' | 'android' | 'web'
    deviceName?: string
    deviceModel?: string
    appVersion?: string
    osVersion?: string
    notificationsEnabled?: boolean
    soundEnabled?: boolean
    vibrationEnabled?: boolean
  }): Promise<boolean> => {
    try {
      const response = await fetch('/api/user-devices/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(deviceData)
      })

      if (!response.ok) {
        throw new Error('Failed to register device')
      }

      const data = await response.json()

      if (data.status === 'success') {
        return true
      } else {
        throw new Error(data.message || 'Failed to register device')
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      console.error('Register device error:', err)
      return false
    }
  }, [])

  // Refresh notifications
  const refreshNotifications = useCallback(async () => {
    await getNotifications()
  }, [getNotifications])

  // Auto-refresh unread count when notifications change
  useEffect(() => {
    const unread = notifications.filter(n => !n.isRead && n.isSent).length
    setUnreadCount(unread)
  }, [notifications])

  return {
    notifications,
    loading,
    error,
    unreadCount,
    sendNotification,
    markAsRead,
    markAllAsRead,
    getNotifications,
    refreshNotifications,
    registerDevice
  }
}