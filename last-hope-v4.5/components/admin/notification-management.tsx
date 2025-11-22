'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

interface Notification {
  id: string
  userId?: string
  user?: {
    firstName: string
    lastName: string
    email: string
  }
  type: string
  title: string
  message: string
  priority: string
  channels: string[]
  imageUrl?: string
  actionUrl?: string
  actionText?: string
  isScheduled: boolean
  scheduledFor?: string
  expiresAt?: string
  isSent: boolean
  isRead: boolean
  isClicked: boolean
  deliveryCount: number
  clickCount: number
  createdAt: string
  sentAt?: string
  readAt?: string
}

interface UserNotification {
  id: string
  userId: string
  user: {
    firstName: string
    lastName: string
    email: string
  }
  type: string
  title: string
  message: string
  read: boolean
  createdAt: string
}

export default function NotificationManagement() {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [userNotifications, setUserNotifications] = useState<UserNotification[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('enhanced')

  // Enhanced notification dialog state
  const [showNotificationDialog, setShowNotificationDialog] = useState(false)
  const [editingNotification, setEditingNotification] = useState<Notification | null>(null)
  const [notificationForm, setNotificationForm] = useState({
    title: '',
    message: '',
    type: 'SYSTEM_ALERT',
    priority: 'NORMAL',
    userId: '',
    targetRole: '',
    targetSegment: '',
    channels: [] as string[],
    imageUrl: '',
    actionUrl: '',
    actionText: '',
    isScheduled: false,
    scheduledFor: '',
    expiresAt: ''
  })

  // Stats
  const [stats, setStats] = useState({
    total: 0,
    sent: 0,
    pending: 0,
    read: 0,
    clicked: 0
  })

  const notificationTypes = [
    'BOOKING_CONFIRMED', 'BOOKING_CANCELLED', 'REVIEW_RECEIVED', 
    'SPECIAL_OFFER', 'PAYMENT_REMINDER', 'CHECK_IN_REMINDER', 
    'SYSTEM_ALERT', 'MAINTENANCE', 'PROMOTION'
  ]

  const notificationChannels = [
    'PUSH', 'EMAIL', 'SMS', 'IN_APP'
  ]

  const priorities = [
    { value: 'LOW', label: 'منخفضة' },
    { value: 'NORMAL', label: 'عادية' },
    { value: 'HIGH', label: 'عالية' },
    { value: 'URGENT', label: 'عاجلة' }
  ]

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)

      // Fetch enhanced notifications
      const notificationsResponse = await fetch('/api/notifications/enhanced')
      if (notificationsResponse.ok) {
        const notificationsData = await notificationsResponse.json()
        if (notificationsData.status === 'success') {
          setNotifications(notificationsData.data)
          
          // Calculate stats
          const total = notificationsData.data.length
          const sent = notificationsData.data.filter((n: any) => n.isSent).length
          const pending = notificationsData.data.filter((n: any) => !n.isSent).length
          const read = notificationsData.data.filter((n: any) => n.isRead).length
          const clicked = notificationsData.data.filter((n: any) => n.isClicked).length
          
          setStats({ total, sent, pending, read, clicked })
        }
      }

      // Fetch user notifications
      const userNotificationsResponse = await fetch('/api/notifications')
      if (userNotificationsResponse.ok) {
        const userNotificationsData = await userNotificationsResponse.json()
        if (userNotificationsData.status === 'success') {
          setUserNotifications(userNotificationsData.data)
        }
      }

      setError(null)
    } catch (error: any) {
      console.error('Error fetching notifications:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  // Enhanced notification operations
  const saveNotification = async () => {
    try {
      const formData = {
        ...notificationForm,
        channels: notificationForm.channels.filter(c => c)
      }

      const url = editingNotification ? `/api/notifications/enhanced/${editingNotification.id}` : '/api/notifications/enhanced'
      const method = editingNotification ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowNotificationDialog(false)
        resetNotificationForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteNotification = async (id: string) => {
    try {
      const response = await fetch(`/api/notifications/enhanced/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const sendNotification = async (id: string) => {
    try {
      const response = await fetch(`/api/notifications/enhanced/${id}/send`, { method: 'POST' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const markAsRead = async (id: string) => {
    try {
      const response = await fetch(`/api/notifications/${id}/read`, { method: 'POST' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const resetNotificationForm = () => {
    setNotificationForm({
      title: '',
      message: '',
      type: 'SYSTEM_ALERT',
      priority: 'NORMAL',
      userId: '',
      targetRole: '',
      targetSegment: '',
      channels: [],
      imageUrl: '',
      actionUrl: '',
      actionText: '',
      isScheduled: false,
      scheduledFor: '',
      expiresAt: ''
    })
    setEditingNotification(null)
  }

  const editNotification = (notification: Notification) => {
    setNotificationForm({
      title: notification.title,
      message: notification.message,
      type: notification.type,
      priority: notification.priority,
      userId: notification.userId || '',
      targetRole: '',
      targetSegment: '',
      channels: notification.channels,
      imageUrl: notification.imageUrl || '',
      actionUrl: notification.actionUrl || '',
      actionText: notification.actionText || '',
      isScheduled: notification.isScheduled,
      scheduledFor: notification.scheduledFor ? notification.scheduledFor.split('T')[0] : '',
      expiresAt: notification.expiresAt ? notification.expiresAt.split('T')[0] : ''
    })
    setEditingNotification(notification)
    setShowNotificationDialog(true)
  }

  const toggleChannel = (channel: string) => {
    setNotificationForm(prev => ({
      ...prev,
      channels: prev.channels.includes(channel)
        ? prev.channels.filter(c => c !== channel)
        : [...prev.channels, channel]
    }))
  }

  if (loading) {
    return <div className="flex items-center justify-center p-8">جاري التحميل...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">إدارة الإشعارات</h2>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 font-medium">خطأ: {error}</p>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="enhanced">الإشعارات المتقدمة</TabsTrigger>
          <TabsTrigger value="user">إشعارات المستخدمين</TabsTrigger>
          <TabsTrigger value="analytics">التحليلات</TabsTrigger>
        </TabsList>

        <TabsContent value="enhanced" className="space-y-4">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>إجمالي الإشعارات</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{stats.total}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>تم الإرسال</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-green-600">{stats.sent}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>في الانتظار</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-yellow-600">{stats.pending}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>تم القراءة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-blue-600">{stats.read}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>تم النقر</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-purple-600">{stats.clicked}</div>
              </CardContent>
            </Card>
          </div>

          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">الإشعارات المتقدمة</h3>
            <Dialog open={showNotificationDialog} onOpenChange={setShowNotificationDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetNotificationForm}>إنشاء إشعار جديد</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingNotification ? 'تعديل الإشعار' : 'إنشاء إشعار جديد'}
                  </DialogTitle>
                  <DialogDescription>
                    إنشاء وإرسال إشعار متقدم للمستخدمين
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="title">عنوان الإشعار</Label>
                    <Input
                      id="title"
                      value={notificationForm.title}
                      onChange={(e) => setNotificationForm({ ...notificationForm, title: e.target.value })}
                      placeholder="عنوان واضح ومختصر"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="message">نص الرسالة</Label>
                    <Textarea
                      id="message"
                      value={notificationForm.message}
                      onChange={(e) => setNotificationForm({ ...notificationForm, message: e.target.value })}
                      placeholder="محتوى الرسالة التفصيلي..."
                      rows={4}
                    />
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="type">نوع الإشعار</Label>
                      <Select value={notificationForm.type} onValueChange={(value) => setNotificationForm({ ...notificationForm, type: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {notificationTypes.map(type => (
                            <SelectItem key={type} value={type}>
                              {type === 'BOOKING_CONFIRMED' ? 'تأكيد الحجز' :
                               type === 'BOOKING_CANCELLED' ? 'إلغاء الحجز' :
                               type === 'REVIEW_RECEIVED' ? 'استلام تقييم' :
                               type === 'SPECIAL_OFFER' ? 'عرض خاص' :
                               type === 'PAYMENT_REMINDER' ? 'تذكير الدفع' :
                               type === 'CHECK_IN_REMINDER' ? 'تذكير الوصول' :
                               type === 'SYSTEM_ALERT' ? 'تنبيه النظام' :
                               type === 'MAINTENANCE' ? 'صيانة' :
                               type === 'PROMOTION' ? 'ترويج' : type}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="priority">الأولوية</Label>
                      <Select value={notificationForm.priority} onValueChange={(value) => setNotificationForm({ ...notificationForm, priority: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {priorities.map(priority => (
                            <SelectItem key={priority.value} value={priority.value}>
                              {priority.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="userId">مستخدم محدد</Label>
                      <Input
                        id="userId"
                        value={notificationForm.userId}
                        onChange={(e) => setNotificationForm({ ...notificationForm, userId: e.target.value })}
                        placeholder="معرف المستخدم (اختياري)"
                      />
                    </div>
                  </div>

                  {/* Channels Selection */}
                  <div className="space-y-2">
                    <Label>قنوات الإرسال</Label>
                    <div className="grid grid-cols-4 gap-2">
                      {notificationChannels.map(channel => (
                        <div key={channel} className="flex items-center space-x-2">
                          <Switch
                            id={channel}
                            checked={notificationForm.channels.includes(channel)}
                            onCheckedChange={() => toggleChannel(channel)}
                          />
                          <Label htmlFor={channel}>
                            {channel === 'PUSH' ? 'Push' :
                             channel === 'EMAIL' ? 'إيميل' :
                             channel === 'SMS' ? 'رسالة' :
                             'داخل التطبيق'}
                          </Label>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="imageUrl">رابط الصورة</Label>
                      <Input
                        id="imageUrl"
                        value={notificationForm.imageUrl}
                        onChange={(e) => setNotificationForm({ ...notificationForm, imageUrl: e.target.value })}
                        placeholder="https://example.com/image.jpg"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="actionText">نص الإجراء</Label>
                      <Input
                        id="actionText"
                        value={notificationForm.actionText}
                        onChange={(e) => setNotificationForm({ ...notificationForm, actionText: e.target.value })}
                        placeholder="مثال: عرض التفاصيل"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="actionUrl">رابط الإجراء</Label>
                    <Input
                      id="actionUrl"
                      value={notificationForm.actionUrl}
                      onChange={(e) => setNotificationForm({ ...notificationForm, actionUrl: e.target.value })}
                      placeholder="https://example.com/action"
                    />
                  </div>

                  {/* Scheduling */}
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="isScheduled"
                      checked={notificationForm.isScheduled}
                      onCheckedChange={(checked) => setNotificationForm({ ...notificationForm, isScheduled: checked })}
                    />
                    <Label htmlFor="isScheduled">جدولة الإرسال</Label>
                  </div>

                  {notificationForm.isScheduled && (
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="scheduledFor">تاريخ ووقت الإرسال</Label>
                        <Input
                          id="scheduledFor"
                          type="datetime-local"
                          value={notificationForm.scheduledFor}
                          onChange={(e) => setNotificationForm({ ...notificationForm, scheduledFor: e.target.value })}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="expiresAt">تاريخ انتهاء الصلاحية</Label>
                        <Input
                          id="expiresAt"
                          type="datetime-local"
                          value={notificationForm.expiresAt}
                          onChange={(e) => setNotificationForm({ ...notificationForm, expiresAt: e.target.value })}
                        />
                      </div>
                    </div>
                  )}
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowNotificationDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveNotification}>
                    {editingNotification ? 'تحديث' : 'إنشاء'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة الإشعارات المتقدمة</CardTitle>
              <CardDescription>إدارة جميع الإشعارات المتقدمة والإحصائيات</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>العنوان</TableHead>
                    <TableHead>النوع</TableHead>
                    <TableHead>الأولوية</TableHead>
                    <TableHead>القنوات</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإحصائيات</TableHead>
                    <TableHead>التاريخ</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {notifications.map((notification) => (
                    <TableRow key={notification.id}>
                      <TableCell className="font-medium">
                        {notification.title}
                        {notification.user && (
                          <div className="text-xs text-muted-foreground">
                            للمستخدم: {notification.user.firstName} {notification.user.lastName}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{notification.type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={
                          notification.priority === 'URGENT' ? 'destructive' :
                          notification.priority === 'HIGH' ? 'default' : 'secondary'
                        }>
                          {notification.priority === 'LOW' ? 'منخفضة' :
                           notification.priority === 'NORMAL' ? 'عادية' :
                           notification.priority === 'HIGH' ? 'عالية' : 'عاجلة'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          {notification.channels.map(channel => (
                            <Badge key={channel} variant="outline" className="text-xs">
                              {channel}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <Badge variant={notification.isSent ? "default" : "secondary"}>
                            {notification.isSent ? 'تم الإرسال' : 'في الانتظار'}
                          </Badge>
                          {notification.isScheduled && (
                            <Badge variant="outline" className="text-xs">مجدول</Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-xs space-y-1">
                          <div>التسليم: {notification.deliveryCount}</div>
                          <div>القراءة: {notification.isRead ? '✓' : '✗'}</div>
                          <div>النقر: {notification.clickCount}</div>
                        </div>
                      </TableCell>
                      <TableCell>{new Date(notification.createdAt).toLocaleDateString('ar')}</TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editNotification(notification)}
                          >
                            تعديل
                          </Button>
                          {!notification.isSent && (
                            <Button
                              size="sm"
                              variant="default"
                              onClick={() => sendNotification(notification.id)}
                            >
                              إرسال
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteNotification(notification.id)}
                          >
                            حذف
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="user" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>إشعارات المستخدمين</CardTitle>
              <CardDescription>إدارة الإشعارات الشخصية للمستخدمين</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>المستخدم</TableHead>
                    <TableHead>العنوان</TableHead>
                    <TableHead>النوع</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>التاريخ</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {userNotifications.map((notification) => (
                    <TableRow key={notification.id}>
                      <TableCell className="font-medium">
                        {notification.user.firstName} {notification.user.lastName}
                        <div className="text-xs text-muted-foreground">{notification.user.email}</div>
                      </TableCell>
                      <TableCell>{notification.title}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{notification.type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={notification.read ? "default" : "secondary"}>
                          {notification.read ? 'مقروء' : 'غير مقروء'}
                        </Badge>
                      </TableCell>
                      <TableCell>{new Date(notification.createdAt).toLocaleDateString('ar')}</TableCell>
                      <TableCell>
                        {!notification.read && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => markAsRead(notification.id)}
                          >
                            تحديد كمقروء
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>إحصائيات الأداء</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span>معدل التسليم</span>
                    <span className="font-bold">{stats.total > 0 ? Math.round((stats.sent / stats.total) * 100) : 0}%</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>معدل القراءة</span>
                    <span className="font-bold">{stats.total > 0 ? Math.round((stats.read / stats.sent) * 100) : 0}%</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>معدل النقر</span>
                    <span className="font-bold">{stats.total > 0 ? Math.round((stats.clicked / stats.sent) * 100) : 0}%</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>توزيع القنوات</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {notificationChannels.map(channel => {
                    const count = notifications.filter(n => n.channels.includes(channel)).length
                    const percentage = stats.total > 0 ? Math.round((count / stats.total) * 100) : 0
                    return (
                      <div key={channel} className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span>
                            {channel === 'PUSH' ? 'Push Notification' :
                             channel === 'EMAIL' ? 'البريد الإلكتروني' :
                             channel === 'SMS' ? 'الرسائل النصية' : 'داخل التطبيق'}
                          </span>
                          <span>{percentage}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div 
                            className="bg-blue-600 h-2 rounded-full" 
                            style={{ width: `${percentage}%` }}
                          ></div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}