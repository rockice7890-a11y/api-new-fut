'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AlertCircle, BarChart3, LogOut, Settings, Users, Hotel, Calendar, TrendingUp } from 'lucide-react'

export function ExternalDashboard() {
  const [token, setToken] = useState<string>('')
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [analytics, setAnalytics] = useState<any>(null)
  const [users, setUsers] = useState<any[]>([])
  const [hotels, setHotels] = useState<any[]>([])
  const [bookings, setBookings] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string>('')
  const [activeTab, setActiveTab] = useState('overview')
  const [selectedUser, setSelectedUser] = useState<any>(null)

  useEffect(() => {
    const savedToken = localStorage.getItem('authToken')
    if (savedToken) {
      setToken(savedToken)
      setIsAuthenticated(true)
      verifyToken(savedToken)
    }
  }, [])

  const verifyToken = async (tokenValue: string) => {
    try {
      const response = await fetch('/api/auth/verify-token', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${tokenValue}` },
      })
      if (response.ok) {
        await loadDashboardData(tokenValue)
      }
    } catch (err) {
      console.error('Token verification failed')
    }
  }

  const loadDashboardData = async (tokenValue: string) => {
    setLoading(true)
    try {
      const [analyticsRes, usersRes, hotelsRes] = await Promise.all([
        fetch('/api/admin/analytics/summary', {
          headers: { 'Authorization': `Bearer ${tokenValue}` },
        }),
        fetch('/api/admin/users', {
          headers: { 'Authorization': `Bearer ${tokenValue}` },
        }),
        fetch('/api/hotels', {
          headers: { 'Authorization': `Bearer ${tokenValue}` },
        }),
      ])

      if (analyticsRes.ok) {
        const data = await analyticsRes.json()
        setAnalytics(data.data)
      }
      if (usersRes.ok) {
        const data = await usersRes.json()
        setUsers(data.data?.users || [])
      }
      if (hotelsRes.ok) {
        const data = await hotelsRes.json()
        setHotels(data.data?.hotels || [])
      }
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isAuthenticated && token) {
      loadBookings()
    }
  }, [isAuthenticated, token])

  const loadBookings = async () => {
    try {
      const response = await fetch('/api/bookings', {
        headers: { 'Authorization': `Bearer ${token}` },
      })
      if (response.ok) {
        const data = await response.json()
        setBookings(data.data?.bookings || [])
      }
    } catch (err: any) {
      console.error('Failed to load bookings')
    }
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const formData = new FormData(e.currentTarget as HTMLFormElement)
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: formData.get('email'),
          password: formData.get('password'),
        }),
      })

      if (response.ok) {
        const data = await response.json()
        const newToken = data.data?.token
        setToken(newToken)
        localStorage.setItem('authToken', newToken)
        setIsAuthenticated(true)
        await loadDashboardData(newToken)
      } else {
        const errData = await response.json()
        setError(errData.message || 'Login failed')
      }
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      })
    } catch (err) {
      console.error('Logout failed')
    } finally {
      setToken('')
      setIsAuthenticated(false)
      localStorage.removeItem('authToken')
      setAnalytics(null)
      setUsers([])
      setHotels([])
      setBookings([])
      setSelectedUser(null)
    }
  }

  const handleBlockUser = async (userId: string) => {
    try {
      const response = await fetch(`/api/users/${userId}/block`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ reason: 'POLICY_BREACH' }),
      })

      if (response.ok) {
        setUsers(users.map(u => u.id === userId ? { ...u, blockInfo: { isBlocked: true } } : u))
      }
    } catch (err) {
      console.error('Failed to block user')
    }
  }

  const handleViewUserDetails = (user: any) => {
    setSelectedUser(user)
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="text-2xl">Admin Login</CardTitle>
            <CardDescription>لوحة التحكم الإدارية للفنادق</CardDescription>
          </CardHeader>
          <CardContent>
            {error && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg flex gap-2">
                <AlertCircle className="text-red-600 w-5 h-5 flex-shrink-0" />
                <p className="text-sm text-red-700">{error}</p>
              </div>
            )}
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">البريد الإلكتروني</label>
                <input
                  type="email"
                  name="email"
                  placeholder="admin@example.com"
                  required
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">كلمة المرور</label>
                <input
                  type="password"
                  name="password"
                  placeholder="••••••••"
                  required
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <Button type="submit" disabled={loading} className="w-full">
                {loading ? 'جاري تسجيل الدخول...' : 'تسجيل الدخول'}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <div className="bg-white border-b border-slate-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold text-slate-900">لوحة التحكم الإدارية</h1>
          <Button variant="outline" size="sm" onClick={handleLogout}>
            <LogOut className="w-4 h-4 mr-2" />
            تسجيل الخروج
          </Button>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-600">إجمالي الحجوزات</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <span className="text-2xl font-bold">{analytics?.totalBookings || 0}</span>
                <Calendar className="w-8 h-8 text-blue-500 opacity-50" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-600">إجمالي الإيرادات</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <span className="text-2xl font-bold">${analytics?.totalRevenue || 0}</span>
                <TrendingUp className="w-8 h-8 text-green-500 opacity-50" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-600">الفنادق النشطة</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <span className="text-2xl font-bold">{analytics?.activeHotels || 0}</span>
                <Hotel className="w-8 h-8 text-purple-500 opacity-50" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-600">المستخدمون المسجلون</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <span className="text-2xl font-bold">{analytics?.registeredUsers || 0}</span>
                <Users className="w-8 h-8 text-orange-500 opacity-50" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs Section */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid grid-cols-5 w-full">
            <TabsTrigger value="overview">نظرة عامة</TabsTrigger>
            <TabsTrigger value="users">المستخدمون</TabsTrigger>
            <TabsTrigger value="hotels">الفنادق</TabsTrigger>
            <TabsTrigger value="bookings">الحجوزات</TabsTrigger>
            <TabsTrigger value="settings">الإعدادات</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>إحصائيات سريعة</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between">
                    <span>متوسط التقييم:</span>
                    <span className="font-bold">4.5/5</span>
                  </div>
                  <div className="flex justify-between">
                    <span>معدل الإشغال:</span>
                    <span className="font-bold">85%</span>
                  </div>
                  <div className="flex justify-between">
                    <span>الحجوزات اليوم:</span>
                    <span className="font-bold">{bookings.length}</span>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>الإجراءات السريعة</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Button variant="outline" className="w-full justify-start">
                    إنشاء مستخدم جديد
                  </Button>
                  <Button variant="outline" className="w-full justify-start">
                    إضافة فندق
                  </Button>
                  <Button variant="outline" className="w-full justify-start">
                    عرض التقارير
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Users Tab with Advanced Features */}
          <TabsContent value="users">
            <Card>
              <CardHeader>
                <CardTitle>إدارة المستخدمين</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-200">
                        <th className="text-left py-3 px-4">البريد</th>
                        <th className="text-left py-3 px-4">الاسم</th>
                        <th className="text-left py-3 px-4">الدور</th>
                        <th className="text-left py-3 px-4">الحالة</th>
                        <th className="text-left py-3 px-4">الإجراءات</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((user: any) => (
                        <tr key={user.id} className="border-b border-slate-100 hover:bg-slate-50">
                          <td className="py-3 px-4">{user.email}</td>
                          <td className="py-3 px-4">{user.firstName} {user.lastName}</td>
                          <td className="py-3 px-4">
                            <Badge variant={user.role === 'ADMIN' ? 'default' : 'secondary'}>
                              {user.role}
                            </Badge>
                          </td>
                          <td className="py-3 px-4">
                            <Badge variant={user.blockInfo?.isBlocked ? 'destructive' : 'outline'}>
                              {user.blockInfo?.isBlocked ? 'محظور' : 'نشط'}
                            </Badge>
                          </td>
                          <td className="py-3 px-4 space-x-2">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleViewUserDetails(user)}
                            >
                              التفاصيل
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleBlockUser(user.id)}
                            >
                              {user.blockInfo?.isBlocked ? 'إلغاء الحظر' : 'حظر'}
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {selectedUser && (
                  <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
                    <h3 className="font-bold mb-3">تفاصيل المستخدم</h3>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div><span className="text-slate-600">المعرّف:</span> {selectedUser.id}</div>
                      <div><span className="text-slate-600">البريد:</span> {selectedUser.email}</div>
                      <div><span className="text-slate-600">الهاتف:</span> {selectedUser.phone || 'غير محدد'}</div>
                      <div><span className="text-slate-600">تاريخ التسجيل:</span> {new Date(selectedUser.createdAt).toLocaleDateString('ar-EG')}</div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Hotels Tab */}
          <TabsContent value="hotels">
            <Card>
              <CardHeader>
                <CardTitle>قائمة الفنادق</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {hotels.slice(0, 6).map((hotel: any) => (
                    <Card key={hotel.id} className="border">
                      <CardHeader>
                        <CardTitle className="text-lg">{hotel.name}</CardTitle>
                        <CardDescription>{hotel.city}, {hotel.country}</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2 text-sm">
                          <div>
                            <span className="font-medium">التقييم:</span> {hotel.rating.toFixed(1)}/5
                          </div>
                          <div>
                            <span className="font-medium">التقييمات:</span> {hotel.totalReviews}
                          </div>
                          <div>
                            <span className="font-medium">الغرف:</span> {hotel.rooms?.length || 0}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Bookings Tab */}
          <TabsContent value="bookings">
            <Card>
              <CardHeader>
                <CardTitle>الحجوزات الحالية</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-200">
                        <th className="text-left py-3 px-4">رقم الحجز</th>
                        <th className="text-left py-3 px-4">الضيف</th>
                        <th className="text-left py-3 px-4">تاريخ الدخول</th>
                        <th className="text-left py-3 px-4">تاريخ الخروج</th>
                        <th className="text-left py-3 px-4">الحالة</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bookings.slice(0, 10).map((booking: any) => (
                        <tr key={booking.id} className="border-b border-slate-100 hover:bg-slate-50">
                          <td className="py-3 px-4 font-mono text-xs">{booking.bookingReference}</td>
                          <td className="py-3 px-4">{booking.guestName}</td>
                          <td className="py-3 px-4">{new Date(booking.checkInDate).toLocaleDateString('ar-EG')}</td>
                          <td className="py-3 px-4">{new Date(booking.checkOutDate).toLocaleDateString('ar-EG')}</td>
                          <td className="py-3 px-4">
                            <Badge variant={booking.status === 'CONFIRMED' ? 'default' : 'secondary'}>
                              {booking.status}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Settings Tab */}
          <TabsContent value="settings">
            <Card>
              <CardHeader>
                <CardTitle>إعدادات النظام</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                  <h3 className="font-medium text-green-900 mb-2">حالة الخادم</h3>
                  <div className="text-sm text-green-800 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 bg-green-600 rounded-full"></span>
                      قاعدة البيانات: متصلة
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 bg-green-600 rounded-full"></span>
                      الخادم: يعمل بشكل طبيعي
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 bg-green-600 rounded-full"></span>
                      التخزين: متوفر
                    </div>
                  </div>
                </div>

                <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                  <h3 className="font-medium text-blue-900 mb-2">معلومات الـ API</h3>
                  <div className="text-sm text-blue-800 space-y-2">
                    <div><span className="font-medium">الإصدار:</span> 1.0.0</div>
                    <div><span className="font-medium">نوع قاعدة البيانات:</span> PostgreSQL</div>
                    <div><span className="font-medium">المصادقة:</span> JWT with Refresh Tokens</div>
                    <div><span className="font-medium">التشفير:</span> bcryptjs</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
