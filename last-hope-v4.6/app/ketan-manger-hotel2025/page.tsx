'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { AlertCircle, RefreshCw, Database } from 'lucide-react'
import Sidebar from '@/components/admin/sidebar'
import UserManagement from '@/components/admin/user-management'
import HotelManagement from '@/components/admin/hotel-management'
import AuditLogs from '@/components/admin/audit-logs'
import Permissions from '@/components/admin/permissions'
import GamesContestsManagement from '@/components/admin/games-contests-management'
import LoyaltyManagement from '@/components/admin/loyalty-management'
import StaffPayrollManagement from '@/components/admin/staff-payroll-management'
import OrganizationManagement from '@/components/admin/organization-management'
import NotificationManagement from '@/components/admin/notification-management'
import PromotionManagement from '@/components/admin/promotion-management'
import SystemConfiguration from '@/components/admin/system-configuration'

interface AnalyticsData {
  totalUsers: number
  totalBookings: number
  totalRevenue: number
  avgBookingValue: number
}

// بيانات افتراضية عند فشل الاتصال
const FALLBACK_ANALYTICS: AnalyticsData = {
  totalUsers: 0,
  totalBookings: 0,
  totalRevenue: 0,
  avgBookingValue: 0
}

export default function KetanManagerDashboard() {
  const router = useRouter()
  const [analytics, setAnalytics] = useState<AnalyticsData>(FALLBACK_ANALYTICS)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('overview')
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  // التحقق من المصادقة
  useEffect(() => {
    const token = localStorage.getItem('admin_token')
    if (!token) {
      router.push('/admin/login')
      return
    }

    // التحقق من صحة التوكن
    fetch('/api/admin/auth/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    }).then(res => {
      if (res.ok) {
        setIsAuthenticated(true)
      } else {
        localStorage.removeItem('admin_token')
        router.push('/admin/login')
      }
    }).catch(() => {
      // في حالة فشل التحقق، نسمح بالمتابعة (للاختبار)
      setIsAuthenticated(true)
    })
  }, [router])

  const fetchAnalytics = async () => {
    setLoading(true)
    setError(null)
    
    try {
      const token = localStorage.getItem('admin_token')
      const headers: HeadersInit = {
        'Content-Type': 'application/json'
      }
      
      if (token) {
        headers['Authorization'] = `Bearer ${token}`
      }

      const response = await fetch('/api/admin/analytics/summary', { headers })
      
      if (!response.ok) {
        throw new Error(`خطأ في الاتصال: ${response.status}`)
      }
      
      const data = await response.json()
      if (data.status === 'success') {
        setAnalytics(data.data)
        setError(null)
      } else {
        throw new Error(data.message || 'فشل تحميل البيانات')
      }
    } catch (error: any) {
      console.error('Failed to fetch analytics:', error)
      setError(error.message || 'فشل الاتصال بقاعدة البيانات')
      setAnalytics(FALLBACK_ANALYTICS)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isAuthenticated) {
      fetchAnalytics()
    }
  }, [isAuthenticated])

  if (!isAuthenticated) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">جاري التحقق من الصلاحيات...</p>
        </div>
      </div>
    )
  }

  const chartData = [
    { name: 'Jan', bookings: 400, revenue: 2400 },
    { name: 'Feb', bookings: 300, revenue: 1398 },
    { name: 'Mar', bookings: 200, revenue: 9800 },
    { name: 'Apr', bookings: 278, revenue: 3908 },
    { name: 'May', bookings: 189, revenue: 4800 },
    { name: 'Jun', bookings: 239, revenue: 3800 },
  ]

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full h-full">
          <div className="border-b sticky top-0 bg-background z-10">
            <TabsList className="w-full justify-start rounded-none border-b overflow-x-auto">
              <TabsTrigger value="overview">الرئيسية</TabsTrigger>
              <TabsTrigger value="users">المستخدمين</TabsTrigger>
              <TabsTrigger value="hotels">الفنادق</TabsTrigger>
              <TabsTrigger value="staff">الموظفين</TabsTrigger>
              <TabsTrigger value="audit">التدقيق</TabsTrigger>
              <TabsTrigger value="permissions">الأذونات</TabsTrigger>
              <TabsTrigger value="games">الألعاب</TabsTrigger>
              <TabsTrigger value="loyalty">الولاء</TabsTrigger>
              <TabsTrigger value="organizations">المنظمات</TabsTrigger>
              <TabsTrigger value="notifications">الإشعارات</TabsTrigger>
              <TabsTrigger value="promotions">العروض</TabsTrigger>
              <TabsTrigger value="system">النظام</TabsTrigger>
            </TabsList>
          </div>

          <div className="p-6 overflow-auto">
            {error && (
              <div className="mb-6 p-6 bg-red-50 border-2 border-red-200 rounded-lg">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-6 h-6 text-red-600 flex-shrink-0 mt-1" />
                  <div className="flex-1">
                    <p className="text-red-900 font-bold text-lg mb-2">⚠️ فشل الاتصال بقاعدة البيانات</p>
                    <p className="text-red-700 mb-3">{error}</p>
                    <div className="bg-white p-4 rounded border border-red-200 mb-3">
                      <p className="text-sm font-semibold text-red-900 mb-2">📋 خطوات الإصلاح:</p>
                      <ol className="text-sm text-red-800 space-y-1 list-decimal list-inside">
                        <li>تأكد من تشغيل PostgreSQL على جهازك</li>
                        <li>تحقق من صحة DATABASE_URL في ملف .env</li>
                        <li>قم بتشغيل: <code className="bg-red-100 px-2 py-1 rounded">npx prisma generate</code></li>
                        <li>قم بتشغيل: <code className="bg-red-100 px-2 py-1 rounded">npx prisma db push</code></li>
                      </ol>
                    </div>
                    <div className="flex gap-2">
                      <Button 
                        onClick={fetchAnalytics}
                        className="bg-red-600 hover:bg-red-700"
                      >
                        <RefreshCw className="w-4 h-4 mr-2" />
                        إعادة المحاولة
                      </Button>
                      <Button 
                        variant="outline"
                        onClick={() => setError(null)}
                      >
                        متابعة بالبيانات الافتراضية
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            <TabsContent value="overview" className="space-y-6 mt-0">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                  title="إجمالي المستخدمين"
                  value={loading ? '-' : analytics.totalUsers.toString()}
                  icon="👥"
                  loading={loading}
                />
                <StatCard
                  title="إجمالي الحجوزات"
                  value={loading ? '-' : analytics.totalBookings.toString()}
                  icon="📅"
                  loading={loading}
                />
                <StatCard
                  title="الإيراد الكلي"
                  value={loading ? '-' : `$${analytics.totalRevenue.toFixed(2)}`}
                  icon="💰"
                  loading={loading}
                />
                <StatCard
                  title="متوسط قيمة الحجز"
                  value={loading ? '-' : `$${analytics.avgBookingValue.toFixed(2)}`}
                  icon="📊"
                  loading={loading}
                />
              </div>

              <Card className="border-sidebar-border">
                <CardHeader>
                  <CardTitle>الحجوزات والإيراد</CardTitle>
                  <CardDescription>آخر 6 أشهر</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--sidebar-border)" />
                      <XAxis stroke="var(--sidebar-foreground)" />
                      <YAxis stroke="var(--sidebar-foreground)" />
                      <Tooltip contentStyle={{ backgroundColor: 'var(--sidebar)', border: '1px solid var(--sidebar-border)' }} />
                      <Legend />
                      <Line type="monotone" dataKey="bookings" stroke="var(--sidebar-primary)" strokeWidth={2} />
                      <Line type="monotone" dataKey="revenue" stroke="var(--chart-1)" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="users" className="mt-0">
              <UserManagement />
            </TabsContent>

            <TabsContent value="hotels" className="mt-0">
              <HotelManagement />
            </TabsContent>

            <TabsContent value="audit" className="mt-0">
              <AuditLogs />
            </TabsContent>

            <TabsContent value="permissions" className="mt-0">
              <Permissions />
            </TabsContent>

            <TabsContent value="staff" className="mt-0">
              <StaffPayrollManagement />
            </TabsContent>

            <TabsContent value="games" className="mt-0">
              <GamesContestsManagement />
            </TabsContent>

            <TabsContent value="loyalty" className="mt-0">
              <LoyaltyManagement />
            </TabsContent>

            <TabsContent value="organizations" className="mt-0">
              <OrganizationManagement />
            </TabsContent>

            <TabsContent value="notifications" className="mt-0">
              <NotificationManagement />
            </TabsContent>

            <TabsContent value="promotions" className="mt-0">
              <PromotionManagement />
            </TabsContent>

            <TabsContent value="system" className="mt-0">
              <SystemConfiguration />
            </TabsContent>
          </div>
        </Tabs>
      </main>
    </div>
  )
}

function StatCard({ 
  title, 
  value, 
  icon,
  loading = false
}: { 
  title: string
  value: string
  icon: string
  loading?: boolean
}) {
  return (
    <Card className="border-sidebar-border">
      <CardHeader className="pb-2">
        <CardDescription className="text-sidebar-foreground">{title}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="text-3xl font-bold text-sidebar-primary">
            {loading ? (
              <div className="h-10 w-20 bg-gray-200 animate-pulse rounded"></div>
            ) : (
              value
            )}
          </div>
          <div className="text-4xl">{icon}</div>
        </div>
      </CardContent>
    </Card>
  )
}
