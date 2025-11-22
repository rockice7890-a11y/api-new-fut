'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  Users, 
  BedDouble, 
  DollarSign, 
  Star, 
  TrendingUp, 
  TrendingDown,
  Calendar,
  BarChart3,
  PieChart,
  Clock,
  AlertCircle,
  CheckCircle
} from 'lucide-react'

interface HotelDashboardProps {
  hotelId?: string
  role?: 'MANAGER' | 'STAFF' | 'ADMIN'
}

interface DashboardStats {
  totalBookings: number
  occupancyRate: number
  revenue: number
  averageRating: number
  totalReviews: number
  availableRooms: number
  pendingBookings: number
  checkedIn: number
  checkedOut: number
}

interface RecentActivity {
  id: string
  type: 'booking' | 'checkin' | 'checkout' | 'payment' | 'review'
  description: string
  timestamp: Date
  guestName?: string
  roomNumber?: string
}

export default function HotelDashboard({ hotelId, role = 'MANAGER' }: HotelDashboardProps) {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [recentActivity, setRecentActivity] = useState<RecentActivity[]>([])
  const [loading, setLoading] = useState(true)
  const [timeRange, setTimeRange] = useState<'today' | 'week' | 'month'>('today')

  useEffect(() => {
    if (hotelId) {
      fetchDashboardData()
    }
  }, [hotelId, timeRange])

  const fetchDashboardData = async () => {
    setLoading(true)
    try {
      // Fetch dashboard statistics
      const statsResponse = await fetch(`/api/admin/hotels/${hotelId}/dashboard?timeRange=${timeRange}`)
      const statsData = await statsResponse.json()
      
      // Fetch recent activity
      const activityResponse = await fetch(`/api/admin/hotels/${hotelId}/activity?limit=10`)
      const activityData = await activityResponse.json()

      if (statsData.success) {
        setStats(statsData.data)
      }

      if (activityData.success) {
        setRecentActivity(activityData.data)
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'booking': return <Calendar className="h-4 w-4" />
      case 'checkin': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'checkout': return <AlertCircle className="h-4 w-4 text-blue-500" />
      case 'payment': return <DollarSign className="h-4 w-4 text-green-600" />
      case 'review': return <Star className="h-4 w-4 text-yellow-500" />
      default: return <Clock className="h-4 w-4" />
    }
  }

  const getActivityBadge = (type: string) => {
    const variants = {
      booking: 'default',
      checkin: 'secondary',
      checkout: 'outline',
      payment: 'default',
      review: 'destructive'
    } as const

    const labels = {
      booking: 'Booking',
      checkin: 'Check-in',
      checkout: 'Check-out',
      payment: 'Payment',
      review: 'Review'
    }

    return (
      <Badge variant={variants[type as keyof typeof variants] || 'outline'}>
        {labels[type as keyof typeof labels] || type}
      </Badge>
    )
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Hotel Dashboard</h1>
          <p className="text-muted-foreground">
            Welcome back! Here's what's happening at your hotel today.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Tabs value={timeRange} onValueChange={(v) => setTimeRange(v as any)}>
            <TabsList>
              <TabsTrigger value="today">Today</TabsTrigger>
              <TabsTrigger value="week">This Week</TabsTrigger>
              <TabsTrigger value="month">This Month</TabsTrigger>
            </TabsList>
          </Tabs>
          <Button onClick={fetchDashboardData} variant="outline" size="sm">
            Refresh
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Bookings</CardTitle>
            <Calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.totalBookings || 0}</div>
            <p className="text-xs text-muted-foreground">
              +12% from last {timeRange}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Occupancy Rate</CardTitle>
            <BedDouble className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.occupancyRate?.toFixed(1) || 0}%</div>
            <Progress value={stats?.occupancyRate || 0} className="mt-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Revenue</CardTitle>
            <DollarSign className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">${stats?.revenue?.toLocaleString() || 0}</div>
            <p className="text-xs text-muted-foreground flex items-center">
              <TrendingUp className="h-3 w-3 mr-1" />
              +8% from last {timeRange}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Rating</CardTitle>
            <Star className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold flex items-center">
              {stats?.averageRating?.toFixed(1) || 0}
              <Star className="h-4 w-4 ml-1 text-yellow-500 fill-current" />
            </div>
            <p className="text-xs text-muted-foreground">
              Based on {stats?.totalReviews || 0} reviews
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentActivity.length > 0 ? (
                  recentActivity.map((activity) => (
                    <div key={activity.id} className="flex items-center space-x-4">
                      <div className="flex-shrink-0">
                        {getActivityIcon(activity.type)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium">{activity.description}</p>
                        <p className="text-xs text-muted-foreground">
                          {activity.guestName} • {activity.roomNumber} • {activity.timestamp.toLocaleDateString()}
                        </p>
                      </div>
                      <div className="flex-shrink-0">
                        {getActivityBadge(activity.type)}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    No recent activity
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Quick Stats */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Today's Status</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span className="text-sm">Available Rooms</span>
                </div>
                <span className="font-semibold">{stats?.availableRooms || 0}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Clock className="h-4 w-4 text-blue-500" />
                  <span className="text-sm">Pending Bookings</span>
                </div>
                <span className="font-semibold">{stats?.pendingBookings || 0}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <span className="text-sm">Checked In</span>
                </div>
                <span className="font-semibold">{stats?.checkedIn || 0}</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <AlertCircle className="h-4 w-4 text-orange-500" />
                  <span className="text-sm">Check-outs Due</span>
                </div>
                <span className="font-semibold">{stats?.checkedOut || 0}</span>
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          {role === 'MANAGER' && (
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Button className="w-full" size="sm">
                  <Calendar className="h-4 w-4 mr-2" />
                  New Booking
                </Button>
                <Button variant="outline" className="w-full" size="sm">
                  <Users className="h-4 w-4 mr-2" />
                  Manage Staff
                </Button>
                <Button variant="outline" className="w-full" size="sm">
                  <BarChart3 className="h-4 w-4 mr-2" />
                  View Reports
                </Button>
                <Button variant="outline" className="w-full" size="sm">
                  <PieChart className="h-4 w-4 mr-2" />
                  Analytics
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Performance Charts Placeholder */}
      <Card>
        <CardHeader>
          <CardTitle>Performance Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <BarChart3 className="h-12 w-12 mx-auto mb-4" />
              <p>Performance charts will be displayed here</p>
              <p className="text-sm">Integration with charting library needed</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}