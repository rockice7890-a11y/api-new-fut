'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Trash2, Edit2, Eye } from 'lucide-react'

interface Hotel {
  id: string
  name: string
  city: string
  rating: number
  minPrice?: number
}

interface Booking {
  id: string
  hotelName: string
  status: string
  totalPrice: number
  checkInDate: string
}

export default function HotelManagement() {
  const [hotels, setHotels] = useState<Hotel[]>([])
  const [bookings, setBookings] = useState<Booking[]>([])
  const [tab, setTab] = useState<'hotels' | 'bookings'>('hotels')
  const [loading, setLoading] = useState(true)
  const [searchHotel, setSearchHotel] = useState('')

  useEffect(() => {
    fetchData()
  }, [tab])

  const fetchData = async () => {
    try {
      setLoading(true)
      if (tab === 'hotels') {
        const response = await fetch(`/api/hotels?city=${searchHotel}`)
        const data = await response.json()
        if (data.status === 'success') {
          setHotels(data.data.hotels)
        }
      } else {
        const response = await fetch('/api/bookings')
        const data = await response.json()
        if (data.status === 'success') {
          setBookings(data.data.bookings)
        }
      }
    } catch (error) {
      console.error('Failed to fetch data:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="border-sidebar-border">
      <CardHeader>
        <CardTitle>إدارة الفنادق والحجوزات</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex gap-4 mb-6 border-b border-sidebar-border">
          <button
            onClick={() => setTab('hotels')}
            className={`pb-3 px-4 font-semibold transition-colors ${
              tab === 'hotels'
                ? 'text-sidebar-primary border-b-2 border-sidebar-primary'
                : 'text-sidebar-foreground opacity-75 hover:opacity-100'
            }`}
          >
            الفنادق
          </button>
          <button
            onClick={() => setTab('bookings')}
            className={`pb-3 px-4 font-semibold transition-colors ${
              tab === 'bookings'
                ? 'text-sidebar-primary border-b-2 border-sidebar-primary'
                : 'text-sidebar-foreground opacity-75 hover:opacity-100'
            }`}
          >
            الحجوزات
          </button>
        </div>

        {tab === 'hotels' ? (
          <div>
            <div className="mb-6">
              <Input
                placeholder="ابحث عن مدينة..."
                value={searchHotel}
                onChange={(e) => setSearchHotel(e.target.value)}
              />
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-sidebar-border">
                    <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">اسم الفندق</th>
                    <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">المدينة</th>
                    <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">التقييم</th>
                    <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">السعر الأدنى</th>
                    <th className="text-center py-3 px-4 font-semibold text-sidebar-primary">الإجراءات</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan={5} className="text-center py-8 text-sidebar-foreground opacity-50">
                        جاري التحميل...
                      </td>
                    </tr>
                  ) : hotels.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="text-center py-8 text-sidebar-foreground opacity-50">
                        لا توجد فنادق
                      </td>
                    </tr>
                  ) : (
                    hotels.map((hotel) => (
                      <tr key={hotel.id} className="border-b border-sidebar-border hover:bg-sidebar-accent transition-colors">
                        <td className="py-3 px-4 text-sidebar-foreground font-medium">{hotel.name}</td>
                        <td className="py-3 px-4 text-sidebar-foreground">{hotel.city}</td>
                        <td className="py-3 px-4">
                          <span className="text-yellow-500">★ {hotel.rating || 'N/A'}</span>
                        </td>
                        <td className="py-3 px-4 text-sidebar-foreground">${hotel.minPrice?.toFixed(2) || 'N/A'}</td>
                        <td className="py-3 px-4">
                          <div className="flex gap-2 justify-center">
                            <button className="text-sidebar-primary hover:opacity-80 transition-opacity">
                              <Eye size={18} />
                            </button>
                            <button className="text-blue-500 hover:opacity-80 transition-opacity">
                              <Edit2 size={18} />
                            </button>
                            <button className="text-destructive hover:opacity-80 transition-opacity">
                              <Trash2 size={18} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-sidebar-border">
                  <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">اسم الفندق</th>
                  <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">الحالة</th>
                  <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">السعر</th>
                  <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">تاريخ الوصول</th>
                  <th className="text-center py-3 px-4 font-semibold text-sidebar-primary">الإجراءات</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={5} className="text-center py-8 text-sidebar-foreground opacity-50">
                      جاري التحميل...
                    </td>
                  </tr>
                ) : bookings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center py-8 text-sidebar-foreground opacity-50">
                      لا توجد حجوزات
                    </td>
                  </tr>
                ) : (
                  bookings.map((booking) => (
                    <tr key={booking.id} className="border-b border-sidebar-border hover:bg-sidebar-accent transition-colors">
                      <td className="py-3 px-4 text-sidebar-foreground">{booking.hotelName}</td>
                      <td className="py-3 px-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                          booking.status === 'CONFIRMED'
                            ? 'bg-green-500 text-white'
                            : 'bg-yellow-500 text-white'
                        }`}>
                          {booking.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sidebar-foreground">${booking.totalPrice.toFixed(2)}</td>
                      <td className="py-3 px-4 text-sidebar-foreground">
                        {new Date(booking.checkInDate).toLocaleDateString('ar-SA')}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <button className="text-sidebar-primary hover:opacity-80 transition-opacity">
                          <Eye size={18} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
