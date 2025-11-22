'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { 
  Search, 
  Filter, 
  MoreHorizontal, 
  Eye, 
  Edit, 
  Trash2, 
  Calendar,
  User,
  MapPin,
  DollarSign,
  Phone,
  Mail,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw
} from 'lucide-react'

interface Booking {
  id: string
  bookingReference: string
  user: {
    id: string
    firstName: string
    lastName: string
    email: string
    phone: string
  }
  hotel: {
    id: string
    name: string
  }
  room: {
    id: string
    roomNumber: string
    roomType: string
  }
  checkInDate: string
  checkOutDate: string
  guests: number
  guestName: string
  guestEmail: string
  guestPhone: string
  status: 'PENDING' | 'CONFIRMED' | 'CANCELLED' | 'COMPLETED' | 'CHECKED_IN' | 'CHECKED_OUT'
  totalPrice: number
  paymentStatus: 'pending' | 'completed' | 'failed' | 'refunded'
  createdAt: string
  updatedAt: string
}

interface BookingManagementProps {
  hotelId?: string
  role?: 'MANAGER' | 'STAFF' | 'ADMIN'
}

export default function BookingManagement({ hotelId, role = 'MANAGER' }: BookingManagementProps) {
  const [bookings, setBookings] = useState<Booking[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [dateFilter, setDateFilter] = useState<string>('all')
  const [selectedBooking, setSelectedBooking] = useState<Booking | null>(null)
  const [showDetails, setShowDetails] = useState(false)
  const [showEditDialog, setShowEditDialog] = useState(false)
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [totalCount, setTotalCount] = useState(0)

  const pageSize = 20

  useEffect(() => {
    fetchBookings()
  }, [hotelId, statusFilter, dateFilter, currentPage])

  const fetchBookings = async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({
        page: currentPage.toString(),
        pageSize: pageSize.toString(),
        ...(hotelId && { hotelId }),
        ...(statusFilter !== 'all' && { status: statusFilter }),
        ...(dateFilter !== 'all' && { dateRange: dateFilter }),
        ...(searchTerm && { search: searchTerm }),
      })

      const response = await fetch(`/api/bookings?${params}`)
      const data = await response.json()

      if (data.success) {
        setBookings(data.data.bookings)
        setTotalCount(data.data.pagination.totalCount)
        setTotalPages(data.data.pagination.totalPages)
      }
    } catch (error) {
      console.error('Failed to fetch bookings:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleStatusUpdate = async (bookingId: string, newStatus: string, reason?: string) => {
    try {
      const response = await fetch(`/api/bookings/${bookingId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status: newStatus,
          reason,
          updatedBy: 'current-user-id', // This should come from auth context
        }),
      })

      if (response.ok) {
        await fetchBookings() // Refresh the list
        setShowEditDialog(false)
      } else {
        const error = await response.json()
        console.error('Failed to update booking status:', error)
      }
    } catch (error) {
      console.error('Failed to update booking status:', error)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'PENDING': return <Clock className="h-4 w-4 text-yellow-500" />
      case 'CONFIRMED': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'CANCELLED': return <XCircle className="h-4 w-4 text-red-500" />
      case 'CHECKED_IN': return <User className="h-4 w-4 text-blue-500" />
      case 'CHECKED_OUT': return <AlertTriangle className="h-4 w-4 text-orange-500" />
      case 'COMPLETED': return <CheckCircle className="h-4 w-4 text-green-600" />
      default: return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusBadge = (status: string) => {
    const variants = {
      PENDING: 'default',
      CONFIRMED: 'secondary',
      CANCELLED: 'destructive',
      CHECKED_IN: 'outline',
      CHECKED_OUT: 'outline',
      COMPLETED: 'secondary',
    } as const

    const colors = {
      PENDING: 'bg-yellow-100 text-yellow-800',
      CONFIRMED: 'bg-green-100 text-green-800',
      CANCELLED: 'bg-red-100 text-red-800',
      CHECKED_IN: 'bg-blue-100 text-blue-800',
      CHECKED_OUT: 'bg-orange-100 text-orange-800',
      COMPLETED: 'bg-green-100 text-green-800',
    } as const

    return (
      <Badge 
        className={`${colors[status as keyof typeof colors] || 'bg-gray-100 text-gray-800'}`}
        variant={variants[status as keyof typeof variants] || 'default'}
      >
        {status.replace('_', ' ')}
      </Badge>
    )
  }

  const getPaymentStatusBadge = (status: string) => {
    const colors = {
      pending: 'bg-yellow-100 text-yellow-800',
      completed: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800',
      refunded: 'bg-blue-100 text-blue-800',
    } as const

    return (
      <Badge className={`${colors[status as keyof typeof colors] || 'bg-gray-100 text-gray-800'}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Badge>
    )
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const calculateNights = (checkIn: string, checkOut: string) => {
    const checkInDate = new Date(checkIn)
    const checkOutDate = new Date(checkOut)
    const diffTime = Math.abs(checkOutDate.getTime() - checkInDate.getTime())
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Booking Management</h1>
          <p className="text-muted-foreground">
            Manage hotel bookings and reservations
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={fetchBookings} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          {role === 'MANAGER' && (
            <Button>
              <Calendar className="h-4 w-4 mr-2" />
              New Booking
            </Button>
          )}
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search bookings..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="PENDING">Pending</SelectItem>
                <SelectItem value="CONFIRMED">Confirmed</SelectItem>
                <SelectItem value="CHECKED_IN">Checked In</SelectItem>
                <SelectItem value="CHECKED_OUT">Checked Out</SelectItem>
                <SelectItem value="COMPLETED">Completed</SelectItem>
                <SelectItem value="CANCELLED">Cancelled</SelectItem>
              </SelectContent>
            </Select>
            <Select value={dateFilter} onValueChange={setDateFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Date Range" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Time</SelectItem>
                <SelectItem value="today">Today</SelectItem>
                <SelectItem value="tomorrow">Tomorrow</SelectItem>
                <SelectItem value="week">This Week</SelectItem>
                <SelectItem value="month">This Month</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={() => { setSearchTerm(''); setStatusFilter('all'); setDateFilter('all') }}>
              <Filter className="h-4 w-4 mr-2" />
              Clear Filters
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Bookings Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Bookings ({totalCount})</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          ) : bookings.length > 0 ? (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Reference</TableHead>
                    <TableHead>Guest</TableHead>
                    <TableHead>Hotel & Room</TableHead>
                    <TableHead>Dates</TableHead>
                    <TableHead>Nights</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Payment</TableHead>
                    <TableHead>Amount</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {bookings.map((booking) => (
                    <TableRow key={booking.id}>
                      <TableCell className="font-mono text-sm">
                        {booking.bookingReference}
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="font-medium">{booking.guestName}</div>
                          <div className="text-sm text-muted-foreground">
                            {booking.guestEmail}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {booking.guestPhone}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="font-medium">{booking.hotel.name}</div>
                          <div className="text-sm text-muted-foreground">
                            Room {booking.room.roomNumber} - {booking.room.roomType}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {booking.guests} guest{booking.guests > 1 ? 's' : ''}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="text-sm">
                            <strong>In:</strong> {formatDate(booking.checkInDate)}
                          </div>
                          <div className="text-sm">
                            <strong>Out:</strong> {formatDate(booking.checkOutDate)}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-center">
                          {calculateNights(booking.checkInDate, booking.checkOutDate)}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getStatusIcon(booking.status)}
                          {getStatusBadge(booking.status)}
                        </div>
                      </TableCell>
                      <TableCell>
                        {getPaymentStatusBadge(booking.paymentStatus)}
                      </TableCell>
                      <TableCell>
                        <div className="font-semibold">
                          ${booking.totalPrice.toLocaleString()}
                        </div>
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" className="h-8 w-8 p-0">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            <DropdownMenuItem
                              onClick={() => {
                                setSelectedBooking(booking)
                                setShowDetails(true)
                              }}
                            >
                              <Eye className="mr-2 h-4 w-4" />
                              View Details
                            </DropdownMenuItem>
                            {(role === 'MANAGER' || role === 'STAFF') && (
                              <>
                                <DropdownMenuItem
                                  onClick={() => {
                                    setSelectedBooking(booking)
                                    setShowEditDialog(true)
                                  }}
                                >
                                  <Edit className="mr-2 h-4 w-4" />
                                  Update Status
                                </DropdownMenuItem>
                                {booking.status === 'PENDING' && (
                                  <DropdownMenuItem
                                    onClick={() => handleStatusUpdate(booking.id, 'CONFIRMED')}
                                  >
                                    <CheckCircle className="mr-2 h-4 w-4" />
                                    Confirm
                                  </DropdownMenuItem>
                                )}
                                {booking.status === 'CONFIRMED' && (
                                  <DropdownMenuItem
                                    onClick={() => handleStatusUpdate(booking.id, 'CHECKED_IN')}
                                  >
                                    <User className="mr-2 h-4 w-4" />
                                    Check In
                                  </DropdownMenuItem>
                                )}
                                {booking.status === 'CHECKED_IN' && (
                                  <DropdownMenuItem
                                    onClick={() => handleStatusUpdate(booking.id, 'CHECKED_OUT')}
                                  >
                                    <AlertTriangle className="mr-2 h-4 w-4" />
                                    Check Out
                                  </DropdownMenuItem>
                                )}
                              </>
                            )}
                            {role === 'ADMIN' && (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  onClick={() => handleStatusUpdate(booking.id, 'CANCELLED')}
                                  className="text-red-600"
                                >
                                  <XCircle className="mr-2 h-4 w-4" />
                                  Cancel Booking
                                </DropdownMenuItem>
                              </>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {/* Pagination */}
              <div className="flex items-center justify-between mt-4">
                <div className="text-sm text-muted-foreground">
                  Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, totalCount)} of {totalCount} entries
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                    disabled={currentPage === 1}
                  >
                    Previous
                  </Button>
                  <span className="text-sm">
                    Page {currentPage} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                    disabled={currentPage === totalPages}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              No bookings found matching your criteria
            </div>
          )}
        </CardContent>
      </Card>

      {/* Booking Details Dialog */}
      <Dialog open={showDetails} onOpenChange={setShowDetails}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Booking Details</DialogTitle>
            <DialogDescription>
              Complete information for booking {selectedBooking?.bookingReference}
            </DialogDescription>
          </DialogHeader>
          {selectedBooking && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm font-medium">Guest Information</Label>
                  <div className="mt-1 space-y-1 text-sm">
                    <div className="flex items-center">
                      <User className="h-4 w-4 mr-2" />
                      {selectedBooking.guestName}
                    </div>
                    <div className="flex items-center">
                      <Mail className="h-4 w-4 mr-2" />
                      {selectedBooking.guestEmail}
                    </div>
                    <div className="flex items-center">
                      <Phone className="h-4 w-4 mr-2" />
                      {selectedBooking.guestPhone}
                    </div>
                  </div>
                </div>
                <div>
                  <Label className="text-sm font-medium">Booking Information</Label>
                  <div className="mt-1 space-y-1 text-sm">
                    <div className="flex items-center">
                      <MapPin className="h-4 w-4 mr-2" />
                      {selectedBooking.hotel.name}
                    </div>
                    <div>Room: {selectedBooking.room.roomNumber} - {selectedBooking.room.roomType}</div>
                    <div>Guests: {selectedBooking.guests}</div>
                    <div>Created: {formatDate(selectedBooking.createdAt)}</div>
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm font-medium">Stay Details</Label>
                  <div className="mt-1 space-y-1 text-sm">
                    <div>
                      <strong>Check-in:</strong> {formatDate(selectedBooking.checkInDate)}
                    </div>
                    <div>
                      <strong>Check-out:</strong> {formatDate(selectedBooking.checkOutDate)}
                    </div>
                    <div>
                      <strong>Nights:</strong> {calculateNights(selectedBooking.checkInDate, selectedBooking.checkOutDate)}
                    </div>
                  </div>
                </div>
                <div>
                  <Label className="text-sm font-medium">Payment & Status</Label>
                  <div className="mt-1 space-y-1 text-sm">
                    <div className="flex items-center gap-2">
                      <strong>Status:</strong>
                      {getStatusBadge(selectedBooking.status)}
                    </div>
                    <div className="flex items-center gap-2">
                      <strong>Payment:</strong>
                      {getPaymentStatusBadge(selectedBooking.paymentStatus)}
                    </div>
                    <div>
                      <strong>Total:</strong> ${selectedBooking.totalPrice.toLocaleString()}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Edit Booking Status Dialog */}
      <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Update Booking Status</DialogTitle>
            <DialogDescription>
              Update the status for booking {selectedBooking?.bookingReference}
            </DialogDescription>
          </DialogHeader>
          {selectedBooking && (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="newStatus">New Status</Label>
                <Select 
                  onValueChange={(value) => handleStatusUpdate(selectedBooking.id, value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select new status" />
                  </SelectTrigger>
                  <SelectContent>
                    {selectedBooking.status === 'PENDING' && (
                      <SelectItem value="CONFIRMED">Confirmed</SelectItem>
                    )}
                    {selectedBooking.status === 'CONFIRMED' && (
                      <SelectItem value="CHECKED_IN">Checked In</SelectItem>
                    )}
                    {selectedBooking.status === 'CHECKED_IN' && (
                      <SelectItem value="CHECKED_OUT">Checked Out</SelectItem>
                    )}
                    {selectedBooking.status !== 'CANCELLED' && (
                      <SelectItem value="CANCELLED">Cancelled</SelectItem>
                    )}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}