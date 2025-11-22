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

interface Organization {
  id: string
  name: string
  description?: string
  email?: string
  phone?: string
  address?: string
  city?: string
  country?: string
  logo?: string
  website?: string
  contactPerson?: string
  taxId?: string
  isActive: boolean
  guestCount: number
  totalBookings: number
  createdAt: string
  updatedAt: string
}

interface GuestDetails {
  id: string
  bookingId: string
  userId: string
  user: {
    firstName: string
    lastName: string
    email: string
  }
  organizationId?: string
  organization?: Organization
  fullName: string
  nationalId?: string
  passportNumber?: string
  phoneNumber: string
  city: string
  country: string
  specialRequests?: string
  emergencyContact?: string
  emergencyPhone?: string
  checkInDate: string
  checkOutDate: string
  guestCount: number
  verified: boolean
  verifiedAt?: string
  createdAt: string
}

export default function OrganizationManagement() {
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [guestDetails, setGuestDetails] = useState<GuestDetails[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('organizations')

  // Organization dialog state
  const [showOrganizationDialog, setShowOrganizationDialog] = useState(false)
  const [editingOrganization, setEditingOrganization] = useState<Organization | null>(null)
  const [organizationForm, setOrganizationForm] = useState({
    name: '',
    description: '',
    email: '',
    phone: '',
    address: '',
    city: '',
    country: '',
    logo: '',
    website: '',
    contactPerson: '',
    taxId: '',
    isActive: true
  })

  // Guest details dialog state
  const [showGuestDialog, setShowGuestDialog] = useState(false)
  const [editingGuest, setEditingGuest] = useState<GuestDetails | null>(null)
  const [guestForm, setGuestForm] = useState({
    organizationId: '',
    fullName: '',
    nationalId: '',
    passportNumber: '',
    phoneNumber: '',
    city: '',
    country: '',
    specialRequests: '',
    emergencyContact: '',
    emergencyPhone: '',
    checkInDate: '',
    checkOutDate: '',
    guestCount: 1,
    verified: false
  })

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)

      // Fetch organizations
      const organizationsResponse = await fetch('/api/organizations')
      if (organizationsResponse.ok) {
        const organizationsData = await organizationsResponse.json()
        if (organizationsData.status === 'success') {
          setOrganizations(organizationsData.data)
        }
      }

      // Fetch guest details
      const guestResponse = await fetch('/api/guest-details')
      if (guestResponse.ok) {
        const guestData = await guestResponse.json()
        if (guestData.status === 'success') {
          setGuestDetails(guestData.data)
        }
      }

      setError(null)
    } catch (error: any) {
      console.error('Error fetching organization data:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  // Organization operations
  const saveOrganization = async () => {
    try {
      const url = editingOrganization ? `/api/organizations/${editingOrganization.id}` : '/api/organizations'
      const method = editingOrganization ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(organizationForm)
      })

      if (response.ok) {
        await fetchData()
        setShowOrganizationDialog(false)
        resetOrganizationForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteOrganization = async (id: string) => {
    try {
      const response = await fetch(`/api/organizations/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const toggleOrganizationStatus = async (id: string, currentStatus: boolean) => {
    try {
      const response = await fetch(`/api/organizations/${id}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isActive: !currentStatus })
      })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  // Guest operations
  const saveGuest = async () => {
    try {
      const url = editingGuest ? `/api/guest-details/${editingGuest.id}` : '/api/guest-details'
      const method = editingGuest ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(guestForm)
      })

      if (response.ok) {
        await fetchData()
        setShowGuestDialog(false)
        resetGuestForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteGuest = async (id: string) => {
    try {
      const response = await fetch(`/api/guest-details/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const toggleGuestVerification = async (id: string, currentStatus: boolean) => {
    try {
      const response = await fetch(`/api/guest-details/${id}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verified: !currentStatus })
      })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const resetOrganizationForm = () => {
    setOrganizationForm({
      name: '',
      description: '',
      email: '',
      phone: '',
      address: '',
      city: '',
      country: '',
      logo: '',
      website: '',
      contactPerson: '',
      taxId: '',
      isActive: true
    })
    setEditingOrganization(null)
  }

  const resetGuestForm = () => {
    setGuestForm({
      organizationId: '',
      fullName: '',
      nationalId: '',
      passportNumber: '',
      phoneNumber: '',
      city: '',
      country: '',
      specialRequests: '',
      emergencyContact: '',
      emergencyPhone: '',
      checkInDate: '',
      checkOutDate: '',
      guestCount: 1,
      verified: false
    })
    setEditingGuest(null)
  }

  const editOrganization = (organization: Organization) => {
    setOrganizationForm({
      name: organization.name,
      description: organization.description || '',
      email: organization.email || '',
      phone: organization.phone || '',
      address: organization.address || '',
      city: organization.city || '',
      country: organization.country || '',
      logo: organization.logo || '',
      website: organization.website || '',
      contactPerson: organization.contactPerson || '',
      taxId: organization.taxId || '',
      isActive: organization.isActive
    })
    setEditingOrganization(organization)
    setShowOrganizationDialog(true)
  }

  const editGuest = (guest: GuestDetails) => {
    setGuestForm({
      organizationId: guest.organizationId || '',
      fullName: guest.fullName,
      nationalId: guest.nationalId || '',
      passportNumber: guest.passportNumber || '',
      phoneNumber: guest.phoneNumber,
      city: guest.city,
      country: guest.country,
      specialRequests: guest.specialRequests || '',
      emergencyContact: guest.emergencyContact || '',
      emergencyPhone: guest.emergencyPhone || '',
      checkInDate: guest.checkInDate.split('T')[0],
      checkOutDate: guest.checkOutDate.split('T')[0],
      guestCount: guest.guestCount,
      verified: guest.verified
    })
    setEditingGuest(guest)
    setShowGuestDialog(true)
  }

  // Stats calculation
  const activeOrganizations = organizations.filter(org => org.isActive).length
  const totalGuests = guestDetails.length
  const verifiedGuests = guestDetails.filter(guest => guest.verified).length
  const pendingGuests = guestDetails.filter(guest => !guest.verified).length

  if (loading) {
    return <div className="flex items-center justify-center p-8">جاري التحميل...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">إدارة المنظمات والنزلاء</h2>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 font-medium">خطأ: {error}</p>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">نظرة عامة</TabsTrigger>
          <TabsTrigger value="organizations">المنظمات</TabsTrigger>
          <TabsTrigger value="guests">بيانات النزلاء</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>المنظمات النشطة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{activeOrganizations}</div>
                <p className="text-xs text-muted-foreground">من أصل {organizations.length} منظمة</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>إجمالي النزلاء</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{totalGuests}</div>
                <p className="text-xs text-muted-foreground">إجمالي المسجلين</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>النزلاء المؤكدون</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{verifiedGuests}</div>
                <p className="text-xs text-muted-foreground">بيانات مؤكدة</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>في انتظار التأكيد</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{pendingGuests}</div>
                <p className="text-xs text-muted-foreground">تحتاج تأكيد</p>
              </CardContent>
            </Card>
          </div>

          {/* Country Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>توزيع النزلاء حسب الدولة</CardTitle>
              <CardDescription>عدد النزلاء المسجلين من كل دولة</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(
                  guestDetails.reduce((acc, guest) => {
                    acc[guest.country] = (acc[guest.country] || 0) + 1
                    return acc
                  }, {} as Record<string, number>)
                ).map(([country, count]) => (
                  <div key={country} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className="text-2xl">
                        {country === 'SA' ? '🇸🇦' :
                         country === 'AE' ? '🇦🇪' :
                         country === 'EG' ? '🇪🇬' :
                         country === 'JO' ? '🇯🇴' :
                         country === 'KW' ? '🇰🇼' :
                         country === 'QA' ? '🇶🇦' :
                         country === 'BH' ? '🇧🇭' :
                         country === 'OM' ? '🇴🇲' : '🌍'}
                      </div>
                      <span className="font-medium">{country}</span>
                    </div>
                    <Badge variant="outline">{count} نزيل</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="organizations" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">إدارة المنظمات</h3>
            <Dialog open={showOrganizationDialog} onOpenChange={setShowOrganizationDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetOrganizationForm}>إضافة منظمة جديدة</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingOrganization ? 'تعديل المنظمة' : 'إضافة منظمة جديدة'}
                  </DialogTitle>
                  <DialogDescription>
                    املأ المعلومات التالية لإضافة منظمة جديدة
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="orgName">اسم المنظمة</Label>
                    <Input
                      id="orgName"
                      value={organizationForm.name}
                      onChange={(e) => setOrganizationForm({ ...organizationForm, name: e.target.value })}
                      placeholder="مثال: شركة الرحلات الذهبية"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">وصف المنظمة</Label>
                    <Textarea
                      id="description"
                      value={organizationForm.description}
                      onChange={(e) => setOrganizationForm({ ...organizationForm, description: e.target.value })}
                      placeholder="وصف تفصيلي للمنظمة..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="email">البريد الإلكتروني</Label>
                      <Input
                        id="email"
                        type="email"
                        value={organizationForm.email}
                        onChange={(e) => setOrganizationForm({ ...organizationForm, email: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="phone">رقم الهاتف</Label>
                      <Input
                        id="phone"
                        value={organizationForm.phone}
                        onChange={(e) => setOrganizationForm({ ...organizationForm, phone: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="address">العنوان</Label>
                    <Textarea
                      id="address"
                      value={organizationForm.address}
                      onChange={(e) => setOrganizationForm({ ...organizationForm, address: e.target.value })}
                      placeholder="عنوان المنظمة الكامل..."
                      rows={2}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="city">المدينة</Label>
                      <Input
                        id="city"
                        value={organizationForm.city}
                        onChange={(e) => setOrganizationForm({ ...organizationForm, city: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="country">الدولة</Label>
                      <Select value={organizationForm.country} onValueChange={(value) => setOrganizationForm({ ...organizationForm, country: value })}>
                        <SelectTrigger>
                          <SelectValue placeholder="اختر الدولة" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="SA">السعودية</SelectItem>
                          <SelectItem value="AE">الإمارات</SelectItem>
                          <SelectItem value="EG">مصر</SelectItem>
                          <SelectItem value="JO">الأردن</SelectItem>
                          <SelectItem value="KW">الكويت</SelectItem>
                          <SelectItem value="QA">قطر</SelectItem>
                          <SelectItem value="BH">البحرين</SelectItem>
                          <SelectItem value="OM">عمان</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="website">الموقع الإلكتروني</Label>
                      <Input
                        id="website"
                        value={organizationForm.website}
                        onChange={(e) => setOrganizationForm({ ...organizationForm, website: e.target.value })}
                        placeholder="https://example.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="logo">رابط الشعار</Label>
                      <Input
                        id="logo"
                        value={organizationForm.logo}
                        onChange={(e) => setOrganizationForm({ ...organizationForm, logo: e.target.value })}
                        placeholder="https://example.com/logo.png"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="contactPerson">الشخص المسؤول</Label>
                      <Input
                        id="contactPerson"
                        value={organizationForm.contactPerson}
                        onChange={(e) => setOrganizationForm({ ...organizationForm, contactPerson: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="taxId">الرقم الضريبي</Label>
                      <Input
                        id="taxId"
                        value={organizationForm.taxId}
                        onChange={(e) => setOrganizationForm({ ...organizationForm, taxId: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="isActive"
                      checked={organizationForm.isActive}
                      onCheckedChange={(checked) => setOrganizationForm({ ...organizationForm, isActive: checked })}
                    />
                    <Label htmlFor="isActive">منظمة نشطة</Label>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowOrganizationDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveOrganization}>
                    {editingOrganization ? 'تحديث' : 'إضافة'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة المنظمات</CardTitle>
              <CardDescription>إدارة جميع المنظمات والشركات المسجلة</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>اسم المنظمة</TableHead>
                    <TableHead>البريد الإلكتروني</TableHead>
                    <TableHead>الهاتف</TableHead>
                    <TableHead>المدينة</TableHead>
                    <TableHead>الشخص المسؤول</TableHead>
                    <TableHead>عدد النزلاء</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {organizations.map((organization) => (
                    <TableRow key={organization.id}>
                      <TableCell className="font-medium">{organization.name}</TableCell>
                      <TableCell>{organization.email || '-'}</TableCell>
                      <TableCell>{organization.phone || '-'}</TableCell>
                      <TableCell>{organization.city || '-'}</TableCell>
                      <TableCell>{organization.contactPerson || '-'}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{organization.guestCount}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={organization.isActive ? "default" : "secondary"}>
                          {organization.isActive ? 'نشط' : 'غير نشط'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editOrganization(organization)}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant={organization.isActive ? "destructive" : "default"}
                            onClick={() => toggleOrganizationStatus(organization.id, organization.isActive)}
                          >
                            {organization.isActive ? 'إيقاف' : 'تفعيل'}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteOrganization(organization.id)}
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

        <TabsContent value="guests" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">بيانات النزلاء</h3>
            <Dialog open={showGuestDialog} onOpenChange={setShowGuestDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetGuestForm}>إضافة نزيل جديد</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingGuest ? 'تعديل بيانات النزيل' : 'إضافة نزيل جديد'}
                  </DialogTitle>
                  <DialogDescription>
                    املأ بيانات النزيل الجديد
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="organization">المنظمة</Label>
                    <Select value={guestForm.organizationId} onValueChange={(value) => setGuestForm({ ...guestForm, organizationId: value })}>
                      <SelectTrigger>
                        <SelectValue placeholder="اختر منظمة (اختياري)" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="">بدون منظمة</SelectItem>
                        {organizations.filter(org => org.isActive).map(org => (
                          <SelectItem key={org.id} value={org.id}>{org.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="fullName">الاسم الكامل</Label>
                    <Input
                      id="fullName"
                      value={guestForm.fullName}
                      onChange={(e) => setGuestForm({ ...guestForm, fullName: e.target.value })}
                      placeholder="الاسم الثلاثي"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="nationalId">الرقم القومي</Label>
                      <Input
                        id="nationalId"
                        value={guestForm.nationalId}
                        onChange={(e) => setGuestForm({ ...guestForm, nationalId: e.target.value })}
                        placeholder="رقم الهوية"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="passportNumber">رقم الجواز</Label>
                      <Input
                        id="passportNumber"
                        value={guestForm.passportNumber}
                        onChange={(e) => setGuestForm({ ...guestForm, passportNumber: e.target.value })}
                        placeholder="رقم جواز السفر"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="phoneNumber">رقم الهاتف</Label>
                      <Input
                        id="phoneNumber"
                        value={guestForm.phoneNumber}
                        onChange={(e) => setGuestForm({ ...guestForm, phoneNumber: e.target.value })}
                        placeholder="+966xxxxxxxxx"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="guestCount">عدد الأفراد</Label>
                      <Input
                        id="guestCount"
                        type="number"
                        min="1"
                        value={guestForm.guestCount}
                        onChange={(e) => setGuestForm({ ...guestForm, guestCount: parseInt(e.target.value) })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="city">المدينة</Label>
                      <Input
                        id="city"
                        value={guestForm.city}
                        onChange={(e) => setGuestForm({ ...guestForm, city: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="country">الدولة</Label>
                      <Select value={guestForm.country} onValueChange={(value) => setGuestForm({ ...guestForm, country: value })}>
                        <SelectTrigger>
                          <SelectValue placeholder="اختر الدولة" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="SA">السعودية</SelectItem>
                          <SelectItem value="AE">الإمارات</SelectItem>
                          <SelectItem value="EG">مصر</SelectItem>
                          <SelectItem value="JO">الأردن</SelectItem>
                          <SelectItem value="KW">الكويت</SelectItem>
                          <SelectItem value="QA">قطر</SelectItem>
                          <SelectItem value="BH">البحرين</SelectItem>
                          <SelectItem value="OM">عمان</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="checkInDate">تاريخ الوصول</Label>
                      <Input
                        id="checkInDate"
                        type="date"
                        value={guestForm.checkInDate}
                        onChange={(e) => setGuestForm({ ...guestForm, checkInDate: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="checkOutDate">تاريخ المغادرة</Label>
                      <Input
                        id="checkOutDate"
                        type="date"
                        value={guestForm.checkOutDate}
                        onChange={(e) => setGuestForm({ ...guestForm, checkOutDate: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="specialRequests">طلبات خاصة</Label>
                    <Textarea
                      id="specialRequests"
                      value={guestForm.specialRequests}
                      onChange={(e) => setGuestForm({ ...guestForm, specialRequests: e.target.value })}
                      placeholder="أي طلبات خاصة أو احتياجات خاصة..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="emergencyContact">جهة الاتصال الطارئ</Label>
                      <Input
                        id="emergencyContact"
                        value={guestForm.emergencyContact}
                        onChange={(e) => setGuestForm({ ...guestForm, emergencyContact: e.target.value })}
                        placeholder="اسم جهة الاتصال"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="emergencyPhone">هاتف الطوارئ</Label>
                      <Input
                        id="emergencyPhone"
                        value={guestForm.emergencyPhone}
                        onChange={(e) => setGuestForm({ ...guestForm, emergencyPhone: e.target.value })}
                        placeholder="+966xxxxxxxxx"
                      />
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="verified"
                      checked={guestForm.verified}
                      onCheckedChange={(checked) => setGuestForm({ ...guestForm, verified: checked })}
                    />
                    <Label htmlFor="verified">بيانات مؤكدة</Label>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowGuestDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveGuest}>
                    {editingGuest ? 'تحديث' : 'إضافة'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>بيانات النزلاء</CardTitle>
              <CardDescription>إدارة بيانات وحالة جميع النزلاء المسجلين</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>الاسم</TableHead>
                    <TableHead>الهاتف</TableHead>
                    <TableHead>المنظمة</TableHead>
                    <TableHead>البلد</TableHead>
                    <TableHead>فترة الإقامة</TableHead>
                    <TableHead>عدد الأفراد</TableHead>
                    <TableHead>التأكيد</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {guestDetails.map((guest) => (
                    <TableRow key={guest.id}>
                      <TableCell className="font-medium">{guest.fullName}</TableCell>
                      <TableCell>{guest.phoneNumber}</TableCell>
                      <TableCell>
                        {guest.organization ? (
                          <Badge variant="outline">{guest.organization.name}</Badge>
                        ) : (
                          <span className="text-muted-foreground">فردي</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          <span>
                            {guest.country === 'SA' ? '🇸🇦' :
                             guest.country === 'AE' ? '🇦🇪' :
                             guest.country === 'EG' ? '🇪🇬' :
                             guest.country === 'JO' ? '🇯🇴' :
                             guest.country === 'KW' ? '🇰🇼' :
                             guest.country === 'QA' ? '🇶🇦' :
                             guest.country === 'BH' ? '🇧🇭' :
                             guest.country === 'OM' ? '🇴🇲' : '🌍'}
                          </span>
                          <span>{guest.country}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        {new Date(guest.checkInDate).toLocaleDateString('ar')} - {new Date(guest.checkOutDate).toLocaleDateString('ar')}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{guest.guestCount}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={guest.verified ? "default" : "secondary"}>
                          {guest.verified ? 'مؤكد' : 'في انتظار'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editGuest(guest)}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant={guest.verified ? "destructive" : "default"}
                            onClick={() => toggleGuestVerification(guest.id, guest.verified)}
                          >
                            {guest.verified ? 'إلغاء التأكيد' : 'تأكيد'}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteGuest(guest.id)}
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
      </Tabs>
    </div>
  )
}