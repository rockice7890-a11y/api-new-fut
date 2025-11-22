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

interface PromotionImage {
  id: string
  hotelId: string
  hotel: { name: string }
  imageUrl: string
  title: string
  description?: string
  altText?: string
  displayOrder: number
  isActive: boolean
  startDate?: string
  endDate?: string
  createdAt: string
  updatedAt: string
}

interface Discount {
  id: string
  hotelId: string
  hotel: { name: string }
  code: string
  type: string
  value: number
  description?: string
  minStay?: number
  maxStay?: number
  minPrice?: number
  maxPrice?: number
  validFrom: string
  validUntil: string
  usageLimit?: number
  used: number
  createdAt: string
  updatedAt: string
}

export default function PromotionManagement() {
  const [promotionImages, setPromotionImages] = useState<PromotionImage[]>([])
  const [discounts, setDiscounts] = useState<Discount[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('images')

  // Promotion image dialog state
  const [showImageDialog, setShowImageDialog] = useState(false)
  const [editingImage, setEditingImage] = useState<PromotionImage | null>(null)
  const [imageForm, setImageForm] = useState({
    hotelId: '',
    imageUrl: '',
    title: '',
    description: '',
    altText: '',
    displayOrder: 0,
    isActive: true,
    startDate: '',
    endDate: ''
  })

  // Discount dialog state
  const [showDiscountDialog, setShowDiscountDialog] = useState(false)
  const [editingDiscount, setEditingDiscount] = useState<Discount | null>(null)
  const [discountForm, setDiscountForm] = useState({
    hotelId: '',
    code: '',
    type: 'PERCENTAGE',
    value: 0,
    description: '',
    minStay: '',
    maxStay: '',
    minPrice: '',
    maxPrice: '',
    validFrom: '',
    validUntil: '',
    usageLimit: ''
  })

  const discountTypes = [
    { value: 'PERCENTAGE', label: 'نسبة مئوية' },
    { value: 'FIXED_AMOUNT', label: 'مبلغ ثابت' },
    { value: 'EARLY_BIRD', label: 'الحجز المبكر' },
    { value: 'LOYALTY', label: 'ولاء العملاء' },
    { value: 'SEASONAL', label: 'موسمي' }
  ]

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)

      // Fetch promotion images
      const imagesResponse = await fetch('/api/promotions')
      if (imagesResponse.ok) {
        const imagesData = await imagesResponse.json()
        if (imagesData.status === 'success') {
          setPromotionImages(imagesData.data)
        }
      }

      // Fetch discounts
      const discountsResponse = await fetch('/api/discounts')
      if (discountsResponse.ok) {
        const discountsData = await discountsResponse.json()
        if (discountsData.status === 'success') {
          setDiscounts(discountsData.data)
        }
      }

      setError(null)
    } catch (error: any) {
      console.error('Error fetching promotion data:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  // Promotion image operations
  const saveImage = async () => {
    try {
      const formData = {
        ...imageForm,
        displayOrder: parseInt(imageForm.displayOrder.toString())
      }

      const url = editingImage ? `/api/promotions/${editingImage.id}` : '/api/promotions'
      const method = editingImage ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowImageDialog(false)
        resetImageForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteImage = async (id: string) => {
    try {
      const response = await fetch(`/api/promotions/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const toggleImageStatus = async (id: string, currentStatus: boolean) => {
    try {
      const response = await fetch(`/api/promotions/${id}/toggle`, {
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

  // Discount operations
  const saveDiscount = async () => {
    try {
      const formData = {
        ...discountForm,
        minStay: discountForm.minStay ? parseInt(discountForm.minStay) : null,
        maxStay: discountForm.maxStay ? parseInt(discountForm.maxStay) : null,
        minPrice: discountForm.minPrice ? parseFloat(discountForm.minPrice) : null,
        maxPrice: discountForm.maxPrice ? parseFloat(discountForm.maxPrice) : null,
        usageLimit: discountForm.usageLimit ? parseInt(discountForm.usageLimit) : null
      }

      const url = editingDiscount ? `/api/discounts/${editingDiscount.id}` : '/api/discounts'
      const method = editingDiscount ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowDiscountDialog(false)
        resetDiscountForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteDiscount = async (id: string) => {
    try {
      const response = await fetch(`/api/discounts/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const resetImageForm = () => {
    setImageForm({
      hotelId: '',
      imageUrl: '',
      title: '',
      description: '',
      altText: '',
      displayOrder: 0,
      isActive: true,
      startDate: '',
      endDate: ''
    })
    setEditingImage(null)
  }

  const resetDiscountForm = () => {
    setDiscountForm({
      hotelId: '',
      code: '',
      type: 'PERCENTAGE',
      value: 0,
      description: '',
      minStay: '',
      maxStay: '',
      minPrice: '',
      maxPrice: '',
      validFrom: '',
      validUntil: '',
      usageLimit: ''
    })
    setEditingDiscount(null)
  }

  const editImage = (image: PromotionImage) => {
    setImageForm({
      hotelId: image.hotelId,
      imageUrl: image.imageUrl,
      title: image.title,
      description: image.description || '',
      altText: image.altText || '',
      displayOrder: image.displayOrder,
      isActive: image.isActive,
      startDate: image.startDate ? image.startDate.split('T')[0] : '',
      endDate: image.endDate ? image.endDate.split('T')[0] : ''
    })
    setEditingImage(image)
    setShowImageDialog(true)
  }

  const editDiscount = (discount: Discount) => {
    setDiscountForm({
      hotelId: discount.hotelId,
      code: discount.code,
      type: discount.type,
      value: discount.value,
      description: discount.description || '',
      minStay: discount.minStay?.toString() || '',
      maxStay: discount.maxStay?.toString() || '',
      minPrice: discount.minPrice?.toString() || '',
      maxPrice: discount.maxPrice?.toString() || '',
      validFrom: discount.validFrom.split('T')[0],
      validUntil: discount.validUntil.split('T')[0],
      usageLimit: discount.usageLimit?.toString() || ''
    })
    setEditingDiscount(discount)
    setShowDiscountDialog(true)
  }

  const isDiscountExpired = (discount: Discount) => {
    return new Date(discount.validUntil) < new Date()
  }

  const isDiscountActive = (discount: Discount) => {
    const now = new Date()
    const validFrom = new Date(discount.validFrom)
    const validUntil = new Date(discount.validUntil)
    return now >= validFrom && now <= validUntil && 
           (!discount.usageLimit || discount.used < discount.usageLimit)
  }

  // Stats calculation
  const activeImages = promotionImages.filter(img => img.isActive).length
  const totalDiscounts = discounts.length
  const activeDiscounts = discounts.filter(d => isDiscountActive(d)).length
  const expiredDiscounts = discounts.filter(d => isDiscountExpired(d)).length

  if (loading) {
    return <div className="flex items-center justify-center p-8">جاري التحميل...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">إدارة العروض والترويج</h2>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 font-medium">خطأ: {error}</p>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">نظرة عامة</TabsTrigger>
          <TabsTrigger value="images">صور الترويج</TabsTrigger>
          <TabsTrigger value="discounts">الخصومات والعروض</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>الصور النشطة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{activeImages}</div>
                <p className="text-xs text-muted-foreground">من أصل {promotionImages.length} صورة</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>إجمالي الخصومات</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{totalDiscounts}</div>
                <p className="text-xs text-muted-foreground">جميع العروض</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>العروض النشطة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-green-600">{activeDiscounts}</div>
                <p className="text-xs text-muted-foreground">صالحة للاستخدام</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>العروض المنتهية</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-red-600">{expiredDiscounts}</div>
                <p className="text-xs text-muted-foreground">انتهت صلاحيتها</p>
              </CardContent>
            </Card>
          </div>

          {/* Usage Statistics */}
          <Card>
            <CardHeader>
              <CardTitle>إحصائيات الاستخدام</CardTitle>
              <CardDescription>استخدام الخصومات والعروض</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {discounts.slice(0, 5).map((discount) => {
                  const usagePercentage = discount.usageLimit ? (discount.used / discount.usageLimit) * 100 : 0
                  return (
                    <div key={discount.id} className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="font-medium">{discount.code}</span>
                        <span className="text-sm text-muted-foreground">
                          {discount.used}
                          {discount.usageLimit ? ` / ${discount.usageLimit}` : ''} استخدام
                        </span>
                      </div>
                      {discount.usageLimit && (
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div 
                            className={`h-2 rounded-full ${usagePercentage >= 100 ? 'bg-red-600' : usagePercentage >= 80 ? 'bg-yellow-600' : 'bg-green-600'}`}
                            style={{ width: `${Math.min(usagePercentage, 100)}%` }}
                          ></div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="images" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">صور الترويج</h3>
            <Dialog open={showImageDialog} onOpenChange={setShowImageDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetImageForm}>إضافة صورة جديدة</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingImage ? 'تعديل صورة الترويج' : 'إضافة صورة ترويج جديدة'}
                  </DialogTitle>
                  <DialogDescription>
                    إضافة أو تعديل صورة ترويجية للفندق
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="hotel">الفندق</Label>
                    <Select value={imageForm.hotelId} onValueChange={(value) => setImageForm({ ...imageForm, hotelId: value })}>
                      <SelectTrigger>
                        <SelectValue placeholder="اختر فندق" />
                      </SelectTrigger>
                      <SelectContent>
                        {/* You would populate this with actual hotel data */}
                        <SelectItem value="hotel1">فندق الرياض الفاخر</SelectItem>
                        <SelectItem value="hotel2">منتجع دبي海滩</SelectItem>
                        <SelectItem value="hotel3">فندق القاهرة التاريخي</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="imageUrl">رابط الصورة</Label>
                    <Input
                      id="imageUrl"
                      value={imageForm.imageUrl}
                      onChange={(e) => setImageForm({ ...imageForm, imageUrl: e.target.value })}
                      placeholder="https://example.com/promotion.jpg"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="title">عنوان الصورة</Label>
                    <Input
                      id="title"
                      value={imageForm.title}
                      onChange={(e) => setImageForm({ ...imageForm, title: e.target.value })}
                      placeholder="عنوان جذاب للصورة"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">وصف الصورة</Label>
                    <Textarea
                      id="description"
                      value={imageForm.description}
                      onChange={(e) => setImageForm({ ...imageForm, description: e.target.value })}
                      placeholder="وصف تفصيلي للعروض والخصومات..."
                      rows={3}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="altText">النص البديل (للوصول)</Label>
                    <Input
                      id="altText"
                      value={imageForm.altText}
                      onChange={(e) => setImageForm({ ...imageForm, altText: e.target.value })}
                      placeholder="وصف الصورة للمكفوفين"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="displayOrder">ترتيب العرض</Label>
                      <Input
                        id="displayOrder"
                        type="number"
                        value={imageForm.displayOrder}
                        onChange={(e) => setImageForm({ ...imageForm, displayOrder: parseInt(e.target.value) })}
                        placeholder="0"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>الحالة</Label>
                      <div className="flex items-center space-x-2 mt-2">
                        <Switch
                          id="isActive"
                          checked={imageForm.isActive}
                          onCheckedChange={(checked) => setImageForm({ ...imageForm, isActive: checked })}
                        />
                        <Label htmlFor="isActive">صورة نشطة</Label>
                      </div>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="startDate">تاريخ البداية</Label>
                      <Input
                        id="startDate"
                        type="date"
                        value={imageForm.startDate}
                        onChange={(e) => setImageForm({ ...imageForm, startDate: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="endDate">تاريخ النهاية</Label>
                      <Input
                        id="endDate"
                        type="date"
                        value={imageForm.endDate}
                        onChange={(e) => setImageForm({ ...imageForm, endDate: e.target.value })}
                      />
                    </div>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowImageDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveImage}>
                    {editingImage ? 'تحديث' : 'إضافة'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة صور الترويج</CardTitle>
              <CardDescription>إدارة جميع صور الترويج والعروض</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>الصورة</TableHead>
                    <TableHead>العنوان</TableHead>
                    <TableHead>الفندق</TableHead>
                    <TableHead>الترتيب</TableHead>
                    <TableHead>تاريخ البداية</TableHead>
                    <TableHead>تاريخ النهاية</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {promotionImages.map((image) => (
                    <TableRow key={image.id}>
                      <TableCell>
                        <div className="w-16 h-16 bg-gray-100 rounded-lg overflow-hidden">
                          <img 
                            src={image.imageUrl} 
                            alt={image.altText || image.title}
                            className="w-full h-full object-cover"
                            onError={(e) => {
                              e.currentTarget.style.display = 'none'
                            }}
                          />
                        </div>
                      </TableCell>
                      <TableCell className="font-medium">{image.title}</TableCell>
                      <TableCell>{image.hotel?.name || '-'}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{image.displayOrder}</Badge>
                      </TableCell>
                      <TableCell>
                        {image.startDate ? new Date(image.startDate).toLocaleDateString('ar') : '-'}
                      </TableCell>
                      <TableCell>
                        {image.endDate ? new Date(image.endDate).toLocaleDateString('ar') : '-'}
                      </TableCell>
                      <TableCell>
                        <Badge variant={image.isActive ? "default" : "secondary"}>
                          {image.isActive ? 'نشط' : 'غير نشط'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editImage(image)}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant={image.isActive ? "destructive" : "default"}
                            onClick={() => toggleImageStatus(image.id, image.isActive)}
                          >
                            {image.isActive ? 'إيقاف' : 'تفعيل'}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteImage(image.id)}
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

        <TabsContent value="discounts" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">الخصومات والعروض</h3>
            <Dialog open={showDiscountDialog} onOpenChange={setShowDiscountDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetDiscountForm}>إنشاء خصم جديد</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingDiscount ? 'تعديل الخصم' : 'إنشاء خصم جديد'}
                  </DialogTitle>
                  <DialogDescription>
                    إنشاء خصم أو عرض جديد للعملاء
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="discountHotel">الفندق</Label>
                      <Select value={discountForm.hotelId} onValueChange={(value) => setDiscountForm({ ...discountForm, hotelId: value })}>
                        <SelectTrigger>
                          <SelectValue placeholder="اختر فندق" />
                        </SelectTrigger>
                        <SelectContent>
                          {/* You would populate this with actual hotel data */}
                          <SelectItem value="hotel1">فندق الرياض الفاخر</SelectItem>
                          <SelectItem value="hotel2">منتجع دبي海滩</SelectItem>
                          <SelectItem value="hotel3">فندق القاهرة التاريخي</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="code">كود الخصم</Label>
                      <Input
                        id="code"
                        value={discountForm.code}
                        onChange={(e) => setDiscountForm({ ...discountForm, code: e.target.value.toUpperCase() })}
                        placeholder="SUMMER2024"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="type">نوع الخصم</Label>
                      <Select value={discountForm.type} onValueChange={(value) => setDiscountForm({ ...discountForm, type: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {discountTypes.map(type => (
                            <SelectItem key={type.value} value={type.value}>
                              {type.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="value">قيمة الخصم</Label>
                      <Input
                        id="value"
                        type="number"
                        step="0.01"
                        value={discountForm.value}
                        onChange={(e) => setDiscountForm({ ...discountForm, value: parseFloat(e.target.value) })}
                        placeholder={
                          discountForm.type === 'PERCENTAGE' ? '20' : 
                          discountForm.type === 'FIXED_AMOUNT' ? '100' : '0'
                        }
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">وصف الخصم</Label>
                    <Textarea
                      id="description"
                      value={discountForm.description}
                      onChange={(e) => setDiscountForm({ ...discountForm, description: e.target.value })}
                      placeholder="وصف تفصيلي للخصم والعرض..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="minStay">أقل مدة إقامة (ليل)</Label>
                      <Input
                        id="minStay"
                        type="number"
                        value={discountForm.minStay}
                        onChange={(e) => setDiscountForm({ ...discountForm, minStay: e.target.value })}
                        placeholder="اختياري"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="maxStay">أقصى مدة إقامة (ليل)</Label>
                      <Input
                        id="maxStay"
                        type="number"
                        value={discountForm.maxStay}
                        onChange={(e) => setDiscountForm({ ...discountForm, maxStay: e.target.value })}
                        placeholder="اختياري"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="minPrice">أقل سعر للحجز</Label>
                      <Input
                        id="minPrice"
                        type="number"
                        step="0.01"
                        value={discountForm.minPrice}
                        onChange={(e) => setDiscountForm({ ...discountForm, minPrice: e.target.value })}
                        placeholder="اختياري"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="maxPrice">أقصى سعر للحجز</Label>
                      <Input
                        id="maxPrice"
                        type="number"
                        step="0.01"
                        value={discountForm.maxPrice}
                        onChange={(e) => setDiscountForm({ ...discountForm, maxPrice: e.target.value })}
                        placeholder="اختياري"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="validFrom">صالح من</Label>
                      <Input
                        id="validFrom"
                        type="date"
                        value={discountForm.validFrom}
                        onChange={(e) => setDiscountForm({ ...discountForm, validFrom: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="validUntil">صالح حتى</Label>
                      <Input
                        id="validUntil"
                        type="date"
                        value={discountForm.validUntil}
                        onChange={(e) => setDiscountForm({ ...discountForm, validUntil: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="usageLimit">حد الاستخدام (اختياري)</Label>
                    <Input
                      id="usageLimit"
                      type="number"
                      value={discountForm.usageLimit}
                      onChange={(e) => setDiscountForm({ ...discountForm, usageLimit: e.target.value })}
                      placeholder="اتركه فارغاً للحد غير المحدود"
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowDiscountDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveDiscount}>
                    {editingDiscount ? 'تحديث' : 'إنشاء'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة الخصومات</CardTitle>
              <CardDescription>إدارة جميع الخصومات والعروض المتاحة</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>الكود</TableHead>
                    <TableHead>الفندق</TableHead>
                    <TableHead>نوع الخصم</TableHead>
                    <TableHead>القيمة</TableHead>
                    <TableHead>الاستخدام</TableHead>
                    <TableHead>الصلاحية</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {discounts.map((discount) => {
                    const isExpired = isDiscountExpired(discount)
                    const isActive = isDiscountActive(discount)
                    const usagePercentage = discount.usageLimit ? (discount.used / discount.usageLimit) * 100 : 0

                    return (
                      <TableRow key={discount.id}>
                        <TableCell className="font-mono font-bold">{discount.code}</TableCell>
                        <TableCell>{discount.hotel?.name || '-'}</TableCell>
                        <TableCell>
                          <Badge variant="outline">
                            {discountTypes.find(t => t.value === discount.type)?.label || discount.type}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {discount.type === 'PERCENTAGE' ? `${discount.value}%` : `$${discount.value}`}
                        </TableCell>
                        <TableCell>
                          <div className="space-y-1">
                            <div className="text-sm">
                              {discount.used}
                              {discount.usageLimit ? ` / ${discount.usageLimit}` : ''} استخدام
                            </div>
                            {discount.usageLimit && (
                              <div className="w-16 bg-gray-200 rounded-full h-1">
                                <div 
                                  className={`h-1 rounded-full ${usagePercentage >= 100 ? 'bg-red-600' : usagePercentage >= 80 ? 'bg-yellow-600' : 'bg-green-600'}`}
                                  style={{ width: `${Math.min(usagePercentage, 100)}%` }}
                                ></div>
                              </div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="text-sm">
                            <div>{new Date(discount.validFrom).toLocaleDateString('ar')}</div>
                            <div>إلى {new Date(discount.validUntil).toLocaleDateString('ar')}</div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant={
                            isExpired ? 'destructive' : 
                            isActive ? 'default' : 'secondary'
                          }>
                            {isExpired ? 'منتهي' : isActive ? 'نشط' : 'غير نشط'}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => editDiscount(discount)}
                            >
                              تعديل
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => deleteDiscount(discount.id)}
                            >
                              حذف
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}