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

interface SystemConfig {
  id: string
  key: string
  value: string
  type: string
  description?: string
  category?: string
  isEditable: boolean
  updatedBy?: string
  updatedAt: string
  createdAt: string
}

interface QRCode {
  id: string
  userId?: string
  user?: {
    firstName: string
    lastName: string
    email: string
  }
  type: string
  code: string
  data?: any
  expiresAt?: string
  usedCount: number
  maxUsage?: number
  isActive: boolean
  createdAt: string
  updatedAt: string
}

interface BiometricAuth {
  id: string
  userId: string
  user: {
    firstName: string
    lastName: string
    email: string
  }
  fingerprintEnabled: boolean
  faceEnabled: boolean
  voiceEnabled: boolean
  isVerified: boolean
  lastVerified?: string
  hasBackupAuth: boolean
  createdAt: string
  updatedAt: string
}

interface Maintenance {
  id: string
  title: string
  description: string
  startTime: string
  endTime: string
  severity: string
  affectedServices: string[]
  status: string
  createdBy: string
  createdAt: string
  updatedAt: string
}

export default function SystemConfiguration() {
  const [config, setConfig] = useState<SystemConfig[]>([])
  const [qrCodes, setQrCodes] = useState<QRCode[]>([])
  const [biometricAuth, setBiometricAuth] = useState<BiometricAuth[]>([])
  const [maintenance, setMaintenance] = useState<Maintenance[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('config')

  // Config dialog state
  const [showConfigDialog, setShowConfigDialog] = useState(false)
  const [editingConfig, setEditingConfig] = useState<SystemConfig | null>(null)
  const [configForm, setConfigForm] = useState({
    key: '',
    value: '',
    type: 'string',
    description: '',
    category: '',
    isEditable: true
  })

  // QR Code dialog state
  const [showQRDialog, setShowQRDialog] = useState(false)
  const [qrForm, setQRForm] = useState({
    userId: '',
    type: 'ROOM_ACCESS',
    code: '',
    data: '',
    expiresAt: '',
    maxUsage: ''
  })

  // Maintenance dialog state
  const [showMaintenanceDialog, setShowMaintenanceDialog] = useState(false)
  const [editingMaintenance, setEditingMaintenance] = useState<Maintenance | null>(null)
  const [maintenanceForm, setMaintenanceForm] = useState({
    title: '',
    description: '',
    startTime: '',
    endTime: '',
    severity: 'LOW',
    affectedServices: [] as string[],
    status: 'SCHEDULED'
  })

  const qrCodeTypes = [
    'ROOM_ACCESS', 'CHECK_IN', 'CHECK_OUT', 'RESTAURANT', 
    'SPA_BOOKING', 'SERVICE', 'DISCOUNT', 'GAME', 'CONTEST'
  ]

  const maintenanceServices = [
    'bookings', 'payments', 'notifications', 'reports', 
    'users', 'hotels', 'rooms', 'all'
  ]

  const severityLevels = [
    { value: 'LOW', label: 'منخفضة' },
    { value: 'MEDIUM', label: 'متوسطة' },
    { value: 'HIGH', label: 'عالية' },
    { value: 'CRITICAL', label: 'حرجة' }
  ]

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)

      // Fetch system config
      const configResponse = await fetch('/api/admin/config')
      if (configResponse.ok) {
        const configData = await configResponse.json()
        if (configData.status === 'success') {
          setConfig(configData.data)
        }
      }

      // Fetch QR codes
      const qrResponse = await fetch('/api/qr-codes')
      if (qrResponse.ok) {
        const qrData = await qrResponse.json()
        if (qrData.status === 'success') {
          setQrCodes(qrData.data)
        }
      }

      // Fetch biometric auth
      const biometricResponse = await fetch('/api/auth/biometric')
      if (biometricResponse.ok) {
        const biometricData = await biometricResponse.json()
        if (biometricData.status === 'success') {
          setBiometricAuth(biometricData.data)
        }
      }

      // Fetch maintenance
      const maintenanceResponse = await fetch('/api/admin/maintenance')
      if (maintenanceResponse.ok) {
        const maintenanceData = await maintenanceResponse.json()
        if (maintenanceData.status === 'success') {
          setMaintenance(maintenanceData.data)
        }
      }

      setError(null)
    } catch (error: any) {
      console.error('Error fetching system data:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  // Config operations
  const saveConfig = async () => {
    try {
      const url = editingConfig ? `/api/admin/config/${editingConfig.id}` : '/api/admin/config'
      const method = editingConfig ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configForm)
      })

      if (response.ok) {
        await fetchData()
        setShowConfigDialog(false)
        resetConfigForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteConfig = async (id: string) => {
    try {
      const response = await fetch(`/api/admin/config/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  // QR Code operations
  const generateQRCode = async () => {
    try {
      const formData = {
        ...qrForm,
        maxUsage: qrForm.maxUsage ? parseInt(qrForm.maxUsage) : null
      }

      const response = await fetch('/api/qr-codes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowQRDialog(false)
        resetQRForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteQRCode = async (id: string) => {
    try {
      const response = await fetch(`/api/qr-codes/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  // Maintenance operations
  const saveMaintenance = async () => {
    try {
      const url = editingMaintenance ? `/api/admin/maintenance/${editingMaintenance.id}` : '/api/admin/maintenance'
      const method = editingMaintenance ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(maintenanceForm)
      })

      if (response.ok) {
        await fetchData()
        setShowMaintenanceDialog(false)
        resetMaintenanceForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteMaintenance = async (id: string) => {
    try {
      const response = await fetch(`/api/admin/maintenance/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const resetConfigForm = () => {
    setConfigForm({
      key: '',
      value: '',
      type: 'string',
      description: '',
      category: '',
      isEditable: true
    })
    setEditingConfig(null)
  }

  const resetQRForm = () => {
    setQRForm({
      userId: '',
      type: 'ROOM_ACCESS',
      code: '',
      data: '',
      expiresAt: '',
      maxUsage: ''
    })
  }

  const resetMaintenanceForm = () => {
    setMaintenanceForm({
      title: '',
      description: '',
      startTime: '',
      endTime: '',
      severity: 'LOW',
      affectedServices: [],
      status: 'SCHEDULED'
    })
    setEditingMaintenance(null)
  }

  const editConfig = (config: SystemConfig) => {
    setConfigForm({
      key: config.key,
      value: config.value,
      type: config.type,
      description: config.description || '',
      category: config.category || '',
      isEditable: config.isEditable
    })
    setEditingConfig(config)
    setShowConfigDialog(true)
  }

  const editMaintenance = (maintenance: Maintenance) => {
    setMaintenanceForm({
      title: maintenance.title,
      description: maintenance.description,
      startTime: maintenance.startTime.split('T')[0] + 'T' + maintenance.startTime.split('T')[1].substring(0, 5),
      endTime: maintenance.endTime.split('T')[0] + 'T' + maintenance.endTime.split('T')[1].substring(0, 5),
      severity: maintenance.severity,
      affectedServices: maintenance.affectedServices,
      status: maintenance.status
    })
    setEditingMaintenance(maintenance)
    setShowMaintenanceDialog(true)
  }

  const toggleService = (service: string) => {
    setMaintenanceForm(prev => ({
      ...prev,
      affectedServices: prev.affectedServices.includes(service)
        ? prev.affectedServices.filter(s => s !== service)
        : [...prev.affectedServices, service]
    }))
  }

  if (loading) {
    return <div className="flex items-center justify-center p-8">جاري التحميل...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">إعدادات النظام والإعدادات المتقدمة</h2>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 font-medium">خطأ: {error}</p>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="config">إعدادات النظام</TabsTrigger>
          <TabsTrigger value="qr">رموز QR</TabsTrigger>
          <TabsTrigger value="biometric">المصادقة الحيوية</TabsTrigger>
          <TabsTrigger value="maintenance">صيانة النظام</TabsTrigger>
        </TabsList>

        <TabsContent value="config" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">إعدادات النظام</h3>
            <Dialog open={showConfigDialog} onOpenChange={setShowConfigDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetConfigForm}>إضافة إعداد جديد</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>
                    {editingConfig ? 'تعديل الإعداد' : 'إضافة إعداد جديد'}
                  </DialogTitle>
                  <DialogDescription>
                    إضافة أو تعديل إعداد نظام عام
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="key">مفتاح الإعداد</Label>
                      <Input
                        id="key"
                        value={configForm.key}
                        onChange={(e) => setConfigForm({ ...configForm, key: e.target.value })}
                        placeholder="مثال: max_file_size"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="type">نوع البيانات</Label>
                      <Select value={configForm.type} onValueChange={(value) => setConfigForm({ ...configForm, type: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="string">نص</SelectItem>
                          <SelectItem value="number">رقم</SelectItem>
                          <SelectItem value="boolean">منطقي</SelectItem>
                          <SelectItem value="json">JSON</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="value">قيمة الإعداد</Label>
                    <Textarea
                      id="value"
                      value={configForm.value}
                      onChange={(e) => setConfigForm({ ...configForm, value: e.target.value })}
                      placeholder="قيمة الإعداد..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="category">الفئة</Label>
                      <Select value={configForm.category} onValueChange={(value) => setConfigForm({ ...configForm, category: value })}>
                        <SelectTrigger>
                          <SelectValue placeholder="اختر فئة" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="SECURITY">الأمان</SelectItem>
                          <SelectItem value="FEATURES">المميزات</SelectItem>
                          <SelectItem value="INTEGRATIONS">التكامل</SelectItem>
                          <SelectItem value="EMAIL">البريد الإلكتروني</SelectItem>
                          <SelectItem value="PAYMENT">الدفع</SelectItem>
                          <SelectItem value="NOTIFICATION">الإشعارات</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>قابل للتعديل</Label>
                      <div className="flex items-center space-x-2 mt-2">
                        <Switch
                          id="isEditable"
                          checked={configForm.isEditable}
                          onCheckedChange={(checked) => setConfigForm({ ...configForm, isEditable: checked })}
                        />
                        <Label htmlFor="isEditable">يمكن تعديله</Label>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">الوصف</Label>
                    <Textarea
                      id="description"
                      value={configForm.description}
                      onChange={(e) => setConfigForm({ ...configForm, description: e.target.value })}
                      placeholder="وصف الإعداد ووظيفته..."
                      rows={2}
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowConfigDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveConfig}>
                    {editingConfig ? 'تحديث' : 'إضافة'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>إعدادات النظام</CardTitle>
              <CardDescription>إدارة إعدادات النظام العامة والتكوين</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>المفتاح</TableHead>
                    <TableHead>القيمة</TableHead>
                    <TableHead>النوع</TableHead>
                    <TableHead>الفئة</TableHead>
                    <TableHead>الوصف</TableHead>
                    <TableHead>آخر تحديث</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {config.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell className="font-mono">{item.key}</TableCell>
                      <TableCell className="max-w-xs truncate">
                        <span className="font-mono text-sm">
                          {item.value.length > 50 ? item.value.substring(0, 50) + '...' : item.value}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{item.type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{item.category || '-'}</Badge>
                      </TableCell>
                      <TableCell className="max-w-xs truncate">{item.description || '-'}</TableCell>
                      <TableCell>{new Date(item.updatedAt).toLocaleDateString('ar')}</TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editConfig(item)}
                            disabled={!item.isEditable}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteConfig(item.id)}
                            disabled={!item.isEditable}
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

        <TabsContent value="qr" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">رموز QR</h3>
            <Dialog open={showQRDialog} onOpenChange={setShowQRDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetQRForm}>إنشاء رمز QR جديد</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>إنشاء رمز QR جديد</DialogTitle>
                  <DialogDescription>
                    إنشاء رمز QR للوصول أو الخدمات
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="qrType">نوع الرمز</Label>
                      <Select value={qrForm.type} onValueChange={(value) => setQRForm({ ...qrForm, type: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {qrCodeTypes.map(type => (
                            <SelectItem key={type} value={type}>
                              {type === 'ROOM_ACCESS' ? 'دخول الغرفة' :
                               type === 'CHECK_IN' ? 'تسجيل الوصول' :
                               type === 'CHECK_OUT' ? 'تسجيل المغادرة' :
                               type === 'RESTAURANT' ? 'طلب مطعم' :
                               type === 'SPA_BOOKING' ? 'حجز سبا' :
                               type === 'SERVICE' ? 'طلب خدمة' :
                               type === 'DISCOUNT' ? 'خصم' :
                               type === 'GAME' ? 'لعبة' :
                               type === 'CONTEST' ? 'مسابقة' : type}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="qrCode">كود QR</Label>
                      <Input
                        id="qrCode"
                        value={qrForm.code}
                        onChange={(e) => setQRForm({ ...qrForm, code: e.target.value })}
                        placeholder="اتركه فارغاً للتوليد التلقائي"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="qrData">بيانات QR</Label>
                    <Textarea
                      id="qrData"
                      value={qrForm.data}
                      onChange={(e) => setQRForm({ ...qrForm, data: e.target.value })}
                      placeholder="بيانات JSON أو نص إضافي..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="expiresAt">تاريخ انتهاء الصلاحية</Label>
                      <Input
                        id="expiresAt"
                        type="datetime-local"
                        value={qrForm.expiresAt}
                        onChange={(e) => setQRForm({ ...qrForm, expiresAt: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="maxUsage">حد الاستخدام</Label>
                      <Input
                        id="maxUsage"
                        type="number"
                        value={qrForm.maxUsage}
                        onChange={(e) => setQRForm({ ...qrForm, maxUsage: e.target.value })}
                        placeholder="اتركه فارغاً للاستخدام غير المحدود"
                      />
                    </div>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowQRDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={generateQRCode}>إنشاء</Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة رموز QR</CardTitle>
              <CardDescription>إدارة جميع رموز QR المنشأة</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>الكود</TableHead>
                    <TableHead>النوع</TableHead>
                    <TableHead>المستخدم</TableHead>
                    <TableHead>الاستخدام</TableHead>
                    <TableHead>انتهاء الصلاحية</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {qrCodes.map((qr) => (
                    <TableRow key={qr.id}>
                      <TableCell className="font-mono text-sm">{qr.code}</TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {qrCodeTypes.find(t => t === qr.type)?.replace('_', ' ') || qr.type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {qr.user ? `${qr.user.firstName} ${qr.user.lastName}` : '-'}
                      </TableCell>
                      <TableCell>
                        {qr.usedCount}
                        {qr.maxUsage ? ` / ${qr.maxUsage}` : ''} استخدام
                      </TableCell>
                      <TableCell>
                        {qr.expiresAt ? new Date(qr.expiresAt).toLocaleDateString('ar') : 'لا ينتهي'}
                      </TableCell>
                      <TableCell>
                        <Badge variant={qr.isActive ? "default" : "secondary"}>
                          {qr.isActive ? 'نشط' : 'غير نشط'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => deleteQRCode(qr.id)}
                        >
                          حذف
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="biometric" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>إدارة المصادقة الحيوية</CardTitle>
              <CardDescription>إدارة إعدادات المصادقة الحيوية للمستخدمين</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>المستخدم</TableHead>
                    <TableHead>بصمة الإصبع</TableHead>
                    <TableHead>التعرف على الوجه</TableHead>
                    <TableHead>الصوت</TableHead>
                    <TableHead>مؤكد</TableHead>
                    <TableHead>آخر تحقق</TableHead>
                    <TableHead>النسخ الاحتياطي</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {biometricAuth.map((bio) => (
                    <TableRow key={bio.id}>
                      <TableCell className="font-medium">
                        {bio.user.firstName} {bio.user.lastName}
                        <div className="text-xs text-muted-foreground">{bio.user.email}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={bio.fingerprintEnabled ? "default" : "secondary"}>
                          {bio.fingerprintEnabled ? 'مفعل' : 'غير مفعل'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={bio.faceEnabled ? "default" : "secondary"}>
                          {bio.faceEnabled ? 'مفعل' : 'غير مفعل'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={bio.voiceEnabled ? "default" : "secondary"}>
                          {bio.voiceEnabled ? 'مفعل' : 'غير مفعل'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={bio.isVerified ? "default" : "destructive"}>
                          {bio.isVerified ? 'مؤكد' : 'غير مؤكد'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {bio.lastVerified ? new Date(bio.lastVerified).toLocaleDateString('ar') : '-'}
                      </TableCell>
                      <TableCell>
                        <Badge variant={bio.hasBackupAuth ? "default" : "secondary"}>
                          {bio.hasBackupAuth ? 'متوفر' : 'غير متوفر'}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="maintenance" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">صيانة النظام</h3>
            <Dialog open={showMaintenanceDialog} onOpenChange={setShowMaintenanceDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetMaintenanceForm}>جدولة صيانة جديدة</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingMaintenance ? 'تعديل جدولة الصيانة' : 'جدولة صيانة جديدة'}
                  </DialogTitle>
                  <DialogDescription>
                    جدولة صيانة أو تحديث للنظام
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="maintenanceTitle">عنوان الصيانة</Label>
                    <Input
                      id="maintenanceTitle"
                      value={maintenanceForm.title}
                      onChange={(e) => setMaintenanceForm({ ...maintenanceForm, title: e.target.value })}
                      placeholder="مثال: تحديث قاعدة البيانات"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="maintenanceDescription">وصف الصيانة</Label>
                    <Textarea
                      id="maintenanceDescription"
                      value={maintenanceForm.description}
                      onChange={(e) => setMaintenanceForm({ ...maintenanceForm, description: e.target.value })}
                      placeholder="وصف تفصيلي لأعمال الصيانة..."
                      rows={3}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="startTime">وقت البداية</Label>
                      <Input
                        id="startTime"
                        type="datetime-local"
                        value={maintenanceForm.startTime}
                        onChange={(e) => setMaintenanceForm({ ...maintenanceForm, startTime: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="endTime">وقت النهاية</Label>
                      <Input
                        id="endTime"
                        type="datetime-local"
                        value={maintenanceForm.endTime}
                        onChange={(e) => setMaintenanceForm({ ...maintenanceForm, endTime: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="severity">مستوى الأولوية</Label>
                      <Select value={maintenanceForm.severity} onValueChange={(value) => setMaintenanceForm({ ...maintenanceForm, severity: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {severityLevels.map(level => (
                            <SelectItem key={level.value} value={level.value}>
                              {level.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="maintenanceStatus">الحالة</Label>
                      <Select value={maintenanceForm.status} onValueChange={(value) => setMaintenanceForm({ ...maintenanceForm, status: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="SCHEDULED">مجدول</SelectItem>
                          <SelectItem value="IN_PROGRESS">قيد التنفيذ</SelectItem>
                          <SelectItem value="COMPLETED">مكتمل</SelectItem>
                          <SelectItem value="CANCELLED">ملغي</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label>الخدمات المتأثرة</Label>
                    <div className="grid grid-cols-2 gap-2">
                      {maintenanceServices.map(service => (
                        <div key={service} className="flex items-center space-x-2">
                          <Switch
                            id={service}
                            checked={maintenanceForm.affectedServices.includes(service)}
                            onCheckedChange={() => toggleService(service)}
                          />
                          <Label htmlFor={service}>
                            {service === 'bookings' ? 'الحجوزات' :
                             service === 'payments' ? 'المدفوعات' :
                             service === 'notifications' ? 'الإشعارات' :
                             service === 'reports' ? 'التقارير' :
                             service === 'users' ? 'المستخدمين' :
                             service === 'hotels' ? 'الفنادق' :
                             service === 'rooms' ? 'الغرف' :
                             service === 'all' ? 'جميع الخدمات' : service}
                          </Label>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowMaintenanceDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveMaintenance}>
                    {editingMaintenance ? 'تحديث' : 'جدولة'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>جدولة الصيانة</CardTitle>
              <CardDescription>إدارة جدولة وأعمال صيانة النظام</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>العنوان</TableHead>
                    <TableHead>الوقت</TableHead>
                    <TableHead>الأولوية</TableHead>
                    <TableHead>الخدمات المتأثرة</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {maintenance.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell className="font-medium">{item.title}</TableCell>
                      <TableCell>
                        <div className="text-sm">
                          <div>من: {new Date(item.startTime).toLocaleString('ar')}</div>
                          <div>إلى: {new Date(item.endTime).toLocaleString('ar')}</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={
                          item.severity === 'CRITICAL' ? 'destructive' :
                          item.severity === 'HIGH' ? 'default' : 
                          item.severity === 'MEDIUM' ? 'secondary' : 'outline'
                        }>
                          {severityLevels.find(s => s.value === item.severity)?.label || item.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {item.affectedServices.map(service => (
                            <Badge key={service} variant="outline" className="text-xs">
                              {service === 'all' ? 'جميع الخدمات' : service}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={
                          item.status === 'COMPLETED' ? 'default' :
                          item.status === 'IN_PROGRESS' ? 'secondary' :
                          item.status === 'CANCELLED' ? 'destructive' : 'outline'
                        }>
                          {item.status === 'SCHEDULED' ? 'مجدول' :
                           item.status === 'IN_PROGRESS' ? 'قيد التنفيذ' :
                           item.status === 'COMPLETED' ? 'مكتمل' : 'ملغي'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editMaintenance(item)}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteMaintenance(item.id)}
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