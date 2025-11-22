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

interface Employee {
  id: string
  firstName: string
  lastName: string
  email: string
  phone?: string
  role: string
  department: string
  employeeId: string
  hireDate: string
  salary: number
  status: string
  address?: string
  emergencyContact?: string
  emergencyPhone?: string
  permissions?: string[]
  createdAt: string
  updatedAt: string
}

interface Payroll {
  id: string
  payrollNumber: string
  hotelId: string
  hotel: { name: string }
  staffId: string
  staff: {
    firstName: string
    lastName: string
    email: string
  }
  baseSalary: number
  bonuses: number
  deductions: number
  netSalary: number
  payPeriodStart: string
  payPeriodEnd: string
  status: string
  paidDate?: string
  bankAccount?: string
  notes?: string
  createdAt: string
}

interface StaffNotification {
  id: string
  hotelId: string
  hotel: { name: string }
  senderId: string
  sender: { firstName: string; lastName: string }
  recipientId: string
  recipient: { firstName: string; lastName: string }
  type: string
  subject: string
  message: string
  priority: string
  isRead: boolean
  readAt?: string
  createdAt: string
}

export default function StaffPayrollManagement() {
  const [employees, setEmployees] = useState<Employee[]>([])
  const [payrolls, setPayrolls] = useState<Payroll[]>([])
  const [notifications, setNotifications] = useState<StaffNotification[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('employees')

  // Employee dialog state
  const [showEmployeeDialog, setShowEmployeeDialog] = useState(false)
  const [editingEmployee, setEditingEmployee] = useState<Employee | null>(null)
  const [employeeForm, setEmployeeForm] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    role: 'STAFF',
    department: 'RECEPTION',
    employeeId: '',
    hireDate: '',
    salary: '',
    status: 'ACTIVE',
    address: '',
    emergencyContact: '',
    emergencyPhone: '',
    password: ''
  })

  // Payroll dialog state
  const [showPayrollDialog, setShowPayrollDialog] = useState(false)
  const [payrollForm, setPayrollForm] = useState({
    staffId: '',
    baseSalary: '',
    bonuses: '',
    deductions: '',
    payPeriodStart: '',
    payPeriodEnd: '',
    bankAccount: '',
    notes: ''
  })

  // Notification dialog state
  const [showNotificationDialog, setShowNotificationDialog] = useState(false)
  const [notificationForm, setNotificationForm] = useState({
    recipientId: '',
    type: 'GENERAL',
    priority: 'NORMAL',
    subject: '',
    message: ''
  })

  const departments = [
    'RECEPTION', 'HOUSEKEEPING', 'RESTAURANT', 'SPA', 
    'MAINTENANCE', 'SECURITY', 'MANAGEMENT', 'ACCOUNTING', 'HR', 'MARKETING'
  ]

  const roles = ['ADMIN', 'MANAGER', 'SUPERVISOR', 'STAFF', 'PART_TIME']

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)

      // Fetch employees
      const employeesResponse = await fetch('/api/admin/users?role=STAFF')
      if (employeesResponse.ok) {
        const employeesData = await employeesResponse.json()
        if (employeesData.status === 'success') {
          setEmployees(employeesData.data)
        }
      }

      // Fetch payrolls
      const payrollResponse = await fetch('/api/payroll')
      if (payrollResponse.ok) {
        const payrollData = await payrollResponse.json()
        if (payrollData.status === 'success') {
          setPayrolls(payrollData.data)
        }
      }

      // Fetch staff notifications
      const notificationsResponse = await fetch('/api/staff-notifications')
      if (notificationsResponse.ok) {
        const notificationsData = await notificationsResponse.json()
        if (notificationsData.status === 'success') {
          setNotifications(notificationsData.data)
        }
      }

      setError(null)
    } catch (error: any) {
      console.error('Error fetching staff data:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  // Employee operations
  const saveEmployee = async () => {
    try {
      const formData = {
        ...employeeForm,
        salary: parseFloat(employeeForm.salary)
      }

      const url = editingEmployee ? `/api/admin/users/${editingEmployee.id}` : '/api/admin/users'
      const method = editingEmployee ? 'PUT' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowEmployeeDialog(false)
        resetEmployeeForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const deleteEmployee = async (id: string) => {
    try {
      const response = await fetch(`/api/admin/users/${id}`, { method: 'DELETE' })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const toggleEmployeeStatus = async (id: string, currentStatus: string) => {
    try {
      const newStatus = currentStatus === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE'
      const response = await fetch(`/api/admin/users/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  // Payroll operations
  const savePayroll = async () => {
    try {
      const formData = {
        ...payrollForm,
        baseSalary: parseFloat(payrollForm.baseSalary),
        bonuses: parseFloat(payrollForm.bonuses || '0'),
        deductions: parseFloat(payrollForm.deductions || '0')
      }

      const response = await fetch('/api/payroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      if (response.ok) {
        await fetchData()
        setShowPayrollDialog(false)
        resetPayrollForm()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  const processPayroll = async (id: string, action: string) => {
    try {
      const response = await fetch(`/api/payroll/${id}/${action}`, {
        method: 'POST'
      })
      if (response.ok) {
        await fetchData()
      }
    } catch (error: any) {
      setError(error.message)
    }
  }

  // Notification operations
  const sendNotification = async () => {
    try {
      const response = await fetch('/api/staff-notifications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notificationForm)
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

  const resetEmployeeForm = () => {
    setEmployeeForm({
      firstName: '',
      lastName: '',
      email: '',
      phone: '',
      role: 'STAFF',
      department: 'RECEPTION',
      employeeId: '',
      hireDate: '',
      salary: '',
      status: 'ACTIVE',
      address: '',
      emergencyContact: '',
      emergencyPhone: '',
      password: ''
    })
    setEditingEmployee(null)
  }

  const resetPayrollForm = () => {
    setPayrollForm({
      staffId: '',
      baseSalary: '',
      bonuses: '',
      deductions: '',
      payPeriodStart: '',
      payPeriodEnd: '',
      bankAccount: '',
      notes: ''
    })
  }

  const resetNotificationForm = () => {
    setNotificationForm({
      recipientId: '',
      type: 'GENERAL',
      priority: 'NORMAL',
      subject: '',
      message: ''
    })
  }

  const editEmployee = (employee: Employee) => {
    setEmployeeForm({
      firstName: employee.firstName,
      lastName: employee.lastName,
      email: employee.email,
      phone: employee.phone || '',
      role: employee.role,
      department: employee.department,
      employeeId: employee.employeeId,
      hireDate: employee.hireDate.split('T')[0],
      salary: employee.salary.toString(),
      status: employee.status,
      address: employee.address || '',
      emergencyContact: employee.emergencyContact || '',
      emergencyPhone: employee.emergencyPhone || '',
      password: ''
    })
    setEditingEmployee(employee)
    setShowEmployeeDialog(true)
  }

  // Stats calculation
  const activeEmployees = employees.filter(emp => emp.status === 'ACTIVE').length
  const totalPayroll = payrolls.reduce((sum, p) => sum + p.netSalary, 0)
  const pendingPayrolls = payrolls.filter(p => p.status === 'PENDING').length
  const unreadNotifications = notifications.filter(n => !n.isRead).length

  if (loading) {
    return <div className="flex items-center justify-center p-8">جاري التحميل...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">إدارة الموظفين والرواتب</h2>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 font-medium">خطأ: {error}</p>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">نظرة عامة</TabsTrigger>
          <TabsTrigger value="employees">الموظفين</TabsTrigger>
          <TabsTrigger value="payroll">الرواتب</TabsTrigger>
          <TabsTrigger value="notifications">الإشعارات</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>الموظفين النشطين</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{activeEmployees}</div>
                <p className="text-xs text-muted-foreground">من أصل {employees.length} موظف</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>إجمالي الرواتب</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">${totalPayroll.toLocaleString()}</div>
                <p className="text-xs text-muted-foreground">للفترة الحالية</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>رواتب معلقة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{pendingPayrolls}</div>
                <p className="text-xs text-muted-foreground">تحتاج معالجة</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>إشعارات غير مقروءة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{unreadNotifications}</div>
                <p className="text-xs text-muted-foreground">إشعارات جديدة</p>
              </CardContent>
            </Card>
          </div>

          {/* Department Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>توزيع الموظفين حسب الأقسام</CardTitle>
              <CardDescription>عدد الموظفين في كل قسم</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                {departments.map(dept => {
                  const count = employees.filter(emp => emp.department === dept && emp.status === 'ACTIVE').length
                  return (
                    <div key={dept} className="text-center p-4 border rounded-lg">
                      <div className="text-2xl font-bold">{count}</div>
                      <div className="text-sm text-muted-foreground">
                        {dept === 'RECEPTION' ? 'الاستقبال' :
                         dept === 'HOUSEKEEPING' ? 'الخدمات' :
                         dept === 'RESTAURANT' ? 'المطعم' :
                         dept === 'SPA' ? 'السبا' :
                         dept === 'MAINTENANCE' ? 'الصيانة' :
                         dept === 'SECURITY' ? 'الأمن' :
                         dept === 'MANAGEMENT' ? 'الإدارة' :
                         dept === 'ACCOUNTING' ? 'المحاسبة' :
                         dept === 'HR' ? 'الموارد البشرية' :
                         dept === 'MARKETING' ? 'التسويق' : dept}
                      </div>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="employees" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">إدارة الموظفين</h3>
            <Dialog open={showEmployeeDialog} onOpenChange={setShowEmployeeDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetEmployeeForm}>إضافة موظف جديد</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingEmployee ? 'تعديل الموظف' : 'إضافة موظف جديد'}
                  </DialogTitle>
                  <DialogDescription>
                    املأ المعلومات التالية لإضافة موظف جديد
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="firstName">الاسم الأول</Label>
                      <Input
                        id="firstName"
                        value={employeeForm.firstName}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, firstName: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="lastName">الاسم الأخير</Label>
                      <Input
                        id="lastName"
                        value={employeeForm.lastName}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, lastName: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="email">البريد الإلكتروني</Label>
                      <Input
                        id="email"
                        type="email"
                        value={employeeForm.email}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, email: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="phone">رقم الهاتف</Label>
                      <Input
                        id="phone"
                        value={employeeForm.phone}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, phone: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="role">المنصب</Label>
                      <Select value={employeeForm.role} onValueChange={(value) => setEmployeeForm({ ...employeeForm, role: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {roles.map(role => (
                            <SelectItem key={role} value={role}>
                              {role === 'ADMIN' ? 'مدير النظام' :
                               role === 'MANAGER' ? 'مدير' :
                               role === 'SUPERVISOR' ? 'مشرف' :
                               role === 'STAFF' ? 'موظف' :
                               role === 'PART_TIME' ? 'دوام جزئي' : role}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="department">القسم</Label>
                      <Select value={employeeForm.department} onValueChange={(value) => setEmployeeForm({ ...employeeForm, department: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {departments.map(dept => (
                            <SelectItem key={dept} value={dept}>
                              {dept === 'RECEPTION' ? 'الاستقبال' :
                               dept === 'HOUSEKEEPING' ? 'الخدمات' :
                               dept === 'RESTAURANT' ? 'المطعم' :
                               dept === 'SPA' ? 'السبا' :
                               dept === 'MAINTENANCE' ? 'الصيانة' :
                               dept === 'SECURITY' ? 'الأمن' :
                               dept === 'MANAGEMENT' ? 'الإدارة' :
                               dept === 'ACCOUNTING' ? 'المحاسبة' :
                               dept === 'HR' ? 'الموارد البشرية' :
                               dept === 'MARKETING' ? 'التسويق' : dept}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="employeeId">رقم الموظف</Label>
                      <Input
                        id="employeeId"
                        value={employeeForm.employeeId}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, employeeId: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="hireDate">تاريخ التوظيف</Label>
                      <Input
                        id="hireDate"
                        type="date"
                        value={employeeForm.hireDate}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, hireDate: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="salary">الراتب</Label>
                      <Input
                        id="salary"
                        type="number"
                        value={employeeForm.salary}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, salary: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="status">الحالة</Label>
                      <Select value={employeeForm.status} onValueChange={(value) => setEmployeeForm({ ...employeeForm, status: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="ACTIVE">نشط</SelectItem>
                          <SelectItem value="INACTIVE">غير نشط</SelectItem>
                          <SelectItem value="ON_LEAVE">في إجازة</SelectItem>
                          <SelectItem value="SUSPENDED">موقوف</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  {!editingEmployee && (
                    <div className="space-y-2">
                      <Label htmlFor="password">كلمة المرور</Label>
                      <Input
                        id="password"
                        type="password"
                        value={employeeForm.password}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, password: e.target.value })}
                        placeholder="كلمة مرور قوية"
                      />
                    </div>
                  )}
                  <div className="space-y-2">
                    <Label htmlFor="address">العنوان</Label>
                    <Textarea
                      id="address"
                      value={employeeForm.address}
                      onChange={(e) => setEmployeeForm({ ...employeeForm, address: e.target.value })}
                      rows={2}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="emergencyContact">جهة الاتصال الطارئ</Label>
                      <Input
                        id="emergencyContact"
                        value={employeeForm.emergencyContact}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, emergencyContact: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="emergencyPhone">هاتف طوارئ</Label>
                      <Input
                        id="emergencyPhone"
                        value={employeeForm.emergencyPhone}
                        onChange={(e) => setEmployeeForm({ ...employeeForm, emergencyPhone: e.target.value })}
                      />
                    </div>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowEmployeeDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={saveEmployee}>
                    {editingEmployee ? 'تحديث' : 'إضافة'}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة الموظفين</CardTitle>
              <CardDescription>إدارة معلومات وحالة جميع الموظفين</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>الاسم</TableHead>
                    <TableHead>البريد الإلكتروني</TableHead>
                    <TableHead>القسم</TableHead>
                    <TableHead>المنصب</TableHead>
                    <TableHead>الراتب</TableHead>
                    <TableHead>تاريخ التوظيف</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {employees.map((employee) => (
                    <TableRow key={employee.id}>
                      <TableCell className="font-medium">
                        {employee.firstName} {employee.lastName}
                      </TableCell>
                      <TableCell>{employee.email}</TableCell>
                      <TableCell>{employee.department}</TableCell>
                      <TableCell>{employee.role}</TableCell>
                      <TableCell>${employee.salary.toLocaleString()}</TableCell>
                      <TableCell>{new Date(employee.hireDate).toLocaleDateString('ar')}</TableCell>
                      <TableCell>
                        <Badge variant={employee.status === 'ACTIVE' ? 'default' : 'secondary'}>
                          {employee.status === 'ACTIVE' ? 'نشط' : 
                           employee.status === 'INACTIVE' ? 'غير نشط' :
                           employee.status === 'ON_LEAVE' ? 'إجازة' : 'موقوف'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => editEmployee(employee)}
                          >
                            تعديل
                          </Button>
                          <Button
                            size="sm"
                            variant={employee.status === 'ACTIVE' ? "destructive" : "default"}
                            onClick={() => toggleEmployeeStatus(employee.id, employee.status)}
                          >
                            {employee.status === 'ACTIVE' ? 'إيقاف' : 'تفعيل'}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => deleteEmployee(employee.id)}
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

        <TabsContent value="payroll" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">إدارة الرواتب</h3>
            <Dialog open={showPayrollDialog} onOpenChange={setShowPayrollDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetPayrollForm}>إنشاء راتب جديد</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>إنشاء راتب جديد</DialogTitle>
                  <DialogDescription>إنشاء راتب جديد لموظف</DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="staff">الموظف</Label>
                    <Select value={payrollForm.staffId} onValueChange={(value) => setPayrollForm({ ...payrollForm, staffId: value })}>
                      <SelectTrigger>
                        <SelectValue placeholder="اختر موظف" />
                      </SelectTrigger>
                      <SelectContent>
                        {employees.filter(emp => emp.status === 'ACTIVE').map(emp => (
                          <SelectItem key={emp.id} value={emp.id}>
                            {emp.firstName} {emp.lastName} - {emp.department}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="baseSalary">الراتب الأساسي</Label>
                      <Input
                        id="baseSalary"
                        type="number"
                        value={payrollForm.baseSalary}
                        onChange={(e) => setPayrollForm({ ...payrollForm, baseSalary: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="bonuses">العلاوات</Label>
                      <Input
                        id="bonuses"
                        type="number"
                        value={payrollForm.bonuses}
                        onChange={(e) => setPayrollForm({ ...payrollForm, bonuses: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="deductions">الخصومات</Label>
                      <Input
                        id="deductions"
                        type="number"
                        value={payrollForm.deductions}
                        onChange={(e) => setPayrollForm({ ...payrollForm, deductions: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="payPeriodStart">بداية الفترة</Label>
                      <Input
                        id="payPeriodStart"
                        type="date"
                        value={payrollForm.payPeriodStart}
                        onChange={(e) => setPayrollForm({ ...payrollForm, payPeriodStart: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="payPeriodEnd">نهاية الفترة</Label>
                      <Input
                        id="payPeriodEnd"
                        type="date"
                        value={payrollForm.payPeriodEnd}
                        onChange={(e) => setPayrollForm({ ...payrollForm, payPeriodEnd: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="bankAccount">رقم الحساب البنكي</Label>
                    <Input
                      id="bankAccount"
                      value={payrollForm.bankAccount}
                      onChange={(e) => setPayrollForm({ ...payrollForm, bankAccount: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="payrollNotes">ملاحظات</Label>
                    <Textarea
                      id="payrollNotes"
                      value={payrollForm.notes}
                      onChange={(e) => setPayrollForm({ ...payrollForm, notes: e.target.value })}
                      rows={3}
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowPayrollDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={savePayroll}>إنشاء</Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>قائمة الرواتب</CardTitle>
              <CardDescription>إدارة رواتب الموظفين والمدفوعات</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>الموظف</TableHead>
                    <TableHead>الراتب الأساسي</TableHead>
                    <TableHead>العلاوات</TableHead>
                    <TableHead>الخصومات</TableHead>
                    <TableHead>الصافي</TableHead>
                    <TableHead>الفترة</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>الإجراءات</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {payrolls.map((payroll) => (
                    <TableRow key={payroll.id}>
                      <TableCell className="font-medium">
                        {payroll.staff.firstName} {payroll.staff.lastName}
                      </TableCell>
                      <TableCell>${payroll.baseSalary.toLocaleString()}</TableCell>
                      <TableCell className="text-green-600">+${payroll.bonuses.toLocaleString()}</TableCell>
                      <TableCell className="text-red-600">-${payroll.deductions.toLocaleString()}</TableCell>
                      <TableCell className="font-bold">${payroll.netSalary.toLocaleString()}</TableCell>
                      <TableCell>
                        {new Date(payroll.payPeriodStart).toLocaleDateString('ar')} - {new Date(payroll.payPeriodEnd).toLocaleDateString('ar')}
                      </TableCell>
                      <TableCell>
                        <Badge variant={payroll.status === 'PAID' ? 'default' : 
                                      payroll.status === 'PROCESSED' ? 'secondary' : 
                                      payroll.status === 'FAILED' ? 'destructive' : 'outline'}>
                          {payroll.status === 'PAID' ? 'مدفوع' :
                           payroll.status === 'PROCESSED' ? 'معالج' :
                           payroll.status === 'FAILED' ? 'فاشل' : 'معلق'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          {payroll.status === 'PENDING' && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => processPayroll(payroll.id, 'process')}
                            >
                              معالجة
                            </Button>
                          )}
                          {payroll.status === 'PROCESSED' && (
                            <Button
                              size="sm"
                              variant="default"
                              onClick={() => processPayroll(payroll.id, 'pay')}
                            >
                              دفع
                            </Button>
                          )}
                          {payroll.status === 'PAID' && payroll.paidDate && (
                            <span className="text-sm text-muted-foreground">
                              مدفوع في {new Date(payroll.paidDate).toLocaleDateString('ar')}
                            </span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">إشعارات الموظفين</h3>
            <Dialog open={showNotificationDialog} onOpenChange={setShowNotificationDialog}>
              <DialogTrigger asChild>
                <Button onClick={resetNotificationForm}>إرسال إشعار</Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>إرسال إشعار للموظفين</DialogTitle>
                  <DialogDescription>إرسال إشعار أو رسالة لموظف أو مجموعة من الموظفين</DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="recipient">المستلم</Label>
                    <Select value={notificationForm.recipientId} onValueChange={(value) => setNotificationForm({ ...notificationForm, recipientId: value })}>
                      <SelectTrigger>
                        <SelectValue placeholder="اختر موظف" />
                      </SelectTrigger>
                      <SelectContent>
                        {employees.filter(emp => emp.status === 'ACTIVE').map(emp => (
                          <SelectItem key={emp.id} value={emp.id}>
                            {emp.firstName} {emp.lastName} - {emp.department}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="notifType">نوع الإشعار</Label>
                      <Select value={notificationForm.type} onValueChange={(value) => setNotificationForm({ ...notificationForm, type: value })}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="GENERAL">عام</SelectItem>
                          <SelectItem value="URGENT">عاجل</SelectItem>
                          <SelectItem value="BOOKING_ALERT">تنبيه حجز</SelectItem>
                          <SelectItem value="MAINTENANCE">صيانة</SelectItem>
                          <SelectItem value="STAFF_MEETING">اجتماع موظفين</SelectItem>
                          <SelectItem value="SHIFT_UPDATE">تحديث ورديات</SelectItem>
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
                          <SelectItem value="LOW">منخفضة</SelectItem>
                          <SelectItem value="NORMAL">عادية</SelectItem>
                          <SelectItem value="HIGH">عالية</SelectItem>
                          <SelectItem value="URGENT">عاجلة</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="subject">الموضوع</Label>
                    <Input
                      id="subject"
                      value={notificationForm.subject}
                      onChange={(e) => setNotificationForm({ ...notificationForm, subject: e.target.value })}
                      placeholder="موضوع الإشعار"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="message">الرسالة</Label>
                    <Textarea
                      id="message"
                      value={notificationForm.message}
                      onChange={(e) => setNotificationForm({ ...notificationForm, message: e.target.value })}
                      placeholder="نص الرسالة..."
                      rows={4}
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={() => setShowNotificationDialog(false)}>
                    إلغاء
                  </Button>
                  <Button onClick={sendNotification}>إرسال</Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>إشعارات الموظفين</CardTitle>
              <CardDescription>إدارة وإرسال الإشعارات للموظفين</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>المرسل</TableHead>
                    <TableHead>المستلم</TableHead>
                    <TableHead>الموضوع</TableHead>
                    <TableHead>النوع</TableHead>
                    <TableHead>الأولوية</TableHead>
                    <TableHead>الحالة</TableHead>
                    <TableHead>التاريخ</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {notifications.map((notification) => (
                    <TableRow key={notification.id}>
                      <TableCell>
                        {notification.sender.firstName} {notification.sender.lastName}
                      </TableCell>
                      <TableCell className="font-medium">
                        {notification.recipient.firstName} {notification.recipient.lastName}
                      </TableCell>
                      <TableCell>{notification.subject}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{notification.type}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={notification.priority === 'URGENT' ? 'destructive' : 
                                      notification.priority === 'HIGH' ? 'default' : 'secondary'}>
                          {notification.priority === 'LOW' ? 'منخفضة' :
                           notification.priority === 'NORMAL' ? 'عادية' :
                           notification.priority === 'HIGH' ? 'عالية' : 'عاجلة'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={notification.isRead ? 'default' : 'secondary'}>
                          {notification.isRead ? 'مقروء' : 'غير مقروء'}
                        </Badge>
                      </TableCell>
                      <TableCell>{new Date(notification.createdAt).toLocaleDateString('ar')}</TableCell>
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