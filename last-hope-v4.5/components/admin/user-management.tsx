'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Search, ChevronLeft, ChevronRight, Trash2 } from 'lucide-react'

interface User {
  id: string
  email: string
  firstName: string
  lastName: string
  role: string
  createdAt: string
}

export default function UserManagement() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [role, setRole] = useState('')

  useEffect(() => {
    fetchUsers()
  }, [page, search, role])

  const fetchUsers = async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      params.set('page', page.toString())
      params.set('pageSize', '10')
      if (search) params.set('search', search)
      if (role) params.set('role', role)

      const response = await fetch(`/api/admin/users?${params}`)
      const data = await response.json()
      if (data.status === 'success') {
        setUsers(data.data.users)
        setTotal(data.data.total)
      }
    } catch (error) {
      console.error('Failed to fetch users:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="border-sidebar-border">
      <CardHeader>
        <CardTitle>إدارة المستخدمين</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex gap-4 mb-6">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-sidebar-foreground opacity-50" size={20} />
            <Input
              placeholder="ابحث عن مستخدم..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(1)
              }}
              className="pl-10"
            />
          </div>
          <Select value={role} onValueChange={(val) => {
            setRole(val)
            setPage(1)
          }}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="الدور" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">الكل</SelectItem>
              <SelectItem value="ADMIN">مسؤول</SelectItem>
              <SelectItem value="USER">مستخدم</SelectItem>
              <SelectItem value="MANAGER">مدير</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-sidebar-border">
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">البريد الإلكتروني</th>
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">الاسم</th>
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">الدور</th>
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">تاريخ الإنشاء</th>
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
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-sidebar-foreground opacity-50">
                    لا توجد مستخدمين
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id} className="border-b border-sidebar-border hover:bg-sidebar-accent transition-colors">
                    <td className="py-3 px-4 text-sidebar-foreground">{user.email}</td>
                    <td className="py-3 px-4 text-sidebar-foreground">{user.firstName} {user.lastName}</td>
                    <td className="py-3 px-4">
                      <span className="inline-block px-3 py-1 bg-sidebar-primary text-sidebar-primary-foreground rounded-full text-xs font-semibold">
                        {user.role}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-sidebar-foreground">
                      {new Date(user.createdAt).toLocaleDateString('ar-SA')}
                    </td>
                    <td className="py-3 px-4 text-center">
                      <button className="text-destructive hover:opacity-80 transition-opacity">
                        <Trash2 size={18} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between mt-6">
          <div className="text-sm text-sidebar-foreground opacity-75">
            الصفحة {page} من {Math.ceil(total / 10)}
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="gap-2"
            >
              <ChevronLeft size={18} />
              السابق
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => p + 1)}
              disabled={page * 10 >= total}
              className="gap-2"
            >
              التالي
              <ChevronRight size={18} />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
