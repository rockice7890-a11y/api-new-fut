'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Search } from 'lucide-react'

interface AuditLog {
  id: string
  action: string
  resource: string
  userId: string
  timestamp: string
  details: string
}

export default function AuditLogs() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)
  const [action, setAction] = useState('')
  const [resource, setResource] = useState('')

  useEffect(() => {
    fetchLogs()
  }, [action, resource])

  const fetchLogs = async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      if (action) params.set('action', action)
      if (resource) params.set('resource', resource)

      const response = await fetch(`/api/admin/audit-logs?${params}`)
      const data = await response.json()
      if (data.status === 'success') {
        setLogs(data.data)
      }
    } catch (error) {
      console.error('Failed to fetch logs:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="border-sidebar-border">
      <CardHeader>
        <CardTitle>سجلات التدقيق</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex gap-4 mb-6">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-sidebar-foreground opacity-50" size={20} />
            <Input placeholder="ابحث في الإجراءات..." className="pl-10" />
          </div>
          <Select value={action} onValueChange={setAction}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="الإجراء" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">الكل</SelectItem>
              <SelectItem value="CREATE">إنشاء</SelectItem>
              <SelectItem value="UPDATE">تحديث</SelectItem>
              <SelectItem value="DELETE">حذف</SelectItem>
            </SelectContent>
          </Select>
          <Select value={resource} onValueChange={setResource}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="المورد" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">الكل</SelectItem>
              <SelectItem value="USER">مستخدم</SelectItem>
              <SelectItem value="HOTEL">فندق</SelectItem>
              <SelectItem value="BOOKING">حجز</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-sidebar-border">
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">الإجراء</th>
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">المورد</th>
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">المستخدم</th>
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">الوقت</th>
                <th className="text-right py-3 px-4 font-semibold text-sidebar-primary">التفاصيل</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-sidebar-foreground opacity-50">
                    جاري التحميل...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-sidebar-foreground opacity-50">
                    لا توجد سجلات
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="border-b border-sidebar-border hover:bg-sidebar-accent transition-colors">
                    <td className="py-3 px-4 text-sidebar-foreground">{log.action}</td>
                    <td className="py-3 px-4 text-sidebar-foreground">{log.resource}</td>
                    <td className="py-3 px-4 text-sidebar-foreground">{log.userId}</td>
                    <td className="py-3 px-4 text-sidebar-foreground">
                      {new Date(log.timestamp).toLocaleString('ar-SA')}
                    </td>
                    <td className="py-3 px-4 text-sidebar-foreground opacity-75">{log.details}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}
