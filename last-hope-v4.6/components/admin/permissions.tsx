'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { AlertCircle, Lock, Unlock } from 'lucide-react'

interface Permission {
  id: string
  pagePath: string
  reason: string
  message: string
  isBlocked: boolean
  blockedAt: string
}

export default function Permissions() {
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [loading, setLoading] = useState(true)
  const [pagePath, setPagePath] = useState('')
  const [reason, setReason] = useState('MAINTENANCE')
  const [message, setMessage] = useState('')

  useEffect(() => {
    fetchPermissions()
  }, [])

  const fetchPermissions = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/admin/permissions/pages')
      const data = await response.json()
      if (data.status === 'success') {
        setPermissions(data.data)
      }
    } catch (error) {
      console.error('Failed to fetch permissions:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleBlockPage = async () => {
    try {
      const response = await fetch('/api/admin/permissions/pages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pagePath, reason, message }),
      })
      if (response.ok) {
        setPagePath('')
        setMessage('')
        fetchPermissions()
      }
    } catch (error) {
      console.error('Failed to block page:', error)
    }
  }

  const handleUnblockPage = async (path: string) => {
    try {
      const response = await fetch('/api/admin/permissions/pages', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pagePath: path }),
      })
      if (response.ok) {
        fetchPermissions()
      }
    } catch (error) {
      console.error('Failed to unblock page:', error)
    }
  }

  return (
    <div className="space-y-6">
      <Card className="border-sidebar-border">
        <CardHeader>
          <CardTitle>حجب الصفحات</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-semibold text-sidebar-primary">مسار الصفحة</label>
            <Input
              placeholder="/admin/users"
              value={pagePath}
              onChange={(e) => setPagePath(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-semibold text-sidebar-primary">السبب</label>
            <select
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full px-3 py-2 border border-sidebar-border rounded-lg bg-background text-sidebar-foreground"
            >
              <option value="MAINTENANCE">صيانة</option>
              <option value="SYSTEM_DOWN">النظام معطل</option>
              <option value="UPGRADE">ترقية</option>
              <option value="CUSTOM">مخصص</option>
            </select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-semibold text-sidebar-primary">الرسالة</label>
            <Input
              placeholder="يتم صيانة الصفحة حالياً..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
            />
          </div>

          <Button onClick={handleBlockPage} className="bg-sidebar-primary hover:opacity-90">
            حجب الصفحة
          </Button>
        </CardContent>
      </Card>

      <Card className="border-sidebar-border">
        <CardHeader>
          <CardTitle>الصفحات المحجوبة</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8 text-sidebar-foreground opacity-50">جاري التحميل...</div>
          ) : permissions.length === 0 ? (
            <div className="text-center py-8 text-sidebar-foreground opacity-50">لا توجد صفحات محجوبة</div>
          ) : (
            <div className="space-y-4">
              {permissions.map((perm) => (
                <div key={perm.id} className="flex items-center justify-between p-4 border border-sidebar-border rounded-lg bg-sidebar-accent">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <AlertCircle size={20} className="text-destructive" />
                      <div>
                        <p className="font-semibold text-sidebar-primary">{perm.pagePath}</p>
                        <p className="text-sm text-sidebar-foreground opacity-75">{perm.message}</p>
                        <p className="text-xs text-sidebar-foreground opacity-50 mt-1">
                          السبب: {perm.reason} • {new Date(perm.blockedAt).toLocaleString('ar-SA')}
                        </p>
                      </div>
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleUnblockPage(perm.pagePath)}
                    className="gap-2"
                  >
                    <Unlock size={18} />
                    فتح
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
