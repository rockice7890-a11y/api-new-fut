'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { AlertCircle, CheckCircle2, Loader2, Shield } from 'lucide-react'

export default function AdminSetupPage() {
  const router = useRouter()
  const [isConfigured, setIsConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    phone: 'whatsapp:+'
  })

  // التحقق من حالة الإعداد
  useEffect(() => {
    const checkSetupStatus = async () => {
      try {
        const res = await fetch('/api/admin/setup')
        const data = await res.json()
        
        if (data.data.isConfigured) {
          setIsConfigured(true)
          setError('حساب المدير مُعد مسبقاً. سيتم تحويلك لصفحة تسجيل الدخول...')
          setTimeout(() => router.push('/admin/login'), 3000)
        }
      } catch (err) {
        console.error('Error checking setup status:', err)
      } finally {
        setLoading(false)
      }
    }

    checkSetupStatus()
  }, [router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    // التحقق من تطابق كلمات المرور
    if (formData.password !== formData.confirmPassword) {
      setError('كلمات المرور غير متطابقة')
      return
    }

    // التحقق من رقم الواتساب
    if (!formData.phone.startsWith('whatsapp:+')) {
      setError('رقم الواتساب يجب أن يبدأ بـ whatsapp:+')
      return
    }

    setSubmitting(true)

    try {
      const res = await fetch('/api/admin/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: formData.email,
          password: formData.password,
          phone: formData.phone
        })
      })

      const data = await res.json()

      if (data.status === 'success') {
        setSuccess('✅ تم إعداد الحساب بنجاح! جاري التحويل لصفحة تسجيل الدخول...')
        setTimeout(() => router.push('/admin/login'), 2000)
      } else {
        setError(data.message)
      }
    } catch (err: any) {
      setError('حدث خطأ في الاتصال بالخادم')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50">
        <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
      </div>
    )
  }

  if (isConfigured) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6">
            <div className="text-center">
              <CheckCircle2 className="w-16 h-16 text-green-500 mx-auto mb-4" />
              <p className="text-lg text-gray-700">{error}</p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 p-4">
      <Card className="w-full max-w-2xl shadow-2xl">
        <CardHeader className="text-center space-y-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-t-lg">
          <div className="flex justify-center mb-4">
            <Shield className="w-16 h-16" />
          </div>
          <CardTitle className="text-3xl font-bold">إعداد حساب المدير</CardTitle>
          <CardDescription className="text-blue-100">
            قم بإنشاء حساب المدير الرئيسي للنظام
          </CardDescription>
        </CardHeader>

        <CardContent className="p-6">
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
              <p className="text-red-800 text-sm">{error}</p>
            </div>
          )}

          {success && (
            <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg flex items-start gap-2">
              <CheckCircle2 className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
              <p className="text-green-800 text-sm">{success}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">البريد الإلكتروني</Label>
              <Input
                id="email"
                type="email"
                placeholder="admin@hotel.com"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                required
                className="text-right"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="phone">رقم الواتساب</Label>
              <Input
                id="phone"
                type="text"
                placeholder="whatsapp:+966500000000"
                value={formData.phone}
                onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                required
                className="text-left"
                dir="ltr"
              />
              <p className="text-xs text-gray-500">
                سيتم إرسال رموز تسجيل الدخول إلى هذا الرقم
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">كلمة المرور</Label>
              <Input
                id="password"
                type="password"
                placeholder="كلمة مرور قوية"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                required
                className="text-right"
              />
              <ul className="text-xs text-gray-500 space-y-1 list-disc list-inside">
                <li>على الأقل 8 أحرف</li>
                <li>حرف كبير وحرف صغير</li>
                <li>رقم ورمز خاص (!@#$%)</li>
              </ul>
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword">تأكيد كلمة المرور</Label>
              <Input
                id="confirmPassword"
                type="password"
                placeholder="أعد كتابة كلمة المرور"
                value={formData.confirmPassword}
                onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                required
                className="text-right"
              />
            </div>

            <Button
              type="submit"
              disabled={submitting}
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  جاري الإعداد...
                </>
              ) : (
                'إنشاء حساب المدير'
              )}
            </Button>
          </form>

          <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <h4 className="font-semibold text-blue-900 mb-2">🔒 ملاحظات أمنية:</h4>
            <ul className="text-xs text-blue-800 space-y-1">
              <li>• سيتم تشفير كلمة المرور باستخدام bcrypt</li>
              <li>• يمكن إنشاء حساب مدير واحد فقط</li>
              <li>• احتفظ ببيانات الدخول في مكان آمن</li>
              <li>• ستتلقى رموز OTP على الواتساب عند كل تسجيل دخول</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
