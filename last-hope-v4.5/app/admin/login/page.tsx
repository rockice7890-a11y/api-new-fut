'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { AlertCircle, Loader2, Shield, MessageCircle, Lock } from 'lucide-react'

export default function AdminLoginPage() {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [otpSent, setOtpSent] = useState(false)
  const [sendingOtp, setSendingOtp] = useState(false)
  const [error, setError] = useState('')
  const [otpInfo, setOtpInfo] = useState<{ phone: string; expiresIn: number } | null>(null)

  const [formData, setFormData] = useState({
    email: '',
    password: '',
    otp: ''
  })

  // التحقق من التوكن الموجود
  useEffect(() => {
    const token = localStorage.getItem('admin_token')
    if (token) {
      // التحقق من صحة التوكن
      fetch('/api/admin/auth/verify', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      }).then(res => {
        if (res.ok) {
          router.push('/ketan-manger-hotel2025')
        } else {
          localStorage.removeItem('admin_token')
        }
      })
    }
  }, [router])

  const handleRequestOtp = async () => {
    if (!formData.email || !formData.password) {
      setError('الرجاء إدخال البريد الإلكتروني وكلمة المرور أولاً')
      return
    }

    setError('')
    setSendingOtp(true)

    try {
      const res = await fetch('/api/admin/auth/request-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: formData.email })
      })

      const data = await res.json()

      if (data.status === 'success') {
        setOtpSent(true)
        setOtpInfo(data.data)
        setError('')
      } else {
        setError(data.message)
      }
    } catch (err) {
      setError('فشل إرسال رمز OTP. تحقق من اتصالك بالإنترنت.')
    } finally {
      setSendingOtp(false)
    }
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!formData.otp) {
      setError('الرجاء إدخال رمز OTP')
      return
    }

    setLoading(true)

    try {
      const res = await fetch('/api/admin/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      })

      const data = await res.json()

      if (data.status === 'success') {
        // حفظ التوكن
        localStorage.setItem('admin_token', data.data.token)
        
        // التحويل لصفحة المدير
        router.push('/ketan-manger-hotel2025')
      } else {
        setError(data.message)
      }
    } catch (err) {
      setError('حدث خطأ في تسجيل الدخول')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 p-4">
      <Card className="w-full max-w-md shadow-2xl">
        <CardHeader className="text-center space-y-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-t-lg">
          <div className="flex justify-center mb-4">
            <Shield className="w-16 h-16" />
          </div>
          <CardTitle className="text-2xl font-bold">تسجيل دخول المدير</CardTitle>
          <CardDescription className="text-blue-100">
            نظام مصادقة ثنائي عبر WhatsApp
          </CardDescription>
        </CardHeader>

        <CardContent className="p-6">
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
              <p className="text-red-800 text-sm">{error}</p>
            </div>
          )}

          {otpSent && otpInfo && (
            <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg">
              <div className="flex items-start gap-2">
                <MessageCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-green-800 text-sm font-medium">تم إرسال الرمز بنجاح!</p>
                  <p className="text-green-700 text-xs mt-1">
                    تم إرسال الرمز إلى: {otpInfo.phone}
                  </p>
                  <p className="text-green-700 text-xs">
                    صالح لمدة {otpInfo.expiresIn} دقائق
                  </p>
                </div>
              </div>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">البريد الإلكتروني</Label>
              <Input
                id="email"
                type="email"
                placeholder="admin@hotel.com"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                required
                disabled={otpSent}
                className="text-right"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">كلمة المرور</Label>
              <Input
                id="password"
                type="password"
                placeholder="كلمة المرور"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                required
                disabled={otpSent}
                className="text-right"
              />
            </div>

            {!otpSent ? (
              <Button
                type="button"
                onClick={handleRequestOtp}
                disabled={sendingOtp}
                className="w-full bg-green-600 hover:bg-green-700"
              >
                {sendingOtp ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    جاري الإرسال...
                  </>
                ) : (
                  <>
                    <MessageCircle className="w-4 h-4 mr-2" />
                    إرسال رمز WhatsApp
                  </>
                )}
              </Button>
            ) : (
              <>
                <div className="space-y-2">
                  <Label htmlFor="otp">رمز التحقق (OTP)</Label>
                  <Input
                    id="otp"
                    type="text"
                    placeholder="000000"
                    value={formData.otp}
                    onChange={(e) => setFormData({ ...formData, otp: e.target.value })}
                    required
                    maxLength={6}
                    className="text-center text-2xl tracking-widest font-bold"
                    dir="ltr"
                    autoComplete="off"
                  />
                </div>

                <div className="flex gap-2">
                  <Button
                    type="submit"
                    disabled={loading}
                    className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        جاري التحقق...
                      </>
                    ) : (
                      <>
                        <Lock className="w-4 h-4 mr-2" />
                        تسجيل الدخول
                      </>
                    )}
                  </Button>

                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setOtpSent(false)
                      setFormData({ ...formData, otp: '' })
                      setError('')
                    }}
                  >
                    إلغاء
                  </Button>
                </div>

                <Button
                  type="button"
                  variant="link"
                  onClick={handleRequestOtp}
                  disabled={sendingOtp}
                  className="w-full text-sm"
                >
                  إعادة إرسال الرمز
                </Button>
              </>
            )}
          </form>

          <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <h4 className="font-semibold text-blue-900 mb-2 text-sm">🔐 نظام الأمان:</h4>
            <ul className="text-xs text-blue-800 space-y-1">
              <li>1️⃣ إدخال البريد الإلكتروني وكلمة المرور</li>
              <li>2️⃣ إرسال رمز OTP إلى واتساب المدير</li>
              <li>3️⃣ إدخال الرمز للتحقق</li>
              <li>4️⃣ الوصول الآمن للوحة التحكم</li>
            </ul>
          </div>

          <div className="mt-4 text-center">
            <a
              href="/admin-setup"
              className="text-sm text-blue-600 hover:underline"
            >
              لم تقم بإعداد حساب المدير بعد؟
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
