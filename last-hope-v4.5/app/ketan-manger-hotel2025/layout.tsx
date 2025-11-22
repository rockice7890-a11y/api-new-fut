'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { AlertCircle, Shield, Lock, Eye } from 'lucide-react'

export default function KetanManagerLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [authMethod, setAuthMethod] = useState<'token' | 'password' | null>(null)
  const [showPasswordField, setShowPasswordField] = useState(false)
  const [password, setPassword] = useState('')
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const router = useRouter()

  useEffect(() => {
    checkAuthentication()
  }, [])

  const checkAuthentication = () => {
    // تحقق من وجود JWT token
    const savedToken = localStorage.getItem('ketan_admin_token')
    if (savedToken) {
      verifyToken(savedToken)
    } else {
      setIsLoading(false)
    }
  }

  const verifyToken = async (tokenValue: string) => {
    try {
      const response = await fetch('/api/auth/verify-admin-token', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${tokenValue}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          requiredRole: 'ADMIN',
          adminKey: 'ketan-manger-hotel2025'
        }),
      })

      if (response.ok) {
        const data = await response.json()
        if (data.valid) {
          setIsAuthenticated(true)
          setAuthMethod('token')
        } else {
          throw new Error('Invalid token')
        }
      } else {
        throw new Error('Authentication failed')
      }
    } catch (error) {
      console.error('Token verification failed:', error)
      localStorage.removeItem('ketan_admin_token')
      setIsLoading(false)
    } finally {
      setIsLoading(false)
    }
  }

  const handlePasswordAuth = async () => {
    if (!password) {
      setError('يرجى إدخال كلمة المرور')
      return
    }

    try {
      const response = await fetch('/api/auth/admin-password-login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          password: password,
          adminKey: 'ketan-manger-hotel2025'
        }),
      })

      if (response.ok) {
        const data = await response.json()
        localStorage.setItem('ketan_admin_token', data.token)
        setIsAuthenticated(true)
        setAuthMethod('password')
        setError('')
      } else {
        setError('كلمة مرور غير صحيحة')
      }
    } catch (error) {
      setError('خطأ في الاتصال')
    }
  }

  const handleTokenAuth = async () => {
    if (!token) {
      setError('يرجى إدخال الرمز المميز')
      return
    }

    await verifyToken(token)
    if (!isAuthenticated) {
      setError('رمز مميز غير صحيح')
    }
  }

  const handleLogout = () => {
    localStorage.removeItem('ketan_admin_token')
    setIsAuthenticated(false)
    setAuthMethod(null)
    setToken('')
    setPassword('')
    setError('')
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-white text-lg">جاري التحقق من الهوية...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
          <div className="text-center mb-6">
            <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Shield className="w-8 h-8 text-blue-600" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">كيتان مدير الفنادق</h1>
            <p className="text-gray-600">لوحة التحكم الإدارية المحمية</p>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
              <p className="text-red-700 text-sm">{error}</p>
            </div>
          )}

          <div className="space-y-4">
            {!showPasswordField ? (
              <>
                <button
                  onClick={() => setShowPasswordField(true)}
                  className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
                >
                  <Lock className="w-5 h-5" />
                  تسجيل الدخول بكلمة المرور
                </button>
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-white text-gray-500">أو</span>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">الرمز المميز</label>
                  <div className="flex gap-2">
                    <input
                      type="password"
                      value={token}
                      onChange={(e) => setToken(e.target.value)}
                      placeholder="أدخل الرمز المميز"
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <button
                      onClick={handleTokenAuth}
                      className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
                    >
                      <Eye className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">كلمة المرور الإدارية</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="أدخل كلمة المرور"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    onKeyPress={(e) => e.key === 'Enter' && handlePasswordAuth()}
                  />
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={handlePasswordAuth}
                    className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    تسجيل الدخول
                  </button>
                  <button
                    onClick={() => {
                      setShowPasswordField(false)
                      setPassword('')
                      setError('')
                    }}
                    className="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition-colors"
                  >
                    إلغاء
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="mt-6 p-3 bg-blue-50 rounded-lg border border-blue-200">
            <p className="text-blue-800 text-xs text-center">
              🔒 هذه المنطقة محمية ومخصصة للمدراء المعتمدين فقط
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="relative">
      {/* Security Status Bar */}
      <div className="bg-green-600 text-white px-4 py-2 text-sm flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4" />
          <span>محمي - تم التحقق من الهوية بنجاح ({authMethod})</span>
        </div>
        <button
          onClick={handleLogout}
          className="bg-green-700 hover:bg-green-800 px-3 py-1 rounded text-xs transition-colors"
        >
          تسجيل الخروج
        </button>
      </div>
      {children}
    </div>
  )
}
