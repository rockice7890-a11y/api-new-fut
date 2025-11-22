/**
 * WhatsApp OTP Service
 * إرسال رموز OTP عبر WhatsApp باستخدام Twilio
 */

interface OTPSession {
  code: string
  expiresAt: number
  attempts: number
  createdAt: number
}

// تخزين مؤقت للـ OTP (في الإنتاج، استخدم Redis)
const otpStore = new Map<string, OTPSession>()

/**
 * توليد رمز OTP عشوائي
 */
export function generateOTP(length: number = 6): string {
  const digits = '0123456789'
  let otp = ''
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)]
  }
  return otp
}

/**
 * إرسال OTP عبر WhatsApp
 */
export async function sendWhatsAppOTP(phoneNumber: string): Promise<{
  success: boolean
  message: string
  expiresIn?: number
}> {
  try {
    // التحقق من المتغيرات البيئية
    const accountSid = process.env.TWILIO_ACCOUNT_SID
    const authToken = process.env.TWILIO_AUTH_TOKEN
    const fromNumber = process.env.TWILIO_WHATSAPP_FROM
    
    if (!accountSid || !authToken || !fromNumber) {
      console.error('⚠️ Twilio credentials not configured')
      return {
        success: false,
        message: 'خدمة WhatsApp غير مُعدة. الرجاء التواصل مع المطور.'
      }
    }

    // تنظيف رقم الهاتف
    const cleanPhone = phoneNumber.replace(/\s+/g, '')
    if (!cleanPhone.startsWith('whatsapp:')) {
      return {
        success: false,
        message: 'رقم الهاتف يجب أن يبدأ بـ whatsapp:+966...'
      }
    }

    // توليد OTP
    const otp = generateOTP(6)
    const expiryMinutes = parseInt(process.env.OTP_EXPIRY_MINUTES || '5')
    const expiresAt = Date.now() + expiryMinutes * 60 * 1000

    // حفظ OTP
    otpStore.set(cleanPhone, {
      code: otp,
      expiresAt,
      attempts: 0,
      createdAt: Date.now()
    })

    // إرسال الرسالة عبر Twilio
    const twilioUrl = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`
    const message = `🔐 رمز تسجيل الدخول لـ ${process.env.NEXT_PUBLIC_APP_NAME}:\n\n${otp}\n\nصالح لمدة ${expiryMinutes} دقائق فقط.\n⚠️ لا تشارك هذا الرمز مع أحد.`

    const response = await fetch(twilioUrl, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${accountSid}:${authToken}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        From: fromNumber,
        To: cleanPhone,
        Body: message,
      }),
    })

    if (!response.ok) {
      const error = await response.json()
      console.error('Twilio API Error:', error)
      return {
        success: false,
        message: 'فشل إرسال الرسالة. تحقق من رقم الهاتف.'
      }
    }

    console.log('✅ OTP sent successfully to', cleanPhone)
    return {
      success: true,
      message: 'تم إرسال الرمز إلى واتساب',
      expiresIn: expiryMinutes
    }

  } catch (error: any) {
    console.error('WhatsApp OTP Error:', error)
    return {
      success: false,
      message: 'حدث خطأ في إرسال الرمز'
    }
  }
}

/**
 * التحقق من صحة OTP
 */
export function verifyOTP(phoneNumber: string, code: string): {
  valid: boolean
  message: string
} {
  const cleanPhone = phoneNumber.replace(/\s+/g, '')
  const session = otpStore.get(cleanPhone)

  if (!session) {
    return {
      valid: false,
      message: 'لم يتم إرسال رمز OTP. الرجاء طلب رمز جديد.'
    }
  }

  // التحقق من انتهاء الصلاحية
  if (Date.now() > session.expiresAt) {
    otpStore.delete(cleanPhone)
    return {
      valid: false,
      message: 'انتهت صلاحية الرمز. الرجاء طلب رمز جديد.'
    }
  }

  // التحقق من عدد المحاولات
  const maxAttempts = parseInt(process.env.OTP_MAX_ATTEMPTS || '3')
  if (session.attempts >= maxAttempts) {
    otpStore.delete(cleanPhone)
    return {
      valid: false,
      message: 'تجاوزت الحد الأقصى من المحاولات. الرجاء طلب رمز جديد.'
    }
  }

  // التحقق من صحة الرمز
  session.attempts++
  
  if (session.code !== code) {
    otpStore.set(cleanPhone, session)
    return {
      valid: false,
      message: `رمز غير صحيح. المحاولات المتبقية: ${maxAttempts - session.attempts}`
    }
  }

  // نجح التحقق - حذف الـ OTP
  otpStore.delete(cleanPhone)
  return {
    valid: true,
    message: 'تم التحقق بنجاح'
  }
}

/**
 * تنظيف OTP منتهية الصلاحية (يجب تشغيلها دورياً)
 */
export function cleanupExpiredOTPs() {
  const now = Date.now()
  for (const [phone, session] of otpStore.entries()) {
    if (now > session.expiresAt) {
      otpStore.delete(phone)
    }
  }
}

// تنظيف تلقائي كل 10 دقائق
if (typeof window === 'undefined') {
  setInterval(cleanupExpiredOTPs, 10 * 60 * 1000)
}
