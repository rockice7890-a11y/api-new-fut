# 🚀 Vercel Deployment Guide - Hotel Management System

## نظرة عامة (Overview)

هذا الدليل يوضح كيفية نشر نظام إدارة الفنادق المتقدم على منصة Vercel بنجاح.

## متطلبات النشر (Deployment Requirements)

### 1. المتطلبات الأساسية
- ✅ **Node.js 18.18+** (يدعمه Vercel تلقائياً)
- ✅ **npm أو yarn** لإدارة الحزم
- ✅ **حساب Vercel** (مجاني متاح)
- ✅ **قاعدة بيانات إنتاجية** (PostgreSQL مُوصى به)

### 2. المتغيرات البيئية المطلوبة
انسخ جميع المتغيرات من ملف `.env.example` إلى Vercel Environment Variables:

#### متغيرات أساسية:
```env
DATABASE_URL="postgresql://..."
DIRECT_URL="postgresql://..."
JWT_SECRET="your-strong-secret-key"
REFRESH_TOKEN_SECRET="refresh-secret"
QR_SECRET_KEY="HotelBookingQR2025SecretKey1234"
ALLOWED_ORIGINS="https://your-domain.vercel.app"
NEXT_PUBLIC_API_URL="https://your-domain.vercel.app"
```

## خطوات النشر (Deployment Steps)

### الخطوة 1: تحضير المشروع
```bash
# تأكد من أن جميع الملفات جاهزة
git add .
git commit -m "Ready for Vercel deployment"

# تأكد من أن package.json يحتوي على:
# - "build": "prisma generate && next build"
# - "vercel:build": "npm run db:generate && npm run build"
```

### الخطوة 2: ربط المشروع بـ Vercel

#### أ) عبر واجهة Vercel:
1. اذهب إلى [vercel.com](https://vercel.com)
2. انقر على "New Project"
3. اختر مستودع GitHub/ GitLab
4. حدد مشروع `hotel-management-system`
5. انقر على "Deploy"

#### ب) عبر CLI (اختياري):
```bash
# تثبيت Vercel CLI
npm i -g vercel

# تسجيل الدخول
vercel login

# ربط المشروع
vercel

# نشر للإنتاج
vercel --prod
```

### الخطوة 3: إعداد Environment Variables

1. في لوحة تحكم Vercel، اذهب إلى **Settings > Environment Variables**
2. أضف جميع المتغيرات من `.env.example`
3. **مهم**: اختر البيئة المناسبة:
   - **Production**: `DATABASE_URL`, `JWT_SECRET`, `NEXT_PUBLIC_API_URL`
   - **Development**: `DEBUG=true`
   - **Preview**: للمعاينة

### الخطوة 4: إعداد قاعدة البيانات

#### قاعدة بيانات الإنتاج (Production Database):
```bash
# مثال مع Neon (PostgreSQL السحابي)
DATABASE_URL="postgresql://user:pass@ep-xxxx-xx-xx-xx-xx-xx.neon.tech/db?sslmode=require"

# مثال مع Supabase
DATABASE_URL="postgresql://postgres:password@db.xxxxxx.supabase.co:5432/postgres"
```

#### تشغيل Migrations:
```bash
# في terminal Vercel أو محليًا
npx prisma migrate deploy
npx prisma generate
```

### الخطوة 5: إعداد الدومين المخصص (اختياري)

1. في Vercel Dashboard → **Settings > Domains**
2. أضف نطاقك المخصص
3. حدث DNS records:
   ```
   Type: CNAME
   Name: www
   Value: cname.vercel-dns.com
   
   Type: A
   Name: @
   Value: 76.76.19.61
   ```

## إعدادات محسنة لـ Vercel

### 1. `vercel.json` (مُعد مسبقاً)
```json
{
  "functions": {
    "app/api/**": {
      "maxDuration": 60
    }
  },
  "regions": ["fra1"]
}
```

### 2. `next.config.js` (مُعد مسبقاً)
- تحسين الأداء للـ API routes
- إعدادات الأمان
- تحسين الذاكرة

### 3. Build Scripts محسنة:
```json
{
  "build": "prisma generate && next build",
  "vercel:build": "npm run db:generate && npm run build"
}
```

## مراقبلة النشر (Monitoring)

### 1. مراقبة الوظائف (Function Monitoring)
- راقب **Functions** في لوحة تحكم Vercel
- تحقق من **Logs** عند وجود مشاكل
- راقب **Performance** و **Analytics**

### 2. قاعدة البيانات
- راقب **Database Health** في مزود الخدمة
- تحقق من **Connections** و **Queries Performance**

### 3. الأمان
- راجع **Security Headers** في المتصفح
- تأكد من **HTTPS** يعمل بشكل صحيح
- تحقق من **CORS** configuration

## حل المشاكل الشائعة

### 1. خطأ Build Failures
```bash
# تحقق من logs في Vercel Dashboard
# تأكد من أن جميع dependencies مثبتة
# تأكد من أن package.json صحيح
```

### 2. مشاكل قاعدة البيانات
```bash
# تأكد من أن DATABASE_URL صحيح
# تأكد من أن migrations مُطبقة
# تأكد من SSL settings
```

### 3. مشاكل Environment Variables
- تأكد من أن جميع المتغيرات مُعرَّفة
- تأكد من الـ naming (Case Sensitive)
- تأكد من الـ escaping للـ passwords

### 4. مشاكل CORS
```env
ALLOWED_ORIGINS="https://your-domain.vercel.app"
```

## نصائح الأمان للإنتاج

### 1. مفاتيح قوية
```bash
# أنشئ مفاتيح عشوائية قوية
JWT_SECRET=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -hex 16)
```

### 2. قاعدة البيانات آمنة
- استخدم SSL connection
- فعّل connection pooling
- راقب الاستعلامات البطيئة

### 3. المراقبة والتحليل
- فعل Vercel Analytics
- راقب performance metrics
- فعّل error tracking

## الدعم والصيانة

### التحديثات
```bash
# تحديث المكتبات
npm update

# إعادة النشر
vercel --prod
```

### النسخ الاحتياطية
- نسخ احتياطية لقاعدة البيانات
- نسخة احتياطية من Environment Variables
- نسخة احتياطية من إعدادات DNS

## معلومات الاتصال

**📧 الدعم:** [your-email@domain.com]  
**🌐 الدومين:** https://your-domain.vercel.app  
**📊 لوحة التحكم:** https://vercel.com/dashboard

---

**🎯 الخلاصة:** اتباع هذا الدليل سيضمن نشر ناجح وآمن لنظام إدارة الفنادق على Vercel.

**المؤلف:** MiniMax Agent  
**التاريخ:** 2025-11-22  
**الإصدار:** 1.0.0