#!/bin/bash

# سكريبت تطبيق النظام المتقدم للأمان على جميع مسارات الـ APIs
# Advanced Security Implementation Script for APIs

set -e

echo "🚀 بدء تطبيق النظام المتقدم للأمان..."
echo "Starting Advanced Security Implementation..."

# الألوان للنص
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# إنشاء مجلد النسخ الاحتياطية
BACKUP_DIR="backup-$(date +%Y%m%d-%H%M%S)"
echo -e "${BLUE}📁 إنشاء مجلد النسخ الاحتياطية: $BACKUP_DIR${NC}"
mkdir -p "$BACKUP_DIR"

# قائمة الملفات المحسنة الجاهزة
declare -a FILES_TO_APPLY=(
    "app/api/payments/route-advanced.ts:app/api/payments/route.ts"
    "app/api/payments/[id]/route-advanced.ts:app/api/payments/[id]/route.ts"
    "app/api/admin/users/route-advanced.ts:app/api/admin/users/route.ts"
    "app/api/auth/login/route-advanced.ts:app/api/auth/login/route.ts"
    "app/api/bookings/route-advanced.ts:app/api/bookings/route.ts"
    "app/api/hotels/route-advanced.ts:app/api/hotels/route.ts"
)

echo -e "${YELLOW}📋 قائمة الملفات المراد تطبيقها:${NC}"
for file_pair in "${FILES_TO_APPLY[@]}"; do
    source_file="${file_pair%%:*}"
    target_file="${file_pair##*:}"
    echo "  - $source_file → $target_file"
done

echo ""
read -p "هل تريد المتابعة؟ (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}❌ تم إلغاء العملية${NC}"
    exit 1
fi

# تطبيق كل ملف
successful_applications=0
failed_applications=0

echo -e "${BLUE}🔄 بدء تطبيق الملفات...${NC}"
echo "Starting file applications..."

for file_pair in "${FILES_TO_APPLY[@]}"; do
    source_file="${file_pair%%:*}"
    target_file="${file_pair##*:}"
    
    echo ""
    echo -e "${YELLOW}📄 معالجة: $target_file${NC}"
    
    # التحقق من وجود الملف المصدر
    if [[ ! -f "$source_file" ]]; then
        echo -e "${RED}❌ ملف مصدر غير موجود: $source_file${NC}"
        ((failed_applications++))
        continue
    fi
    
    # إنشاء نسخة احتياطية من الملف الأصلي إذا كان موجوداً
    if [[ -f "$target_file" ]]; then
        backup_file="$BACKUP_DIR/$(basename "$target_file").backup"
        echo "💾 إنشاء نسخة احتياطية: $backup_file"
        cp "$target_file" "$backup_file"
    fi
    
    # تطبيق الملف المحسن
    echo "🔧 تطبيق: $source_file → $target_file"
    if cp "$source_file" "$target_file"; then
        echo -e "${GREEN}✅ تم تطبيق بنجاح${NC}"
        ((successful_applications++))
    else
        echo -e "${RED}❌ فشل في التطبيق${NC}"
        ((failed_applications++))
    fi
done

echo ""
echo -e "${BLUE}📊 ملخص النتائج:${NC}"
echo "✅ التطبيقات الناجحة: $successful_applications"
echo "❌ التطبيقات الفاشلة: $failed_applications"

if [[ $successful_applications -gt 0 ]]; then
    echo ""
    echo -e "${GREEN}🎉 تم تطبيق النظام المتقدم للأمان بنجاح!${NC}"
    echo ""
    echo -e "${YELLOW}📋 الخطوات التالية:${NC}"
    echo "1. تشغيل الاختبارات: npm run test:advanced-security"
    echo "2. مراجعة السجلات: tail -f logs/security.log"
    echo "3. مراقبة الأداء: npm run performance-monitor"
    echo ""
    echo -e "${BLUE}🔒 النسخ الاحتياطية محفوظة في: $BACKUP_DIR${NC}"
else
    echo -e "${RED}💥 فشل في تطبيق أي ملفات${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}✨ انتهى تطبيق النظام المتقدم للأمان!${NC}"