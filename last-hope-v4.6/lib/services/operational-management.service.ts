import { prisma } from "@/lib/prisma"
import { OperationalStatus, OperationType, ControlAction, LockLevel, UserRole } from "@prisma/client"

export interface OperationalControlData {
  moduleName: string
  hotelId?: string
  action: ControlAction
  reason?: string
  message?: string
  controlLevel?: LockLevel
  allowedRoles?: UserRole[]
  restrictedRoles?: UserRole[]
  unlockAt?: Date
  adminOnly?: boolean
  allowOverride?: boolean
  performedBy: string
}

export interface OperationStats {
  [key: string]: number
}

export interface PerformanceMetrics {
  metricName: string
  value: number
  status: string
  measuredAt: Date
  moduleName?: string
  hotelId?: string
}

// ===========================================
// OPERATIONAL MANAGEMENT SERVICE
// خدمات إدارة العمليات - نظام شامل للتحكم الإداري
// ===========================================

export class OperationalManagementService {
  
  // ===========================================
  // CONTROLLING OPERATIONS
  // التحكم في العمليات
  // ===========================================

  /**
   * تطبيق عملية تحكم (قفل، فتح، إخفاء، إلخ)
   */
  static async controlOperation(data: OperationalControlData): Promise<any> {
    const { 
      moduleName, 
      hotelId, 
      action, 
      reason, 
      message, 
      controlLevel = LockLevel.SOFT_LOCK,
      allowedRoles,
      restrictedRoles = [],
      unlockAt,
      adminOnly = false,
      allowOverride = false,
      performedBy 
    } = data

    try {
      // التحقق من وجود الوحدة
      let operationalModule = await prisma.operationalModule.findFirst({
        where: { 
          moduleName,
          ...(hotelId && { hotelId })
        }
      })

      // تحديد الحالة الجديدة
      const currentStatus = operationalModule?.status || OperationalStatus.ACTIVE
      const newStatus = this.mapActionToStatus(action, currentStatus)

      // إنشاء أو تحديث الوحدة
      if (!operationalModule) {
        operationalModule = await prisma.operationalModule.create({
          data: {
            moduleName,
            hotelId: hotelId || null,
            operationType: this.inferOperationType(moduleName),
            status: newStatus,
            controlLevel,
            lockedBy: performedBy,
            lockedAt: new Date(),
            unlockAt: unlockAt || null,
            lastAction: action,
            lockMessage: message,
            adminOnly,
            allowOverride,
            requiredRole: undefined,
            restrictedRoles,
            allowedRoles: allowedRoles || [],
            logActions: true
          }
        })
      } else {
        operationalModule = await prisma.operationalModule.update({
          where: { id: operationalModule.id },
          data: {
            status: newStatus,
            controlLevel,
            lockedBy: performedBy,
            lockedAt: new Date(),
            unlockAt: unlockAt || null,
            lastAction: action,
            lockMessage: message,
            adminOnly,
            allowOverride,
            restrictedRoles,
            updatedAt: new Date()
          }
        })
      }

      // تسجيل العملية في السجل
      await this.logOperation({
        moduleId: operationalModule.id,
        action,
        performedBy,
        reason,
        previousStatus: currentStatus,
        newStatus,
        message,
        metadata: {
          controlLevel,
          adminOnly,
          allowOverride,
          allowedRoles,
          restrictedRoles
        }
      })

      // إرسال تنبيهات إذا لزم الأمر
      if (newStatus === OperationalStatus.EMERGENCY || newStatus === OperationalStatus.MAINTENANCE) {
        await this.createOperationalAlert({
          hotelId: operationalModule.hotelId || undefined,
          alertType: newStatus === OperationalStatus.EMERGENCY ? 'error' : 'warning',
          title: `${action} - ${moduleName}`,
          message: message || `تم ${this.getActionMessage(action)} ${moduleName}`,
          priority: newStatus === OperationalStatus.EMERGENCY ? 'critical' : 'high',
          targetRoles: ['ADMIN', 'HOTEL_MANAGER']
        })
      }

      // التحقق من الجدولة التلقائية
      if (unlockAt) {
        await this.scheduleAutoUnlock(operationalModule.id, unlockAt)
      }

      return {
        success: true,
        module: operationalModule,
        action,
        status: newStatus,
        timestamp: new Date()
      }

    } catch (error) {
      console.error('Operational Control Error:', error)
      throw new Error(`فشل في التحكم في العملية: ${error instanceof Error ? error.message : 'خطأ غير معروف'}`)
    }
  }

  /**
   * ربط العملية تلقائياً بحجوزات الفندق
   */
  static async autoLinkToBookings(hotelId: string, moduleName: string): Promise<void> {
    try {
      const operationalModule = await prisma.operationalModule.findFirst({
        where: { moduleName, hotelId }
      })

      if (!operationalModule) return

      // ربط بحجوزات الفندق النشطة
      const activeBookings = await prisma.booking.findMany({
        where: {
          hotelId,
          status: {
            in: ['CONFIRMED', 'CHECKED_IN']
          }
        },
        select: {
          id: true,
          status: true,
          checkInDate: true,
          checkOutDate: true
        }
      })

      // إذا كانت العملية معلقة، إشعار الحجوزات المتأثرة
      if (operationalModule.status === OperationalStatus.SUSPENDED) {
        await this.notifyAffectedBookings(activeBookings, operationalModule)
      }

    } catch (error) {
      console.error('Auto Link Error:', error)
    }
  }

  // ===========================================
  // MONITORING & ALERTS
  // المراقبة والتنبيهات
  // ===========================================

  /**
   * إنشاء تنبيه تشغيلي
   */
  static async createOperationalAlert(data: any): Promise<any> {
    const alert = await prisma.operationalAlert.create({
      data: {
        ...data,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    })

    return alert
  }

  /**
   * جمع إحصائيات الأداء
   */
  static async collectPerformanceMetrics(hotelId?: string): Promise<PerformanceMetrics[]> {
    try {
      const metrics: PerformanceMetrics[] = []

      // وقت الاستجابة
      const responseTime = await this.measureResponseTime()
      metrics.push({
        metricName: 'response_time',
        value: responseTime,
        status: responseTime > 2000 ? 'critical' : responseTime > 1000 ? 'warning' : 'normal',
        measuredAt: new Date(),
        hotelId: hotelId || undefined
      })

      // معدل الأخطاء
      const errorRate = await this.measureErrorRate()
      metrics.push({
        metricName: 'error_rate',
        value: errorRate,
        status: errorRate > 0.1 ? 'critical' : errorRate > 0.05 ? 'warning' : 'normal',
        measuredAt: new Date(),
        hotelId: hotelId || undefined
      })

      // استخدام الذاكرة
      const memoryUsage = await this.measureMemoryUsage()
      metrics.push({
        metricName: 'memory_usage',
        value: memoryUsage,
        status: memoryUsage > 80 ? 'critical' : memoryUsage > 60 ? 'warning' : 'normal',
        measuredAt: new Date(),
        hotelId: hotelId || undefined
      })

      // حفظ المقاييس في قاعدة البيانات
      for (const metric of metrics) {
        await prisma.performanceMonitor.create({
          data: {
            hotelId: metric.hotelId || null,
            metricName: metric.metricName,
            moduleName: 'SYSTEM',
            value: metric.value,
            threshold: this.getThreshold(metric.metricName),
            status: metric.status,
            isAlerting: metric.status === 'critical' || metric.status === 'warning',
            measuredAt: metric.measuredAt
          }
        })
      }

      return metrics

    } catch (error) {
      console.error('Performance Collection Error:', error)
      return []
    }
  }

  /**
   * فحص النظام والتنبيهات التلقائية
   */
  static async performSystemHealthCheck(): Promise<any> {
    const issues: string[] = []
    const criticalIssues: string[] = []

    try {
      // فحص الحجوزات المعلقة
      const pendingBookings = await prisma.booking.count({
        where: {
          status: 'PENDING',
          createdAt: {
            lt: new Date(Date.now() - 24 * 60 * 60 * 1000) // أكثر من 24 ساعة
          }
        }
      })

      if (pendingBookings > 0) {
        issues.push(`يوجد ${pendingBookings} حجز معلق لأكثر من 24 ساعة`)
      }

      // فحص الغرف غير المتاحة
      const unavailableRooms = await prisma.room.count({
        where: {
          status: {
            in: ['MAINTENANCE']
          },
          updatedAt: {
            lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // أكثر من 7 أيام
          }
        }
      })

      if (unavailableRooms > 0) {
        issues.push(`يوجد ${unavailableRooms} غرفة في صيانة لأكثر من 7 أيام`)
      }

      // فحص المدفوعات المتأخرة
      const overduePayments = await prisma.invoice.count({
        where: {
          status: 'OVERDUE',
          dueDate: {
            lt: new Date()
          }
        }
      })

      if (overduePayments > 0) {
        criticalIssues.push(`يوجد ${overduePayments} فاتورة متأخرة`)
      }

      // إرسال التنبيهات الحرجة
      if (criticalIssues.length > 0) {
        await this.createOperationalAlert({
          alertType: 'error',
          title: 'مشاكل حرجة في النظام',
          message: criticalIssues.join('\n'),
          priority: 'critical',
          targetRoles: ['ADMIN', 'HOTEL_MANAGER']
        })
      }

      // إرسال تنبيهات عادية
      if (issues.length > 0) {
        await this.createOperationalAlert({
          alertType: 'warning',
          title: 'تحذيرات في النظام',
          message: issues.join('\n'),
          priority: 'high',
          targetRoles: ['ADMIN', 'HOTEL_MANAGER']
        })
      }

      return {
        status: criticalIssues.length > 0 ? 'critical' : issues.length > 0 ? 'warning' : 'healthy',
        issues,
        criticalIssues,
        timestamp: new Date()
      }

    } catch (error) {
      console.error('Health Check Error:', error)
      return {
        status: 'error',
        error: error instanceof Error ? error.message : 'خطأ غير معروف',
        timestamp: new Date()
      }
    }
  }

  // ===========================================
  // BACKUP & RECOVERY
  // النسخ الاحتياطي والاستعادة
  // ===========================================

  /**
   * إنشاء نسخة احتياطية
   */
  static async createBackup(hotelId?: string, backupType: 'full' | 'incremental' = 'incremental'): Promise<any> {
    try {
      const backupId = `backup_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      
      // حفظ معلومات النسخة الاحتياطية
      const backup = await prisma.backupConfiguration.create({
        data: {
          hotelId: hotelId || null,
          backupName: backupId,
          backupType,
          schedule: 'MANUAL',
          isEnabled: true,
          isRunning: true,
          lastBackup: new Date(),
          nextBackup: new Date(Date.now() + 24 * 60 * 60 * 1000) // غداً
        }
      })

      // تنفيذ عملية النسخ الاحتياطي
      // TODO: تنفيذ عملية النسخ الفعلي

      // تحديث حالة النسخة الاحتياطية
      await prisma.backupConfiguration.update({
        where: { id: backup.id },
        data: {
          isRunning: false,
          lastBackup: new Date()
        }
      })

      return {
        success: true,
        backupId,
        backupName: backup.backupName,
        timestamp: new Date()
      }

    } catch (error) {
      console.error('Backup Creation Error:', error)
      throw new Error(`فشل في إنشاء النسخة الاحتياطية: ${error instanceof Error ? error.message : 'خطأ غير معروف'}`)
    }
  }

  // ===========================================
  // UTILITY METHODS
  // طرق مساعدة
  // ===========================================

  /**
   * تحويل الإجراء إلى حالة
   */
  private static mapActionToStatus(action: ControlAction, currentStatus: OperationalStatus): OperationalStatus {
    switch (action) {
      case 'LOCK':
        return OperationalStatus.LOCKED
      case 'UNLOCK':
        return OperationalStatus.ACTIVE
      case 'HIDE':
        return OperationalStatus.HIDDEN
      case 'SHOW':
        return OperationalStatus.ACTIVE
      case 'SUSPEND':
        return OperationalStatus.SUSPENDED
      case 'ACTIVATE':
        return OperationalStatus.ACTIVE
      case 'MAINTENANCE_MODE':
        return OperationalStatus.MAINTENANCE
      case 'EMERGENCY_MODE':
        return OperationalStatus.EMERGENCY
      default:
        return currentStatus
    }
  }

  /**
   * استنتاج نوع العملية
   */
  private static inferOperationType(moduleName: string): OperationType {
    if (moduleName.includes('BOOKING')) return OperationType.BOOKING_SYSTEM
    if (moduleName.includes('PAYMENT')) return OperationType.PAYMENT_SYSTEM
    if (moduleName.includes('ROOM')) return OperationType.ROOM_MANAGEMENT
    if (moduleName.includes('STAFF')) return OperationType.STAFF_MANAGEMENT
    if (moduleName.includes('FINANCIAL')) return OperationType.FINANCIAL_SYSTEM
    return OperationType.BOOKING_SYSTEM
  }

  /**
   * تسجيل العملية
   */
  private static async logOperation(data: any): Promise<void> {
    await prisma.operationLog.create({
      data
    })
  }

  /**
   * جدولة إلغاء القفل التلقائي
   */
  private static async scheduleAutoUnlock(moduleId: string, unlockAt: Date): Promise<void> {
    // TODO: تنفيذ جدولة إلغاء القفل التلقائي باستخدام نظام جدولة
    await prisma.scheduledOperation.create({
      data: {
        moduleId,
        operationName: `Auto Unlock ${moduleId}`,
        action: ControlAction.UNLOCK,
        scheduledAt: unlockAt,
        isActive: true,
        repeatType: null
      }
    })
  }

  /**
   * إشعار الحجوزات المتأثرة
   */
  private static async notifyAffectedBookings(bookings: any[], operationalModule: any): Promise<void> {
    for (const booking of bookings) {
      await prisma.operationalAlert.create({
        data: {
          hotelId: operationalModule.hotelId,
          alertType: 'warning',
          title: 'تأثر الحجز بالعملية',
          message: `تم تعليق ${operationalModule.moduleName} - الحجز رقم: ${booking.bookingReference}`,
          priority: 'medium',
          targetRoles: ['ADMIN', 'HOTEL_MANAGER']
        }
      })
    }
  }

  /**
   * قياس وقت الاستجابة
   */
  private static async measureResponseTime(): Promise<number> {
    const start = Date.now()
    try {
      await prisma.booking.count()
      return Date.now() - start
    } catch {
      return 5000 // خطأ في القياس
    }
  }

  /**
   * قياس معدل الأخطاء
   */
  private static async measureErrorRate(): Promise<number> {
    try {
      const totalRequests = 100 // محاكاة
      const errorRequests = 0 // محاكاة
      return errorRequests / totalRequests
    } catch {
      return 0
    }
  }

  /**
   * قياس استخدام الذاكرة
   */
  private static async measureMemoryUsage(): Promise<number> {
    // محاكاة - في التطبيق الحقيقي سيتم استخدام مقاييس النظام
    return Math.random() * 100
  }

  /**
   * الحصول على الحد المراقب
   */
  private static getThreshold(metricName: string): number {
    const thresholds: Record<string, number> = {
      'response_time': 2000,
      'error_rate': 0.05,
      'memory_usage': 80,
      'cpu_usage': 80
    }
    return thresholds[metricName] || 100
  }

  /**
   * الحصول على رسالة الإجراء
   */
  private static getActionMessage(action: ControlAction): string {
    const messages: Record<ControlAction, string> = {
      'LOCK': 'قفل',
      'UNLOCK': 'فتح',
      'HIDE': 'إخفاء',
      'SHOW': 'إظهار',
      'SUSPEND': 'تعليق',
      'ACTIVATE': 'تفعيل',
      'MAINTENANCE_MODE': 'وضع الصيانة',
      'EMERGENCY_MODE': 'وضع الطوارئ'
    }
    return messages[action] || action
  }
}