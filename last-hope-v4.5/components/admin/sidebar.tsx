'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { LayoutDashboard, Users, Building2, Notebook as LogBook, Shield, Settings, LogOut } from 'lucide-react'

export default function Sidebar() {
  const pathname = usePathname()

  const menuItems = [
    { icon: LayoutDashboard, label: 'لوحة التحكم', href: '/ketan-manger-hotel2025' },
    { icon: Users, label: 'المستخدمين', href: '/ketan-manger-hotel2025#users' },
    { icon: Building2, label: 'الفنادق', href: '/ketan-manger-hotel2025#hotels' },
    { icon: LogBook, label: 'السجلات', href: '/ketan-manger-hotel2025#audit' },
    { icon: Shield, label: 'الأذونات', href: '/ketan-manger-hotel2025#permissions' },
    { icon: Settings, label: 'الإعدادات', href: '/ketan-manger-hotel2025#settings' },
  ]

  return (
    <aside className="w-64 border-r border-sidebar-border bg-sidebar text-sidebar-foreground hidden md:block">
      <div className="p-6">
        <h1 className="text-2xl font-bold text-sidebar-primary">كيتان مدير الفنادق</h1>
      </div>

      <nav className="space-y-2 p-4">
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = pathname === item.href || pathname.includes(item.href.split('#')[1])

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-4 py-2 rounded-lg transition-colors ${
                isActive
                  ? 'bg-sidebar-primary text-sidebar-primary-foreground'
                  : 'hover:bg-sidebar-accent text-sidebar-foreground'
              }`}
            >
              <Icon size={20} />
              <span>{item.label}</span>
            </Link>
          )
        })}
      </nav>

      <div className="absolute bottom-6 left-4 right-4 border-t border-sidebar-border pt-4">
        <button className="flex items-center gap-3 w-full px-4 py-2 rounded-lg hover:bg-sidebar-accent text-sidebar-foreground transition-colors">
          <LogOut size={20} />
          <span>تسجيل الخروج</span>
        </button>
      </div>
    </aside>
  )
}
