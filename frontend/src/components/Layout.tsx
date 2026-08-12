import { NavLink, Outlet } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, PlayCircle, FileText, Settings, BookOpen, Wrench } from 'lucide-react'
import { useMe, useLogout } from '@/lib/queries'
import { Button } from '@/components/ui/button'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/assessments', label: 'Assessments', icon: PlayCircle },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/docs', label: 'Docs', icon: BookOpen },
  { to: '/tools', label: 'Tools', icon: Wrench },
  { to: '/admin', label: 'Admin', icon: Settings },
]

export function Layout() {
  const { data: me } = useMe()
  const logout = useLogout()

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="w-56 shrink-0 border-r border-border flex flex-col">
        <div className="px-4 py-4 font-semibold text-lg tracking-tight">CSAO</div>
        <nav className="flex-1 px-2 space-y-1">
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                }`
              }
            >
              <Icon className="size-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-4 border-t border-border text-sm">
          <div className="font-medium">{me?.user?.display_name}</div>
          <div className="text-muted-foreground text-xs mb-2">{me?.user?.role}</div>
          <Button variant="outline" size="sm" className="w-full" onClick={() => logout.mutate()}>
            Log out
          </Button>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="max-w-7xl mx-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
