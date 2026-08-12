import { Navigate, Route, Routes } from 'react-router-dom'
import { useMe } from '@/lib/queries'
import { Layout } from '@/components/Layout'
import { LoginPage } from '@/pages/Login'
import { SetupPage } from '@/pages/Setup'
import { DashboardPage } from '@/pages/Dashboard'
import { FindingsPage } from '@/pages/Findings'
import { AssessmentsPage } from '@/pages/Assessments'
import { ReportsPage } from '@/pages/Reports'
import { AdminPage } from '@/pages/Admin'
import { DocsPage } from '@/pages/Docs'
import { ToolsPage } from '@/pages/Tools'

function FullScreenLoader() {
  return <div className="min-h-screen flex items-center justify-center text-muted-foreground">Loading…</div>
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { data: me, isLoading } = useMe()
  if (isLoading) return <FullScreenLoader />
  if (me?.needs_setup) return <Navigate to="/setup" replace />
  if (!me?.authenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  const { data: me, isLoading } = useMe()

  if (isLoading) return <FullScreenLoader />

  return (
    <Routes>
      <Route
        path="/login"
        element={me?.authenticated ? <Navigate to="/dashboard" replace /> : <LoginPage />}
      />
      <Route
        path="/setup"
        element={me?.needs_setup ? <SetupPage /> : <Navigate to={me?.authenticated ? '/dashboard' : '/login'} replace />}
      />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/assessments" element={<AssessmentsPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/docs" element={<DocsPage />} />
        <Route path="/tools" element={<ToolsPage />} />
        <Route path="/admin" element={<AdminPage />} />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}
