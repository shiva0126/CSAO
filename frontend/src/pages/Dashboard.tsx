import { useDashboard } from '@/lib/queries'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#65a30d',
  INFO: '#64748b',
}

function KpiCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="text-sm text-muted-foreground">{label}</div>
        <div className="text-3xl font-semibold mt-1">{value}</div>
        {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
      </CardContent>
    </Card>
  )
}

export function DashboardPage() {
  const { data, isLoading, error } = useDashboard()

  if (isLoading) return <p className="text-muted-foreground">Loading dashboard…</p>
  if (error || !data) return <p className="text-destructive">Failed to load dashboard.</p>

  const severityData = Object.entries(data.findings_by_severity || {}).map(([severity, count]) => ({
    severity,
    count,
  }))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">{data.assessment_name || 'Executive Dashboard'}</h1>
          <p className="text-muted-foreground text-sm">
            {data.cloud_provider} · {data.number_of_accounts} account(s) · {data.regions?.length ?? 0} region(s)
          </p>
        </div>
        <Badge variant={data.assessment_status === 'FAILED' ? 'destructive' : 'secondary'}>
          {data.assessment_status}
        </Badge>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard label="Findings" value={data.findings} />
        <KpiCard label="High Risk Findings" value={data.high_risk_findings} />
        <KpiCard label="Threat Scenarios" value={data.threat_scenarios} />
        <KpiCard label="Attack Paths" value={data.attack_paths} />
        <KpiCard label="Resources Discovered" value={data.resources_discovered} />
        <KpiCard label="Evidence Sources" value={data.evidence_sources} />
        <KpiCard
          label="Checklist Progress"
          value={`${data.checklist_progress?.PASS ?? 0}/${data.checklist_progress?.total ?? 0}`}
          sub="controls passing"
        />
        <KpiCard label="Manual Reviews Remaining" value={data.manual_reviews_remaining} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings by Severity</CardTitle>
        </CardHeader>
        <CardContent className="h-64">
          {severityData.length === 0 ? (
            <p className="text-sm text-muted-foreground">No findings yet — run an assessment to populate this.</p>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="severity" fontSize={12} />
                <YAxis allowDecimals={false} fontSize={12} />
                <Tooltip />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry) => (
                    <Cell key={entry.severity} fill={SEVERITY_COLOR[entry.severity] ?? '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Recent Assessments</CardTitle>
          </CardHeader>
          <CardContent>
            {data.recent_assessments?.length ? (
              <ul className="space-y-2 text-sm">
                {data.recent_assessments.map((a) => (
                  <li key={a.id} className="flex items-center justify-between">
                    <span>{a.name}</span>
                    <Badge variant="outline">{a.status}</Badge>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">No assessments run yet.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Platform Health</CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-1">
            <div>Provider available: {data.platform_health?.provider_available ? 'Yes' : 'No'}</div>
            <div>Accounts validated: {data.platform_health?.accounts_validated}</div>
            <div>Collectors enabled: {data.platform_health?.collector_count}</div>
            <div>Safety validation: {data.safety_validation?.status}</div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
