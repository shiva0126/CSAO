import { useMemo, type ReactNode } from 'react'
import { useChecklist, useCoverage, useDashboard, useRisk } from '@/lib/queries'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
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

function ChartCard({ title, children, height = 260 }: { title: string; children: ReactNode; height?: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent style={{ height }}>{children}</CardContent>
    </Card>
  )
}

function EmptyState({ label }: { label: string }) {
  return <p className="text-sm text-muted-foreground h-full flex items-center justify-center">{label}</p>
}

export function DashboardPage() {
  const { data, isLoading, error } = useDashboard()
  const coverage = useCoverage()
  const risk = useRisk()
  const checklist = useChecklist()

  const severityData = useMemo(
    () => Object.entries(data?.findings_by_severity ?? {}).map(([severity, count]) => ({ severity, count })),
    [data],
  )

  const coverageData = coverage.data?.rows ?? []

  const evidenceCoverageData = (data?.evidence_coverage ?? []).map((e) => ({
    service: e.service,
    coveragePct: e.coverage === '100%' ? 100 : e.coverage === 'Limited' ? 50 : 0,
  }))

  const topRisk = (risk.data?.rows ?? []).slice(0, 10).map((r) => ({
    name: (r.title || r.finding_id || '').slice(0, 28),
    risk_score: r.risk_score,
    severity: r.severity,
  }))

  const health = data?.assessment_health_score
  const healthRadar = health
    ? [
        { metric: 'Configuration', value: health.configuration },
        { metric: 'Permissions', value: health.permissions },
        { metric: 'Evidence Coverage', value: health.evidence_coverage },
        { metric: 'Collector Success', value: health.collector_success },
        { metric: 'Cloud Coverage', value: health.cloud_coverage },
      ]
    : []

  const tacticFrequency = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const row of checklist.data?.rows ?? []) {
      for (const tactic of row.mitre_mapping?.tactics ?? []) {
        counts[tactic] = (counts[tactic] ?? 0) + 1
      }
    }
    return Object.entries(counts)
      .map(([tactic, count]) => ({ tactic, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)
  }, [checklist.data])

  if (isLoading) return <p className="text-muted-foreground">Loading dashboard…</p>
  if (error || !data) return <p className="text-destructive">Failed to load dashboard.</p>

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

      <div className="grid md:grid-cols-2 gap-4">
        <ChartCard title="Findings by Severity">
          {severityData.length === 0 ? (
            <EmptyState label="No findings yet — run an assessment to populate this." />
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
        </ChartCard>

        <ChartCard title="Findings by Severity (share)">
          {severityData.length === 0 ? (
            <EmptyState label="No findings yet." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="count"
                  nameKey="severity"
                  innerRadius={50}
                  outerRadius={85}
                  paddingAngle={2}
                >
                  {severityData.map((entry) => (
                    <Cell key={entry.severity} fill={SEVERITY_COLOR[entry.severity] ?? '#64748b'} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Assessment Health Score">
          {healthRadar.length === 0 ? (
            <EmptyState label="No health data yet." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={healthRadar}>
                <PolarGrid />
                <PolarAngleAxis dataKey="metric" fontSize={11} />
                <PolarRadiusAxis domain={[0, 100]} fontSize={10} />
                <Radar dataKey="value" stroke="#2563eb" fill="#2563eb" fillOpacity={0.35} />
                <Tooltip />
              </RadarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Checklist Coverage by Domain">
          {coverageData.length === 0 ? (
            <EmptyState label="No coverage data yet." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={coverageData} layout="vertical" margin={{ left: 24 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" domain={[0, 100]} fontSize={11} unit="%" />
                <YAxis type="category" dataKey="domain" width={160} fontSize={11} />
                <Tooltip />
                <Bar dataKey="coverage_percentage" radius={[0, 4, 4, 0]} fill="#0ea5e9" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Evidence Coverage by Service">
          {evidenceCoverageData.length === 0 ? (
            <EmptyState label="No evidence coverage data yet." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={evidenceCoverageData} layout="vertical" margin={{ left: 24 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" domain={[0, 100]} fontSize={11} unit="%" />
                <YAxis type="category" dataKey="service" width={120} fontSize={11} />
                <Tooltip />
                <Bar dataKey="coveragePct" radius={[0, 4, 4, 0]} fill="#16a34a" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Top 10 Highest-Risk Findings">
          {topRisk.length === 0 ? (
            <EmptyState label="No findings yet." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topRisk} layout="vertical" margin={{ left: 24 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" fontSize={11} />
                <YAxis type="category" dataKey="name" width={180} fontSize={10} />
                <Tooltip />
                <Bar dataKey="risk_score" radius={[0, 4, 4, 0]}>
                  {topRisk.map((d, i) => (
                    <Cell key={i} fill={SEVERITY_COLOR[d.severity] ?? '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Top MITRE ATT&CK Tactics">
          {tacticFrequency.length === 0 ? (
            <EmptyState label="No MITRE mapping data yet." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={tacticFrequency} layout="vertical" margin={{ left: 24 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" allowDecimals={false} fontSize={11} />
                <YAxis type="category" dataKey="tactic" width={160} fontSize={11} />
                <Tooltip />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} fill="#9333ea" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

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
