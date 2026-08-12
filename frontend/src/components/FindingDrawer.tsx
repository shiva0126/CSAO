import { ExternalLink } from 'lucide-react'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import {
  useAttackPaths,
  useChecklist,
  useCorrelatedThreats,
  useRecommendations,
  useRisk,
  useThreatScenarios,
} from '@/lib/queries'
import type { FindingRow } from '@/lib/types'

function severityVariant(severity: string): 'destructive' | 'secondary' | 'outline' {
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'destructive'
  if (severity === 'MEDIUM') return 'secondary'
  return 'outline'
}

export function FindingDrawer({ finding, onClose }: { finding: FindingRow | null; onClose: () => void }) {
  const checklist = useChecklist()
  const scenarios = useThreatScenarios()
  const correlated = useCorrelatedThreats()
  const attackPaths = useAttackPaths()
  const risk = useRisk()
  const recommendations = useRecommendations()

  const open = finding !== null
  if (!finding) return null

  const matchedChecklist = (checklist.data?.rows ?? []).filter((c) =>
    finding.checklist_controls?.includes(c.id),
  )
  const matchedScenarios = (scenarios.data?.rows ?? []).filter((s) =>
    finding.threat_scenarios?.includes(s.scenario_id),
  )
  const matchedCorrelated = (correlated.data?.rows ?? []).filter((c) =>
    finding.correlated_threats?.includes(c.correlation_id),
  )
  const matchedAttackPaths = (attackPaths.data?.candidates ?? []).filter((c) =>
    finding.attack_path_ids?.includes((c as { id?: string }).id ?? ''),
  )
  const matchedRisk = (risk.data?.rows ?? []).find(
    (r) => r.finding_id === finding.register_id || r.finding_id === finding.finding_id,
  )
  const matchedRecommendations = (recommendations.data?.rows ?? []).filter(
    (r) =>
      r.related_findings?.includes(finding.register_id) ||
      r.affected_resources?.includes(finding.register_id),
  )

  const mitreTactics = new Set<string>()
  const mitreTechniques = new Set<string>()
  for (const c of matchedChecklist) {
    c.mitre_mapping?.tactics?.forEach((t) => mitreTactics.add(t))
    c.mitre_mapping?.techniques?.forEach((t) => mitreTechniques.add(t))
  }
  for (const s of matchedScenarios) {
    s.mitre_mapping?.tactics?.forEach((t) => mitreTactics.add(t))
    s.mitre_mapping?.techniques?.forEach((t) => mitreTechniques.add(t))
  }

  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      <SheetContent className="w-full sm:max-w-xl overflow-y-auto">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <SheetTitle className="text-base">{finding.title || finding.resource}</SheetTitle>
            <Badge variant={severityVariant(finding.severity)}>{finding.severity}</Badge>
            {finding.crown_jewel && <Badge variant="outline">Crown Jewel</Badge>}
          </div>
          <SheetDescription>
            {finding.cloud_service} · {finding.resource} · Register {finding.register_id}
          </SheetDescription>
        </SheetHeader>

        <div className="px-4 pb-6">
          {(mitreTactics.size > 0 || mitreTechniques.size > 0) && (
            <div className="mb-4">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm">
                    Framework Reference (MITRE ATT&CK) ▾
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-72">
                  {[...mitreTactics].map((tactic) => (
                    <DropdownMenuItem key={`t-${tactic}`} disabled className="text-xs font-semibold">
                      Tactic: {tactic}
                    </DropdownMenuItem>
                  ))}
                  {[...mitreTechniques].map((technique) => (
                    <DropdownMenuItem key={technique} asChild>
                      <a
                        href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center justify-between w-full"
                      >
                        {technique}
                        <ExternalLink className="size-3" />
                      </a>
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}

          <Tabs defaultValue="overview">
            <TabsList className="flex-wrap h-auto">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="checklist">Checklist ({matchedChecklist.length})</TabsTrigger>
              <TabsTrigger value="threats">Threats ({matchedScenarios.length + matchedCorrelated.length})</TabsTrigger>
              <TabsTrigger value="attack-paths">Attack Paths ({matchedAttackPaths.length})</TabsTrigger>
              <TabsTrigger value="risk">Risk</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations ({matchedRecommendations.length})</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-2 text-sm">
              <div><span className="text-muted-foreground">Status:</span> {finding.status}</div>
              <div><span className="text-muted-foreground">Internet-facing:</span> {finding.internet_facing ? 'Yes' : 'No'}</div>
              <div><span className="text-muted-foreground">Risk bucket:</span> {finding.risk_bucket}</div>
              <div><span className="text-muted-foreground">Risk score:</span> {finding.risk}</div>
              {finding.analyst_notes && (
                <div>
                  <span className="text-muted-foreground">Analyst notes:</span> {finding.analyst_notes}
                </div>
              )}
            </TabsContent>

            <TabsContent value="checklist" className="space-y-3 text-sm">
              {matchedChecklist.length === 0 && <p className="text-muted-foreground">No matched checklist controls.</p>}
              {matchedChecklist.map((c) => (
                <div key={c.id} className="border border-border rounded-md p-2">
                  <div className="font-medium">{c.title}</div>
                  <div className="text-muted-foreground text-xs">{c.id} · {c.domain} · {c.status}</div>
                </div>
              ))}
            </TabsContent>

            <TabsContent value="threats" className="space-y-3 text-sm">
              {matchedScenarios.map((s) => (
                <div key={s.scenario_id} className="border border-border rounded-md p-2">
                  <div className="font-medium">{s.title}</div>
                  <div className="text-muted-foreground text-xs">{s.scenario_id} · {s.stride_category} · {s.status}</div>
                  <div className="text-xs mt-1">{s.business_impact}</div>
                </div>
              ))}
              {matchedCorrelated.map((c) => (
                <div key={c.correlation_id} className="border border-border rounded-md p-2">
                  <div className="font-medium">{c.correlation_id}</div>
                  <div className="text-xs mt-1">{c.correlation_reason}</div>
                </div>
              ))}
              {matchedScenarios.length === 0 && matchedCorrelated.length === 0 && (
                <p className="text-muted-foreground">No associated threat scenarios.</p>
              )}
            </TabsContent>

            <TabsContent value="attack-paths" className="space-y-3 text-sm">
              {matchedAttackPaths.length === 0 && <p className="text-muted-foreground">Not part of any attack path candidate.</p>}
              {matchedAttackPaths.map((c, i) => (
                <pre key={i} className="border border-border rounded-md p-2 text-xs overflow-x-auto">
                  {JSON.stringify(c, null, 2)}
                </pre>
              ))}
            </TabsContent>

            <TabsContent value="risk" className="space-y-2 text-sm">
              {matchedRisk ? (
                <>
                  <div><span className="text-muted-foreground">Risk score:</span> {matchedRisk.risk_score}</div>
                  <div><span className="text-muted-foreground">Likelihood:</span> {matchedRisk.likelihood}</div>
                  <div><span className="text-muted-foreground">Exposure:</span> {matchedRisk.exposure}</div>
                  <div><span className="text-muted-foreground">Business impact:</span> {matchedRisk.business_impact}</div>
                </>
              ) : (
                <p className="text-muted-foreground">No risk scoring recorded for this finding.</p>
              )}
            </TabsContent>

            <TabsContent value="recommendations" className="space-y-3 text-sm">
              {matchedRecommendations.length === 0 && <p className="text-muted-foreground">No recommendations linked yet.</p>}
              {matchedRecommendations.map((r) => (
                <div key={r.recommendation_id} className="border border-border rounded-md p-2">
                  <div className="font-medium">{r.title}</div>
                  <div className="text-xs mt-1">{r.remediation}</div>
                </div>
              ))}
            </TabsContent>

            <TabsContent value="evidence" className="space-y-2 text-sm">
              {finding.evidence ? (
                <div className="border border-border rounded-md p-2 font-mono text-xs break-all">{finding.evidence}</div>
              ) : (
                <p className="text-muted-foreground">No evidence file recorded.</p>
              )}
            </TabsContent>
          </Tabs>
        </div>
      </SheetContent>
    </Sheet>
  )
}
