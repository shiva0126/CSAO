import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import type {
  AccessRequirementsData,
  AccountRecord,
  AttackPathCatalogRow,
  AttackPathGraph,
  ChecklistRow,
  CorrelatedThreatRow,
  CoverageSummary,
  DashboardData,
  DocContent,
  DocSummary,
  EvidenceSource,
  FindingRow,
  MeResponse,
  MitreMappingRow,
  MonitorState,
  RecommendationRow,
  ReportRow,
  RiskRow,
  ThreatScenarioRow,
  TrustCenterData,
  WizardDefaults,
} from './types'

export function useMe() {
  return useQuery({ queryKey: ['me'], queryFn: () => api.get<MeResponse>('/auth/me') })
}

export function useLogin() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { username: string; password: string }) => api.post('/auth/login', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['me'] }),
  })
}

export function useLogout() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post('/auth/logout'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['me'] }),
  })
}

export function useDashboard() {
  return useQuery({ queryKey: ['dashboard'], queryFn: () => api.get<DashboardData>('/dashboard') })
}

export interface FindingFilters {
  high_risk?: boolean
  needs_review?: boolean
  manual_validation?: boolean
  crown_jewel?: boolean
  internet_facing?: boolean
  search?: string
}

export function useFindings(filters: FindingFilters) {
  const params = new URLSearchParams()
  Object.entries(filters).forEach(([k, v]) => {
    if (v) params.set(k, String(v))
  })
  const qs = params.toString()
  return useQuery({
    queryKey: ['findings', filters],
    queryFn: () => api.get<{ rows: FindingRow[]; validation_statuses: string[] }>(`/findings${qs ? `?${qs}` : ''}`),
  })
}

export function useValidateFinding() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; validation_status: string; analyst_notes: string }) =>
      api.post(`/findings/${id}/validate`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })
}

export function useChecklist() {
  return useQuery({ queryKey: ['checklist'], queryFn: () => api.get<{ rows: ChecklistRow[] }>('/checklist') })
}

export function useThreatScenarios() {
  return useQuery({
    queryKey: ['threat-scenarios'],
    queryFn: () => api.get<{ rows: ThreatScenarioRow[] }>('/threats/scenarios'),
  })
}

export function useCorrelatedThreats() {
  return useQuery({
    queryKey: ['correlated-threats'],
    queryFn: () => api.get<{ rows: CorrelatedThreatRow[] }>('/threats/correlated'),
  })
}

export function useAttackPaths() {
  return useQuery({ queryKey: ['attack-paths'], queryFn: () => api.get<AttackPathGraph>('/attack-paths') })
}

export function useRisk() {
  return useQuery({ queryKey: ['risk'], queryFn: () => api.get<{ rows: RiskRow[] }>('/risk') })
}

export function useRecommendations() {
  return useQuery({
    queryKey: ['recommendations'],
    queryFn: () => api.get<{ rows: RecommendationRow[] }>('/recommendations'),
  })
}

export function useEvidence(source: string, search: string) {
  const params = new URLSearchParams()
  if (source) params.set('source', source)
  if (search) params.set('search', search)
  const qs = params.toString()
  return useQuery({
    queryKey: ['evidence', source, search],
    queryFn: () => api.get<{ sources: EvidenceSource[]; source_options: string[] }>(`/evidence${qs ? `?${qs}` : ''}`),
  })
}

export function useWizardDefaults() {
  return useQuery({
    queryKey: ['wizard-defaults'],
    queryFn: () => api.get<WizardDefaults>('/assessments/wizard-defaults'),
  })
}

export function useAssessmentHistory() {
  return useQuery({
    queryKey: ['assessment-history'],
    queryFn: () => api.get<{ history: unknown[]; active_assessment: unknown }>('/assessments/history'),
  })
}

export function useActiveMonitor(enabled: boolean) {
  return useQuery({
    queryKey: ['active-monitor'],
    queryFn: () => api.get<MonitorState>('/assessments/active'),
    refetchInterval: enabled ? 2500 : false,
  })
}

export function useStartAssessment() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/assessments', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['active-monitor'] })
      qc.invalidateQueries({ queryKey: ['assessment-history'] })
    },
  })
}

export function useCancelAssessment() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post('/assessments/cancel'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['active-monitor'] }),
  })
}

export function useReports() {
  return useQuery({ queryKey: ['reports'], queryFn: () => api.get<{ rows: ReportRow[] }>('/reports') })
}

export function useAccounts() {
  return useQuery({ queryKey: ['accounts'], queryFn: () => api.get<{ accounts: AccountRecord[] }>('/accounts') })
}

export function useSaveAccount() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<AccountRecord>('/accounts', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['accounts'] }),
  })
}

export function useRemoveAccount() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post(`/accounts/${id}/remove`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['accounts'] }),
  })
}

export function useTestAccount() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post(`/accounts/${id}/test`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['accounts'] }),
  })
}

export function useSettings() {
  return useQuery({ queryKey: ['settings'], queryFn: () => api.get<Record<string, unknown>>('/settings') })
}

export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => api.get<{ users: Record<string, unknown>[]; login_history: Record<string, unknown>[] }>('/users'),
  })
}

export function useTrustCenter() {
  return useQuery({ queryKey: ['trust-center'], queryFn: () => api.get<TrustCenterData>('/trust-center') })
}

export function useCoverage() {
  return useQuery({ queryKey: ['coverage'], queryFn: () => api.get<CoverageSummary>('/coverage') })
}

export function useDocsList() {
  return useQuery({ queryKey: ['docs'], queryFn: () => api.get<{ rows: DocSummary[] }>('/docs') })
}

export function useDoc(id: string | null) {
  return useQuery({
    queryKey: ['docs', id],
    queryFn: () => api.get<DocContent>(`/docs/${id}`),
    enabled: !!id,
  })
}

export function useMitreReference() {
  return useQuery({
    queryKey: ['docs-reference-mitre'],
    queryFn: () => api.get<{ rows: MitreMappingRow[] }>('/docs/reference/mitre'),
  })
}

export function useAttackPathCatalog() {
  return useQuery({
    queryKey: ['docs-reference-attack-paths'],
    queryFn: () => api.get<{ rows: AttackPathCatalogRow[] }>('/docs/reference/attack-paths'),
  })
}

export function useAccessRequirements(collectorKeys: string[]) {
  const qs = collectorKeys.length ? `?collectors=${collectorKeys.join(',')}` : ''
  return useQuery({
    queryKey: ['access-requirements', collectorKeys],
    queryFn: () => api.get<AccessRequirementsData>(`/assessments/access-requirements${qs}`),
    enabled: collectorKeys.length > 0,
  })
}
