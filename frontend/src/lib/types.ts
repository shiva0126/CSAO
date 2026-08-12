export interface CurrentUser {
  user_id: number
  username: string
  display_name: string
  role: 'READ_ONLY' | 'ANALYST' | 'ADMINISTRATOR'
}

export interface MeResponse {
  authenticated: boolean
  needs_setup: boolean
  must_change_password?: boolean
  user: CurrentUser | null
}

export interface DashboardData {
  assessment_name: string
  cloud_provider: string
  assessment_status: string
  current_lifecycle_stage: string
  number_of_accounts: number
  regions: string[]
  resources_discovered: number
  total_resources: number
  evidence_sources: number
  findings: number
  findings_by_severity: Record<string, number>
  checklist_progress: {
    PASS: number
    FAIL: number
    MANUAL_REVIEW: number
    NOT_EVALUATED: number
    total: number
  }
  threat_scenarios: number
  attack_paths: number
  high_risk_findings: number
  manual_reviews_remaining: number
  recent_activity: { name: string; when: string }[]
  recent_assessments: AssessmentHistoryItem[]
  recent_reports: ReportRow[]
  monitor: MonitorState
  validation_summary: Record<string, number>
  assessment_health: string
  evidence_coverage: { service: string; coverage: string; status: string }[]
  timeline: TimelineEntry[]
  safety_validation: { status: string; violations?: string[] }
  collector_health: { name: string; status: string }[]
  platform_health: {
    provider_available: boolean
    accounts_validated: number
    collector_count: number
    report_count: number
    issues: string[]
  }
  quick_actions: { label: string; href: string }[]
}

export interface TimelineEntry {
  timestamp: string
  event: string
  stage: string
  status: string
  detail: string
  items_processed: number | string
}

export interface MonitorState {
  assessment?: AssessmentHistoryItem
  status?: string
  status_message?: string
  current_stage?: string
  current_collector?: string
  current_api?: string
  progress?: number
  resources_processed?: number
  failures?: string[]
  warnings?: string[]
  elapsed_time?: string
  estimated_remaining_time?: string
  started_at?: string
  cancel_requested?: boolean
  timeline?: TimelineEntry[]
}

export interface AssessmentHistoryItem {
  id: string
  name: string
  client: string
  cloud: string
  status: string
  started: string
  completed: string
  duration: string
  account_id: string
  account_name: string
  regions: string[]
  collectors: string[]
  report_files: string[]
  finding_count: number
  attack_path_count: number
}

export interface FindingRow {
  finding_id: string
  register_id: string
  severity: string
  cloud_service: string
  resource: string
  evidence: string
  checklist_controls: string[]
  threat_scenarios: string[]
  status: string
  analyst_notes: string
  crown_jewel: boolean
  internet_facing: boolean
  risk_bucket: string
  risk: number
  manual_review: boolean
  needs_review: boolean
  checklist_titles: string[]
  scenario_titles: string[]
  correlated_threats: string[]
  attack_path_ids: string[]
  title?: string
}

export interface ChecklistRow {
  id: string
  title: string
  domain: string
  status: string
  evidence_type: string
  collection_method: string
  register_ids: string[]
  sources: string[]
  related_attack_paths: string[]
  threat_scenario_ids: string[]
  mitre_mapping: { tactics?: string[]; techniques?: string[] }
  finding_count: number
}

export interface ThreatScenarioRow {
  scenario_id: string
  title: string
  status: string
  validated_controls: string[]
  missing_controls: string[]
  stride_category: string
  affected_crown_jewels: string[]
  evidence: string[]
  mitre_mapping: { tactics?: string[]; techniques?: string[] }
  recommendations: string[]
  attack_paths: string[]
  business_impact: string
  risk_level: string
  correlated_threats: string[]
}

export interface CorrelatedThreatRow {
  correlation_id: string
  scenario_ids: string[]
  status: string
  attack_path_refs: string[]
  source_resources: string[]
  target_resources: string[]
  supporting_evidence: string[]
  analyst_decision: string
  correlation_reason: string
}

export interface RiskRow {
  finding_id: string
  title: string
  service: string
  resource: string
  risk_score: number
  business_impact: string
  likelihood: string
  exposure: string
  detection_coverage: number
  affected_crown_jewels: string[]
  attack_paths: string[]
  severity: string
  recommendation_ids: string[]
}

export interface RecommendationRow {
  recommendation_id: string
  title: string
  priority: string
  affected_resources: string[]
  checklist_controls: string[]
  threat_scenarios: string[]
  supporting_evidence: string[]
  status: string
  risk_score: number
  why: string
  remediation: string
  verification: string[]
  related_findings: string[]
}

export interface EvidenceSource {
  source: string
  path: string
  name: string
  exists: boolean
  size: number
  modified: string
  kind: string
  region: string
  resource: string
  checklist_controls: string[]
}

export interface AttackPathGraph {
  nodes: {
    id: string
    label: string
    kind: string
    color: string
    resource_id?: string
    candidate_id?: string
    evidence?: string[]
  }[]
  edges: { source: string; target: string; label: string; candidate_id?: string }[]
  candidates: Record<string, unknown>[]
}

export interface ReportRow {
  name: string
  title: string
  path: string
  size: number
  generated_at: string
  versions: { assessment_id: string; assessment_name: string; status: string; completed: string; path: string }[]
  version_count: number
  archived_versions: string[]
  download_href?: string
  previewable?: boolean
}

export interface AccountRecord {
  id: string
  name: string
  cloud: string
  auth_type: string
  account_id: string
  alias: string
  regions: string[]
  notes: string
  last_validated: string
  last_validation_status: string
  last_validation_error: string
  masked_credentials: Record<string, string>
  read_only_validated: boolean
}

export interface CollectorInfo {
  key: string
  label: string
  enabled: boolean
  description: string
  permissions: string
  runtime: string
  services: string[]
  evidence: string[]
  mitre_mapping: string[]
  threat_scenarios: string[]
  aws_apis: string[]
}

export interface WizardDefaults {
  defaults: Record<string, unknown>
  clients: Record<string, unknown>[]
  accounts: AccountRecord[]
  collectors: CollectorInfo[]
  regions: string[]
  services: string[]
  report_types: { value: string; label: string }[]
  risk_profiles: { value: string; label: string }[]
  assessment_type_options: { value: string; label: string }[]
  readiness: { checks: { label: string; status: string; detail: string }[]; ready: boolean }
}

export interface ToolValidationRow {
  name: string
  installed: boolean
  compatible: boolean
  version: string
  read_only_mode: string
  required: boolean
}

export interface PermissionMatrixRow {
  aws_service: string
  collector: string
  aws_apis: string[]
  iam_actions: string[]
  purpose: string
  evidence_collected: string[]
  assessment_capability_enabled: string
  classification: string
}

export interface TrustCenterData {
  read_only_guarantee: string[]
  permission_matrix: PermissionMatrixRow[]
  collector_permissions: Record<string, unknown>[]
  faq: { q: string; a: string }[]
  tool_validation: ToolValidationRow[]
  tool_status_checked_at: string
  safety_validation: { status: string; violations?: { collector: string; reason: string }[] }
}
