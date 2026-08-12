"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Reporting Engine

Methodology step: Reporting.

Purpose
-------
Generates every client-facing deliverable from normalized, enriched
Findings only - never directly from raw tool output. Visual language
(inline CSS, card/table layout) carries over from the framework's original
single-page dashboard.

Outputs (all under output/reports/):
  index.html                    landing page linking every report
  executive_summary.html        security posture, headline numbers, narrative
  technical_findings.html       full findings table, risk-sorted
  mitre_matrix.html             tactic/technique coverage
  attack_path_summary.html      attack path candidates as hop chains
  checklist_coverage.html       checklist item pass/fail/manual/not-evaluated
  evidence_index.html           tool -> raw evidence file listing
  assessment_metadata.html      assessment, platform, and version metadata
  permission_report.html        least-privilege and collector permission model
  capability_report.html        capability validation coverage
  read_only_verification.html   customer-facing read-only guarantee validation

READ ONLY

===============================================================================
"""

import datetime
from pathlib import Path

from rich.console import Console
from loguru import logger

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine


console = Console()


CSS = """
body { margin:0; padding:0; background:#edf2f7; font-family:'Inter',Arial,sans-serif; }
.header { background:#1e293b; color:white; padding:40px; }
.header h1 { margin:0; font-size:32px; }
.header p { margin-top:10px; color:#cbd5e1; }
.header a { color:#93c5fd; }
.container { width:92%; margin:auto; padding-bottom:60px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:20px; margin-top:30px; }
.card { background:white; border-radius:10px; padding:22px; box-shadow:0 4px 14px rgba(0,0,0,.08); }
.card h3 { margin:0; color:#64748b; font-size:14px; }
.card h1 { margin-top:12px; color:#0f172a; font-size:32px; }
.section { margin-top:35px; background:white; border-radius:10px; padding:25px; box-shadow:0 4px 14px rgba(0,0,0,.08); }
table { width:100%; border-collapse:collapse; }
th { background:#0f172a; color:white; padding:12px; text-align:left; font-size:13px; }
td { padding:10px; border-bottom:1px solid #e2e8f0; font-size:13px; }
tr:hover { background:#f8fafc; }
.badge { padding:3px 9px; color:white; border-radius:4px; font-size:12px; font-weight:600; }
.nav { display:flex; gap:16px; flex-wrap:wrap; margin-top:20px; }
.nav a { background:#334155; color:white; padding:10px 16px; border-radius:6px; text-decoration:none; font-size:13px; }
.nav a:hover { background:#475569; }
.path { font-family:monospace; font-size:13px; line-height:1.8; white-space:pre; }
.footer { margin-top:50px; padding:25px; text-align:center; color:#64748b; font-size:13px; }
"""

SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#27ae60",
    "INFO": "#3498db",
}

STATUS_COLOR = {
    "PASS": "#16a34a",
    "FAIL": "#dc2626",
    "MANUAL_REVIEW": "#d97706",
    "NOT_EVALUATED": "#64748b",
    "SUCCESS": "#16a34a",
    "FAILED": "#dc2626",
    "SKIPPED": "#d97706",
}

REPORTS_NAV = (
    ("index.html", "Overview"),
    ("executive_summary.html", "Executive Summary"),
    ("analyst_traceability.html", "Analyst Traceability"),
    ("technical_findings.html", "Technical Findings"),
    ("mitre_matrix.html", "MITRE ATT&CK Matrix"),
    ("attack_path_summary.html", "Attack Path Summary"),
    ("checklist_coverage.html", "Checklist Coverage"),
    ("assessment_coverage.html", "Assessment Coverage"),
    ("evidence_index.html", "Evidence Index"),
    ("assessment_metadata.html", "Assessment Metadata"),
    ("permission_report.html", "Permission Report"),
    ("capability_report.html", "Capability Report"),
    ("read_only_verification.html", "Read-Only Verification"),
)


def badge(text, color):

    return f'<span class="badge" style="background:{color};">{text}</span>'


def page_shell(title, subtitle, body_html, metadata_html=""):

    nav = "".join(
        f'<a href="{href}">{label}</a>' for href, label in REPORTS_NAV
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} - Cloud Security Assessment Orchestrator</title>
<style>{CSS}</style>
</head>
<body>
<div class="header">
<h1>Cloud Security Assessment Orchestrator</h1>
<p>{subtitle}</p>
<p>Generated : {datetime.datetime.now().strftime("%d %B %Y %H:%M:%S")}</p>
<div class="nav">{nav}</div>
</div>
<div class="container">
{metadata_html}
{body_html}
</div>
<div class="footer">
Cloud Security Assessment Orchestrator (CSAO) &middot; Enterprise Edition
</div>
</body>
</html>
"""


class ReportingEngine:

    def __init__(
        self,
        findings,
        assessment_register=None,
        execution_status=None,
        checklist_coverage=None,
        threat_scenarios=None,
        correlated_threats=None,
        mitre_summary=None,
        attack_path_candidates=None,
        risk_summary=None,
        evidence_index=None,
        discovery_summary=None,
        recommendations=None,
        attack_path_catalog=None,
        knowledge_engine=None,
        traceability_engine=None,
        assessment_metadata=None,
    ):

        self.findings = findings
        self.assessment_register = assessment_register or []
        self.execution_status = execution_status
        self.checklist_coverage = checklist_coverage or []
        self.threat_scenarios = [
            item.to_dict() if hasattr(item, "to_dict") else item
            for item in (threat_scenarios or [])
        ]
        self.correlated_threats = [
            item.to_dict() if hasattr(item, "to_dict") else item
            for item in (correlated_threats or [])
        ]
        self.mitre_summary = mitre_summary or {}
        self.attack_path_candidates = attack_path_candidates or []
        self.risk_summary = risk_summary or {}
        self.evidence_index = evidence_index or {}
        self.discovery_summary = discovery_summary or {}
        self.recommendations = [
            item.to_dict() if hasattr(item, "to_dict") else item
            for item in (recommendations or [])
        ]
        self.knowledge = knowledge_engine
        if self.knowledge is None:
            self.knowledge = AssessmentKnowledgeEngine({})

        self.attack_path_catalog = attack_path_catalog or self.knowledge.attack_path_catalog
        self.traceability_engine = traceability_engine
        self.assessment_metadata = assessment_metadata or {}

        self.output_directory = Path("output/reports")

        self.output_directory.mkdir(parents=True, exist_ok=True)

    def _platform_metadata_html(self):
        metadata = self.assessment_metadata or {}
        rows = [
            ("Platform Version", metadata.get("platform_version", "2.0.0")),
            ("Assessment Engine Version", metadata.get("assessment_engine_version", "2.0.0")),
            ("Collector Versions", ", ".join(metadata.get("collector_versions", [])) or "Dynamic"),
            ("Checklist Version", metadata.get("checklist_version", "Current")),
            ("Threat Library Version", metadata.get("threat_library_version", "Current")),
            ("Assessment Date", metadata.get("assessment_date", "")),
            ("Assessment Duration", metadata.get("assessment_duration", "")),
            ("Assessment ID", metadata.get("assessment_id", "")),
        ]
        body = "".join(
            f"<tr><th>{label}</th><td>{value or 'N/A'}</td></tr>" for label, value in rows
        )
        return f"""
<div class="section">
<h2>Platform Metadata</h2>
<table>{body}</table>
</div>
"""

    def _finding_confidence(self, finding):
        score = 45
        evidence_refs = 1 if getattr(finding, "evidence_location", "") else 0
        if evidence_refs:
            score += 15
        if getattr(finding, "validation_status", "") in {"PASS", "FAIL"}:
            score += 15
        if getattr(finding, "mitre_techniques", []):
            score += 10
        if getattr(finding, "attack_path_candidate", ""):
            score += 10
        if getattr(finding, "_risk_score", 0) or getattr(finding, "assessment_register_id", ""):
            score += 5
        if score >= 85:
            return "High"
        if score >= 65:
            return "Medium"
        return "Low"

    ###########################################################################
    # Overview / Landing page
    ###########################################################################

    def render_index(self):

        posture = self.risk_summary.get("security_posture_score", "N/A")

        body = f"""
<div class="cards">
<div class="card"><h3>Security Posture</h3><h1>{posture}/100</h1></div>
<div class="card"><h3>Total Findings</h3><h1>{len(self.findings)}</h1></div>
<div class="card"><h3>Register Entries</h3><h1>{len(self.assessment_register)}</h1></div>
<div class="card"><h3>Validated Threats</h3><h1>{sum(
            1 for s in self.threat_scenarios if s.get('status') == 'VALIDATED'
        )}</h1></div>
<div class="card"><h3>Attack Path Candidates</h3><h1>{len(self.attack_path_candidates)}</h1></div>
<div class="card"><h3>Assets Discovered</h3><h1>{sum(
            self.discovery_summary.get('resource_counts', {}).values()
        )}</h1></div>
</div>
<div class="section">
<h2>Assessment Methodology</h2>
<ol>
<li>Architecture Understanding</li>
<li>Asset Inventory</li>
<li>Crown Jewel Identification</li>
<li>Evidence Collection</li>
<li>Checklist Validation</li>
<li>MITRE ATT&amp;CK Mapping</li>
<li>Threat Correlation</li>
<li>Attack Path Identification</li>
<li>Risk Prioritization</li>
<li>Reporting</li>
</ol>
</div>
<div class="section">
<h2>Evidence Collection Status</h2>
<table>
<tr><th>Module</th><th>Status</th></tr>
{self._module_status_rows()}
</table>
</div>
<div class="section">
<h2>Assessment Register Traceability</h2>
<table>
<tr><th>Register ID</th><th>Resource</th><th>Source</th><th>Validation</th>
<th>Checklist Ref(s)</th><th>Threat Ref(s)</th><th>Attack Path Ref(s)</th>
<th>Recommendation Ref(s)</th></tr>
{self._assessment_register_rows()}
</table>
</div>
"""

        return page_shell(
            "Overview",
            "Assessment Orchestrator Overview",
            body,
            self._platform_metadata_html(),
        )

    def _module_status_rows(self):

        rows = ""

        for module, status in self.execution_status.items():

            color = STATUS_COLOR.get(status, "#64748b")

            rows += f'<tr><td>{module}</td><td>{badge(status, color)}</td></tr>'

        return rows

    def _assessment_register_rows(self, limit=20):

        rows = ""

        for entry in self.assessment_register[:limit]:
            rows += f"""
<tr>
<td>{entry.register_id}</td>
<td>{entry.resource}</td>
<td>{entry.source}</td>
<td>{badge(entry.validation_status, STATUS_COLOR.get(entry.validation_status, "#64748b"))}</td>
<td>{", ".join(entry.checklist_references) or "-"}</td>
<td>{", ".join(entry.threat_scenario_references) or "-"}</td>
<td>{", ".join(entry.attack_path_references) or "-"}</td>
<td>{", ".join(entry.recommendation_references) or "-"}</td>
</tr>
"""

        if len(self.assessment_register) > limit:
            rows += f"""
<tr><td colspan="8">Showing first {limit} of {len(self.assessment_register)} register entries.</td></tr>
"""

        return rows

    ###########################################################################
    # Executive Summary
    ###########################################################################

    def render_executive_summary(self):

        posture = self.risk_summary.get("security_posture_score", "N/A")

        crown_jewel_findings = sum(1 for f in self.findings if f.crown_jewel == "Yes")

        checklist_fail = sum(1 for c in self.checklist_coverage if c["status"] == "FAIL")

        executive_snapshot = self._executive_snapshot()

        rating = "Poor"
        color = "#dc2626"

        if isinstance(posture, (int, float)):

            if posture >= 90:
                rating, color = "Excellent", "#16a34a"
            elif posture >= 75:
                rating, color = "Good", "#2563eb"
            elif posture >= 60:
                rating, color = "Fair", "#d97706"

        body = f"""
<div class="cards">
<div class="card"><h3>Security Posture</h3><h1 style="color:{color};">{posture}/100</h1></div>
<div class="card"><h3>Overall Rating</h3><h1 style="color:{color};">{rating}</h1></div>
<div class="card"><h3>Critical Findings</h3><h1>{self.risk_summary.get('critical', 0)}</h1></div>
<div class="card"><h3>High Findings</h3><h1>{self.risk_summary.get('high', 0)}</h1></div>
<div class="card"><h3>Validated Threats</h3><h1>{sum(
            1 for s in self.threat_scenarios if s.get('status') == 'VALIDATED'
        )}</h1></div>
<div class="card"><h3>Crown Jewel Findings</h3><h1>{crown_jewel_findings}</h1></div>
<div class="card"><h3>Failed Checklist Items</h3><h1>{checklist_fail}</h1></div>
</div>
<div class="section">
<h2>Executive Summary</h2>
<p>This assessment followed the enterprise Cloud Security Assessment
methodology: architecture understanding, asset inventory, Crown Jewel
identification, automated evidence collection across every enabled tool,
checklist-driven control validation, MITRE ATT&amp;CK mapping, threat
correlation, attack path identification, and business-context-aware risk
prioritization.</p>
<p>Business Risk: <b>{executive_snapshot.get('business_risk', 'N/A')}</b></p>
<p>Affected Business Service: <b>{executive_snapshot.get('affected_service', 'N/A')}</b></p>
<p>Crown Jewel: <b>{executive_snapshot.get('crown_jewel', 'N/A')}</b></p>
<p>Business Impact: <b>{executive_snapshot.get('business_impact', 'N/A')}</b></p>
<p>Priority: <b>{executive_snapshot.get('priority', 'N/A')}</b></p>
<p>Recommended Actions: <b>{executive_snapshot.get('recommended_actions', 'N/A')}</b></p>
<p>Overall Security Posture Score: <b>{posture}/100</b> ({rating})</p>
<p>{len(self.attack_path_candidates)} attack path candidate(s) were identified
connecting validated threats to Crown Jewel resources through workbook-defined
assessment relationships and confirmed cloud connectivity.</p>
<p>{len(self.assessment_register)} assessment register entries track the
assessment as the source of truth. Every recommendation and attack path
candidate can be traced back through the register, checklist, and evidence
references.</p>
</div>
{self.render_recommendations()}
"""

        return page_shell(
            "Executive Summary",
            "Executive Summary",
            body,
            self._platform_metadata_html(),
        )

    ###########################################################################
    # Technical Findings
    ###########################################################################

    def render_technical_findings(self):

        ordered = sorted(
            self.findings,
            key=lambda f: getattr(f, "_risk_score", 0) or 0,
            reverse=True,
        )

        rows = ""

        for finding in ordered:

            color = SEVERITY_COLOR.get(finding.severity, "#3498db")

            confidence = self._finding_confidence(finding)
            likelihood = "High" if finding.internet_facing == "Yes" else "Medium"
            risk_value = round(getattr(finding, "_risk_score", 0) or 0, 1)
            technical_summary = (
                finding.description or "Technical explanation unavailable."
            )
            validation_steps = (
                finding.description
                or "Review source evidence and validated control mapping."
            )
            rows += f"""
<tr>
<td>{finding.assessment_register_id or "-"}</td>
<td>{finding.tool_source}</td>
<td>{confidence}</td>
<td>{finding.service}</td>
<td>{badge(finding.severity, color)}</td>
<td>{risk_value}</td>
<td>{finding.resource_id}</td>
<td><strong>{finding.title}</strong><br>{technical_summary}</td>
<td>{finding.account}</td>
<td>{finding.checklist_id or "-"}</td>
<td>{finding.validation_status}</td>
<td>{finding.related_threat_scenario or "-"}</td>
<td>{", ".join(finding.mitre_techniques) or "-"}</td>
<td>{finding.evidence_location or "-"}</td>
<td>{finding.crown_jewel}</td>
<td>{finding.attack_path_candidate or "-"}</td>
<td>{likelihood}</td>
<td>{validation_steps}</td>
<td>{finding.title}</td>
<td>{finding.evidence_location or 'See evidence archive / diagnostics bundle.'}</td>
</tr>
"""

        body = f"""
<div class="section">
<h2>Technical Findings ({len(self.findings)})</h2>
<table>
<tr>
<th>Register ID</th><th>Tool</th><th>Confidence</th><th>Service</th>
<th>Severity</th><th>Risk Score</th><th>AWS Resource</th>
<th>Executive / Technical Summary</th><th>AWS Account</th>
<th>Checklist Control</th><th>Validation</th><th>Threat Scenario</th>
<th>MITRE ATT&amp;CK</th><th>Evidence</th><th>Business Impact</th>
<th>Likelihood</th><th>Recommendation</th>
<th>Validation Steps / References</th>
</tr>
{rows}
</table>
</div>
"""

        return page_shell(
            "Technical Findings",
            "Technical Findings (risk-sorted)",
            body,
            self._platform_metadata_html(),
        )

    ###########################################################################
    # MITRE Matrix
    ###########################################################################

    def render_mitre_matrix(self):

        tactics = self.mitre_summary.get("tactics", {})
        techniques = self.mitre_summary.get("techniques", {})

        tactic_rows = "".join(
            f"<tr><td>{tactic}</td><td>{count}</td></tr>"
            for tactic, count in sorted(tactics.items(), key=lambda x: -x[1])
        )

        technique_rows = "".join(
            f"<tr><td>{technique}</td><td>{count}</td></tr>"
            for technique, count in sorted(techniques.items(), key=lambda x: -x[1])
        )

        body = f"""
<div class="cards">
<div class="card"><h3>Findings Mapped</h3><h1>{self.mitre_summary.get('mapped_findings', 0)}</h1></div>
<div class="card"><h3>Tactics Identified</h3><h1>{len(tactics)}</h1></div>
<div class="card"><h3>Techniques Identified</h3><h1>{len(techniques)}</h1></div>
</div>
<div class="section">
<h2>Tactics</h2>
<table><tr><th>Tactic</th><th>Findings</th></tr>{tactic_rows}</table>
</div>
<div class="section">
<h2>Techniques</h2>
<table><tr><th>Technique ID</th><th>Findings</th></tr>{technique_rows}</table>
</div>
"""

        return page_shell(
            "MITRE ATT&CK Matrix",
            "MITRE ATT&CK Coverage",
            body,
            self._platform_metadata_html(),
        )

    ###########################################################################
    # Attack Path Summary
    ###########################################################################

    def render_attack_path_summary(self):

        if not self.attack_path_candidates:

            sections = (
                "<div class=\"section\"><p>No attack path candidates identified "
                "from currently connected evidence.</p></div>"
            )

        else:

            sections = ""

            for candidate in self.attack_path_candidates:

                chain = "\n  |\n  v\n".join(
                    f"{hop['type']}: {hop['resource_id']}"
                    + (
                        f"  [{hop['relationship_from_previous']}]"
                        if hop["relationship_from_previous"]
                        else ""
                    )
                    for hop in candidate["hops"]
                )

                sections += f"""
<div class="section">
<h2>{candidate['id']} - {candidate['hop_count']} hop(s)</h2>
<p>{candidate['label']}</p>
<div class="path">{chain}</div>
</div>
"""

        catalog_rows = ""

        for ap in self.attack_path_catalog:

            color = SEVERITY_COLOR.get(str(ap.get("severity", "")).upper(), "#3498db")

            catalog_rows += f"""
<tr>
<td>{ap.get('ap_code', '')}</td>
<td>{ap.get('name', '')}</td>
<td>{ap.get('kill_chain_summary', '')}</td>
<td>{badge(ap.get('severity', ''), color)}</td>
</tr>
"""

        catalog_section = ""

        if catalog_rows:

            catalog_section = f"""
<div class="section">
<h2>Named Attack Path Catalog (from assessment workbook)</h2>
<p>Reference kill chains defined by the assessment methodology. Checklist
items link to these via their <code>related_attack_paths</code> field;
cross-referencing a specific discovered candidate above against one of
these named chains is an analyst judgment call, not automated by this
engine.</p>
<table>
<tr><th>AP Code</th><th>Name</th><th>Kill Chain Summary</th><th>Severity</th></tr>
{catalog_rows}
</table>
</div>
"""

        body = f"""
<div class="cards">
<div class="card"><h3>Discovered Attack Path Candidates</h3><h1>{len(self.attack_path_candidates)}</h1></div>
<div class="card"><h3>Correlated Threats</h3><h1>{len(self.correlated_threats)}</h1></div>
<div class="card"><h3>Named Attack Paths in Catalog</h3><h1>{len(self.attack_path_catalog)}</h1></div>
</div>
{sections}
{catalog_section}
"""

        return page_shell(
            "Attack Path Summary",
            "Attack Path Candidates",
            body,
            self._platform_metadata_html(),
        )

    ###########################################################################
    # Checklist Coverage
    ###########################################################################

    def render_checklist_coverage(self):

        rows = ""

        counts = {"PASS": 0, "FAIL": 0, "MANUAL_REVIEW": 0, "NOT_EVALUATED": 0}

        for item in self.checklist_coverage:

            counts[item["status"]] = counts.get(item["status"], 0) + 1

            color = STATUS_COLOR.get(item["status"], "#64748b")

            tools = ", ".join(item.get("tools", [])) or "manual"

            rows += f"""
<tr>
<td>{item['id']}</td>
<td>{item['title']}</td>
<td>{tools}</td>
<td>{badge(item['status'], color)}</td>
<td>{item['matched_findings']}</td>
<td>{"Yes" if item['manual_validation_required'] else "No"}</td>
</tr>
"""

        body = f"""
<div class="cards">
<div class="card"><h3>Pass</h3><h1 style="color:{STATUS_COLOR['PASS']};">{counts['PASS']}</h1></div>
<div class="card"><h3>Fail</h3><h1 style="color:{STATUS_COLOR['FAIL']};">{counts['FAIL']}</h1></div>
<div class="card"><h3>Manual Review</h3><h1 style="color:{STATUS_COLOR['MANUAL_REVIEW']};">
{counts['MANUAL_REVIEW']}</h1></div>
<div class="card"><h3>Not Evaluated</h3><h1 style="color:{STATUS_COLOR['NOT_EVALUATED']};">
{counts['NOT_EVALUATED']}</h1></div>
</div>
<div class="section">
<h2>Checklist Coverage ({len(self.checklist_coverage)} items)</h2>
<table>
<tr><th>ID</th><th>Title</th><th>Source(s)</th><th>Status</th>
<th>Matched Findings</th><th>Manual Review</th></tr>
{rows}
</table>
</div>
"""

        return page_shell(
            "Checklist Coverage",
            "Checklist Validation Coverage",
            body,
            self._platform_metadata_html(),
        )

    def render_assessment_coverage(self):

        rows = {}
        for item in self.knowledge.checklist_items:
            domain = item.get("domain") or "Uncategorized"
            entry = rows.setdefault(
                domain,
                {
                    "domain": domain,
                    "implemented_controls": 0,
                    "automatically_validated": 0,
                    "manual_validation_required": 0,
                    "not_covered": 0,
                },
            )
            entry["implemented_controls"] += 1
            if item.get("manual_validation_required"):
                entry["manual_validation_required"] += 1

        coverage_by_id = {item.get("id"): item for item in self.checklist_coverage}
        for item in self.knowledge.checklist_items:
            domain = item.get("domain") or "Uncategorized"
            entry = rows[domain]
            coverage = coverage_by_id.get(item.get("id"), {})
            status = coverage.get("status", "NOT_EVALUATED")
            if status in {"PASS", "FAIL"} and not item.get("manual_validation_required"):
                entry["automatically_validated"] += 1
            if status == "NOT_EVALUATED":
                entry["not_covered"] += 1

        body_rows = ""
        average_coverage = 0
        domains = list(sorted(rows.values(), key=lambda item: item["domain"]))
        for entry in domains:
            total = entry["implemented_controls"] or 1
            coverage_percentage = round(
                ((entry["implemented_controls"] - entry["not_covered"]) / total) * 100,
                2,
            )
            average_coverage += coverage_percentage
            body_rows += f"""
<tr>
<td>{entry['domain']}</td>
<td>{entry['implemented_controls']}</td>
<td>{entry['automatically_validated']}</td>
<td>{entry['manual_validation_required']}</td>
<td>{entry['not_covered']}</td>
<td>{coverage_percentage}%</td>
</tr>
"""

        average_coverage = round(
            average_coverage / len(domains), 2
        ) if domains else 0
        body = f"""
<div class="cards">
<div class="card"><h3>Domains</h3><h1>{len(domains)}</h1></div>
<div class="card"><h3>Implemented Controls</h3><h1>{sum(
            item['implemented_controls'] for item in domains
        )}</h1></div>
<div class="card"><h3>Automatically Validated</h3><h1>{sum(
            item['automatically_validated'] for item in domains
        )}</h1></div>
<div class="card"><h3>Manual Validation Required</h3><h1>{sum(
            item['manual_validation_required'] for item in domains
        )}</h1></div>
<div class="card"><h3>Not Covered</h3><h1>{sum(item['not_covered'] for item in domains)}</h1></div>
<div class="card"><h3>Average Coverage</h3><h1>{average_coverage}%</h1></div>
</div>
<div class="section">
<h2>Assessment Coverage by Domain</h2>
<table>
<tr><th>Assessment Domain</th><th>Implemented Controls</th>
<th>Automatically Validated</th><th>Manual Validation Required</th>
<th>Not Covered</th><th>Coverage Percentage</th></tr>
{body_rows}
</table>
</div>
"""
        return page_shell(
            "Assessment Coverage",
            "Domain-level assessment coverage",
            body,
            self._platform_metadata_html(),
        )

    ###########################################################################
    # Evidence Index
    ###########################################################################

    def render_evidence_index(self):

        sections = ""

        for tool, files in self.evidence_index.items():

            file_rows = "".join(f"<tr><td>{f}</td></tr>" for f in files)

            sections += f"""
<div class="section">
<h2>{tool} ({len(files)} file(s))</h2>
<table>{file_rows}</table>
</div>
"""

        body = sections or '<div class="section"><p>No evidence collected yet.</p></div>'

        return page_shell(
            "Evidence Index",
            "Raw Evidence Index",
            body,
            self._platform_metadata_html(),
        )

    def _recommendation_value(self, recommendation, key, default=""):

        if hasattr(recommendation, key):
            return getattr(recommendation, key)

        if isinstance(recommendation, dict):
            return recommendation.get(key, default)

        return default

    def _executive_snapshot(self):

        if self.traceability_engine and self.recommendations:
            recommendation = self.recommendations[0]
            recommendation_id = (
                recommendation.recommendation_id
                if hasattr(recommendation, "recommendation_id")
                else recommendation.get("recommendation_id")
            )
            context = self.traceability_engine.analyst_summary(recommendation_id)
            if context:
                return {
                    "business_risk": f"High ({context.get('risk_score', 0)})",
                    "affected_service": ", ".join(context.get("services", [])) or "N/A",
                    "crown_jewel": ", ".join(context.get("crown_jewel", [])) or "N/A",
                    "business_impact": self._business_impact_for_recommendation(
                        recommendation_id
                    ),
                    "priority": self._priority_for_recommendation(recommendation_id),
                    "recommended_actions": ", ".join(
                        context.get("checklist_controls", [])
                    )
                    or "Review workbook-backed findings",
                }

        top = next(
            (
                f
                for f in sorted(
                    self.findings,
                    key=lambda x: getattr(x, "_risk_score", 0) or 0,
                    reverse=True,
                )
            ),
            None,
        )
        if not top:
            return {}

        return {
            "business_risk": f"{top.severity} ({round(getattr(top, '_risk_score', 0) or 0, 1)})",
            "affected_service": top.service,
            "crown_jewel": top.resource_name or top.resource_id,
            "business_impact": top.description or "N/A",
            "priority": top.severity,
            "recommended_actions": top.title,
        }

    def _business_impact_for_recommendation(self, recommendation_id):

        if not self.traceability_engine:
            return "N/A"

        context = self.traceability_engine.recommendation_context(recommendation_id)
        if not context:
            return "N/A"

        scenarios = context.get("threat_scenarios", [])
        if scenarios:
            first = scenarios[0]
            return first.get("business_impact") or first.get("preconditions") or "N/A"

        return "N/A"

    def _priority_for_recommendation(self, recommendation_id):

        if not self.traceability_engine:
            return "N/A"

        context = self.traceability_engine.recommendation_context(recommendation_id)
        if not context:
            return "N/A"

        controls = context.get("checklist_controls", [])
        if controls:
            first = controls[0]
            return first.get("priority_tier") or first.get("priority_score") or "N/A"

        return "N/A"

    def render_recommendations(self):

        if not self.recommendations:
            return '<div class="section"><p>No traceable recommendations generated.</p></div>'

        rows = ""
        for recommendation in self.recommendations:
            recommendation_id = self._recommendation_value(
                recommendation, "recommendation_id", ""
            )
            title = self._recommendation_value(recommendation, "title", "")
            register_ids = self._recommendation_value(
                recommendation, "assessment_register_ids", []
            )
            checklist_ids = self._recommendation_value(recommendation, "checklist_ids", [])
            threat_refs = self._recommendation_value(
                recommendation, "threat_scenario_refs", []
            )
            attack_refs = self._recommendation_value(
                recommendation, "attack_path_refs", []
            )
            evidence_refs = self._recommendation_value(
                recommendation, "evidence_references", []
            )
            rows += f"""
<tr>
<td>{recommendation_id}</td>
<td>{title}</td>
<td>{", ".join(register_ids) or "-"}</td>
<td>{", ".join(checklist_ids) or "-"}</td>
<td>{", ".join(threat_refs) or "-"}</td>
<td>{", ".join(attack_refs) or "-"}</td>
<td>{", ".join(evidence_refs) or "-"}</td>
</tr>
"""

        return f"""
<div class="section">
<h2>Traceable Recommendations ({len(self.recommendations)})</h2>
<table>
<tr><th>Recommendation</th><th>Title</th><th>Register Ref(s)</th>
<th>Checklist Ref(s)</th><th>Threat Ref(s)</th><th>Attack Path Ref(s)</th>
<th>Evidence Ref(s)</th></tr>
{rows}
</table>
</div>
"""

    def render_analyst_traceability(self):

        if not self.traceability_engine or not self.recommendations:
            return '<div class="section"><p>No traceability details available.</p></div>'

        body = ""

        for recommendation in self.recommendations:
            rec_id = (
                recommendation.recommendation_id
                if hasattr(recommendation, "recommendation_id")
                else recommendation.get("recommendation_id")
            )
            context = self.traceability_engine.analyst_summary(rec_id)
            if not context:
                continue

            path_rows = "".join(
                f"<tr><td><pre class=\"path\">{' -> '.join(path)}</pre></td></tr>"
                for path in context.get("paths", [])
            ) or '<tr><td>No direct evidence-to-recommendation path found.</td></tr>'

            body += f"""
<div class="section">
<h2>{rec_id} - {context.get('title', '')}</h2>
<table>
<tr><th>Why it appeared</th><td>{context.get('title', '')}</td></tr>
<tr><th>Supporting Evidence</th><td>{', '.join(context.get('evidence', [])) or '-'}</td></tr>
<tr><th>Checklist Controls</th><td>{', '.join(context.get('checklist_controls', [])) or '-'}</td></tr>
<tr><th>Threat Scenarios</th><td>{', '.join(context.get('threat_scenarios', [])) or '-'}</td></tr>
<tr><th>Attack Paths</th><td>{', '.join(context.get('attack_paths', [])) or '-'}</td></tr>
<tr><th>MITRE Techniques</th><td>{', '.join(context.get('mitre_techniques', [])) or '-'}</td></tr>
<tr><th>Crown Jewel</th><td>{', '.join(context.get('crown_jewel', [])) or '-'}</td></tr>
<tr><th>Risk Score</th><td>{context.get('risk_score', 0)}</td></tr>
<tr><th>Risk Factors</th><td>{context.get('risk_factors', [])}</td></tr>
<tr><th>Assessment Register Entry</th><td>{', '.join(context.get('assessment_register_entries', [])) or '-'}</td></tr>
<tr><th>Workbook Traceability</th><td>{', '.join(context.get('workbooks', [])) or '-'}
 / {', '.join(context.get('worksheets', [])) or '-'}</td></tr>
</table>
<h3>Evidence to Recommendation Paths</h3>
<table>{path_rows}</table>
</div>
"""

        return page_shell(
            "Analyst Traceability",
            "Assessment explainability and provenance",
            body,
            self._platform_metadata_html(),
        )

    def render_assessment_metadata(self):
        metadata = self.assessment_metadata or {}
        rows = "".join(
            f"<tr><th>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>"
            for key, value in sorted(metadata.items())
            if not isinstance(value, (list, dict))
        )
        return page_shell(
            "Assessment Metadata",
            "Assessment and platform execution metadata",
            (
                f'<div class="section"><h2>Assessment Metadata</h2>'
                f"<table>{rows}</table></div>"
            ),
            self._platform_metadata_html(),
        )

    def render_permission_report(self):
        matrix = self.assessment_metadata.get("permission_matrix", [])
        rows = "".join(
            "<tr>"
            f"<td>{item.get('collector', '')}</td>"
            f"<td>{item.get('aws_service', '')}</td>"
            f"<td>{', '.join(item.get('iam_actions', []))}</td>"
            f"<td>{', '.join(item.get('aws_apis', []))}</td>"
            f"<td>{', '.join(item.get('evidence_collected', []))}</td>"
            f"<td>{item.get('assessment_capability_enabled', '')}</td>"
            f"<td>{str(item.get('classification', '')).upper()}</td>"
            "</tr>"
            for item in matrix
        )
        body = f"""
<div class="section">
<h2>Least-Privilege Permission Matrix</h2>
<table>
<tr><th>Collector</th><th>AWS Service</th><th>IAM Actions</th><th>AWS APIs</th>
<th>Evidence</th><th>Capability</th><th>Classification</th></tr>
{rows}
</table>
</div>
"""
        return page_shell(
            "Permission Report",
            "Dynamic least-privilege permission matrix",
            body,
            self._platform_metadata_html(),
        )

    def render_capability_report(self):
        validation = self.assessment_metadata.get("capability_validation", {}) or {}
        rows = "".join(
            "<tr>"
            f"<td>{item.get('name', '')}</td>"
            f"<td>{item.get('status', '')}</td>"
            f"<td>{item.get('reason', '')}</td>"
            f"<td>{item.get('collector_scope', '')}</td>"
            "</tr>"
            for item in validation.get("capabilities", [])
        )
        body = f"""
<div class="section">
<h2>Capability Validation</h2>
<table>
<tr><th>Capability</th><th>Status</th><th>Reason</th><th>Collector Scope</th></tr>
{rows}
</table>
</div>
"""
        return page_shell(
            "Capability Report",
            "Pre-assessment capability validation",
            body,
            self._platform_metadata_html(),
        )

    def render_read_only_verification(self):
        safety = self.assessment_metadata.get("safety_validation", {}) or {}
        collector_rows = "".join(
            "<tr>"
            f"<td>{item.get('name', '')}</td>"
            f"<td>{item.get('read_only_mode', '')}</td>"
            f"<td>{'Yes' if item.get('installed') else 'No'}</td>"
            f"<td>{'Yes' if item.get('compatible') else 'Review'}</td>"
            "</tr>"
            for item in self.assessment_metadata.get("tool_validation", [])
        )
        violations = safety.get("violations", [])
        violation_html = "".join(
            f"<tr><td>{item.get('collector', '')}</td><td>{item.get('reason', '')}</td></tr>"
            for item in violations
        ) or (
            "<tr><td colspan='2'>No write-operation dependencies were detected "
            "in enabled collectors.</td></tr>"
        )
        body = f"""
<div class="cards">
<div class="card"><h3>Read-Only Guarantee</h3><h1>{safety.get('status', 'UNKNOWN')}</h1></div>
<div class="card"><h3>Violations</h3><h1>{len(violations)}</h1></div>
</div>
<div class="section">
<h2>Safety Validation</h2>
<table><tr><th>Collector</th><th>Reason</th></tr>{violation_html}</table>
</div>
<div class="section">
<h2>External Tool Read-Only Validation</h2>
<table><tr><th>Tool</th><th>Mode</th><th>Installed</th><th>Compatible</th></tr>{collector_rows}</table>
</div>
"""
        return page_shell(
            "Read-Only Verification",
            "Customer-facing validation of CSAO's non-intrusive operating model",
            body,
            self._platform_metadata_html(),
        )

    ###########################################################################
    # Generate
    ###########################################################################

    def generate(self):

        console.print(
            "\n[bold cyan]Generating Reporting Engine Deliverables...[/bold cyan]"
        )

        pages = {

            "index.html": self.render_index,
            "executive_summary.html": self.render_executive_summary,
            "analyst_traceability.html": self.render_analyst_traceability,
            "technical_findings.html": self.render_technical_findings,
            "mitre_matrix.html": self.render_mitre_matrix,
            "attack_path_summary.html": self.render_attack_path_summary,
            "checklist_coverage.html": self.render_checklist_coverage,
            "assessment_coverage.html": self.render_assessment_coverage,
            "evidence_index.html": self.render_evidence_index,
            "assessment_metadata.html": self.render_assessment_metadata,
            "permission_report.html": self.render_permission_report,
            "capability_report.html": self.render_capability_report,
            "read_only_verification.html": self.render_read_only_verification,

        }

        for filename, render in pages.items():

            try:

                html = render()

                with open(self.output_directory / filename, "w", encoding="utf-8") as f:

                    f.write(html)

            except Exception as e:

                logger.exception(e)

                console.print(
                    f"[red]Failed to generate {filename}: {e}[/red]"
                )

        logger.success(
            f"Reporting Engine wrote {len(pages)} report(s) to {self.output_directory}"
        )

        console.print(
            f"[bold green]✓ {len(pages)} Reports Generated : {self.output_directory}[/bold green]"
        )
