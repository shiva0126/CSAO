"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Recommendation Engine

Purpose
-------
Converts checklist failures and manual-review items into traceable
recommendations that explicitly reference the assessment register, checklist
items, threat scenarios, attack paths, and evidence.
===============================================================================
"""

import json
from pathlib import Path

from rich.console import Console
from loguru import logger

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine
from core.schema.recommendation import Recommendation


console = Console()


class RecommendationEngine:

    def __init__(self, config, knowledge_engine=None):

        self.config = config
        self.knowledge = knowledge_engine or AssessmentKnowledgeEngine(config)
        self.output_directory = Path(
            config.get("output", {}).get(
                "assessment_register_directory", "output/assessment_register"
            )
        )
        self.output_directory.mkdir(parents=True, exist_ok=True)
        self.recommendations = []

    def build_recommendation(self, index, item, records, scenarios, correlated_threats):

        register_ids = item.get("register_ids", [])
        if not register_ids:
            register_ids = [
                getattr(record, "register_id", None)
                for record in records
                if getattr(getattr(record, "_finding", record), "checklist_id", None) == item.get("id")
            ]

        template = self.knowledge.recommendation_template_for_checklist(item.get("id"))
        threat_refs = []
        attack_refs = []
        evidence_refs = []
        evidence_ids = []

        for scenario in scenarios:
            if item.get("id") in scenario.prerequisite_checklists:
                threat_refs.append(scenario.scenario_id)
                attack_refs.extend(getattr(scenario, "attack_path_refs", []) or [])
                if scenario.validated_register_ids:
                    register_ids = sorted(set(register_ids + scenario.validated_register_ids))

        for threat in correlated_threats:
            if set(threat.scenario_ids) & set(threat_refs):
                attack_refs.extend(threat.attack_path_refs)
                register_ids = sorted(set(register_ids + threat.validated_register_ids))

        for record in records:
            if getattr(record, "register_id", None) in register_ids:
                evidence_refs.extend(getattr(record, "evidence_references", []) or [])
                evidence_ids.extend(getattr(record, "evidence_ids", []) or [])
                if record.recommendation_references is not None:
                    pass

        return Recommendation(
            recommendation_id=f"REC-{index:03d}",
            title=template.get("title") or f"Remediate checklist item {item.get('id')}: {item.get('title')}",
            status=item.get("status", "OPEN"),
            assessment_register_ids=sorted(set(filter(None, register_ids))),
            checklist_ids=[item.get("id")] if item.get("id") else [],
            threat_scenario_refs=sorted(set(filter(None, threat_refs))),
            attack_path_refs=sorted(set(filter(None, attack_refs))),
            evidence_references=sorted(set(filter(None, evidence_refs))),
            evidence_ids=sorted(set(filter(None, evidence_ids))),
            priority=template.get("priority") or template.get("priority_tier") or item.get("priority_tier", ""),
            severity=template.get("severity") or item.get("severity", ""),
            rationale=template.get("output_document") or "Derived from checklist validation output",
            remediation=template.get("remediation") or template.get("output_document") or "",
            verification_steps=template.get("verification_steps") or template.get("pass_criteria") or "",
            report_sections=list(template.get("report_sections", []) or []),
        )

    def run(self, coverage, records, scenarios, correlated_threats):

        console.rule("[bold cyan]Recommendations")

        actionable = [
            item for item in coverage
            if item.get("status") in ("FAIL", "MANUAL_REVIEW")
        ]

        for index, item in enumerate(actionable, start=1):
            recommendation = self.build_recommendation(
                index, item, records, scenarios, correlated_threats
            )
            self.recommendations.append(recommendation)

        for recommendation in self.recommendations:
            for record in records:
                if getattr(record, "register_id", None) in recommendation.assessment_register_ids:
                    if recommendation.recommendation_id not in record.recommendation_references:
                        record.recommendation_references.append(recommendation.recommendation_id)
                    finding = getattr(record, "_finding", record)
                    if recommendation.recommendation_id not in getattr(finding, "recommendation_ids", []):
                        finding.recommendation_ids.append(recommendation.recommendation_id)

        self.save()

        console.print(
            f"[green]Generated {len(self.recommendations)} traceable recommendation(s)[/green]"
        )

        return self.recommendations

    def save(self):

        output_file = self.output_directory / "recommendations.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([recommendation.to_dict() for recommendation in self.recommendations], f, indent=4, default=str)

        logger.success(f"Recommendations saved : {output_file}")
