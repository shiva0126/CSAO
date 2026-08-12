import yaml
from pathlib import Path

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine


CATALOG_CONFIG = {
    "knowledge_catalog": {"file": "data/assessment_knowledge_catalog.yaml"},
    "checklist": {"file": "checklists/checklist.yaml"},
    "attack_path": {"catalog": "data/attack_path_catalog.yaml"},
}


def test_workbook_catalog_alignment():

    knowledge = AssessmentKnowledgeEngine(CATALOG_CONFIG)

    assert len(knowledge.checklist_items) == 177
    assert len(knowledge.scenarios) == 20
    assert len(knowledge.attack_path_catalog) == 15

    collector_rows = knowledge.collector_mappings()
    assert len(collector_rows) == 8
    assert all(row["supported_controls"] for row in collector_rows)

    attack_paths_with_controls = {
        control["id"]: knowledge.attack_path_refs_for_checklist(control["id"])
        for control in knowledge.checklist_items
    }
    assert all(attack_paths_with_controls.values())

    scenario_refs = {
        control["id"]: knowledge.scenario_ids_for_checklist(control["id"])
        for control in knowledge.checklist_items
        if control.get("threat_scenario_ids") or control.get("linked_threat_numbers")
    }
    assert scenario_refs
    assert all(scenario_refs.values())

    referenced_attack_paths = {
        attack_path
        for control in knowledge.checklist_items
        for attack_path in knowledge.attack_path_refs_for_checklist(control["id"])
    }
    catalog_attack_paths = {
        item["ap_code"] for item in knowledge.attack_path_catalog
    }
    assert catalog_attack_paths.issubset(referenced_attack_paths)

    report_sections = {
        section["id"] for section in knowledge.report_section_catalog()
    }
    assert {
        "assessment_coverage",
        "assessment_metadata",
        "capability_report",
        "permission_report",
        "read_only_verification",
        "risk_summary",
        "recommendations",
        "appendices",
    }.issubset(report_sections)

    template = knowledge.recommendation_template_for_checklist("1.3.1")
    assert "report_sections" in template
    assert "verification_steps" in template


def test_generated_catalog_file_matches_expected_counts():

    data = yaml.safe_load(
        Path("data/assessment_knowledge_catalog.yaml").read_text(encoding="utf-8")
    )

    assert len(data["controls"]) == 177
    assert len(data["threat_scenarios"]) == 20
    assert len(data["attack_paths"]) == 15
    assert len(data["recommendations"]) == 177
