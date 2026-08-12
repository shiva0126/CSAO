from __future__ import annotations

import json
import zipfile
from pathlib import Path
import shutil

import pytest

from workbench.control_plane import AccountVault, WorkbenchState, read_json
from workbench.runtime import WorkbenchRuntime
from tests.test_pipeline import REPO_ROOT, run_pipeline


def test_account_vault_encrypts_credentials(tmp_path):
    state_store = WorkbenchState(tmp_path / "state.json")
    vault = AccountVault(state_store, key_file=tmp_path / ".secret.key")

    account = vault.save_account(
        {
            "name": "Prod AWS",
            "account_id": "123456789012",
            "auth_type": "access_keys",
            "access_key_id": "AKIATESTKEY1234",
            "secret_access_key": "super-secret-value",
            "regions": "us-east-1, us-west-2",
        }
    )

    state = read_json(tmp_path / "state.json", {})
    stored = state["cloud_accounts"][0]
    assert "super-secret-value" not in stored["credentials_encrypted"]
    assert (
        vault.get_credentials(account["id"])["secret_access_key"]
        == "super-secret-value"
    )
    assert account["masked_credentials"]["access_key_id"].startswith("AKIA")
    assert account["regions"] == ["us-east-1", "us-west-2"]


def test_account_vault_trusts_multiple_keys_after_rotation(tmp_path):
    state_store = WorkbenchState(tmp_path / "state.json")
    vault = AccountVault(
        state_store,
        key_file=tmp_path / ".secret.key",
        keyring_file=tmp_path / ".secret.keys.json",
    )
    account = vault.save_account(
        {
            "name": "Prod AWS",
            "account_id": "123456789012",
            "auth_type": "access_keys",
            "access_key_id": "AKIATESTKEY1234",
            "secret_access_key": "super-secret-value",
        }
    )

    original_keyring = vault.keyring_metadata()
    rotated = vault.rotate_active_key()

    assert rotated["active_key_id"] != original_keyring["active_key_id"]
    assert rotated["previous_active_key_id"] == original_keyring["active_key_id"]
    assert len(rotated["trusted_key_ids"]) == 2
    assert (
        vault.get_credentials(account["id"])["secret_access_key"]
        == "super-secret-value"
    )


def test_account_vault_revert_restores_previous_active_key(tmp_path):
    state_store = WorkbenchState(tmp_path / "state.json")
    vault = AccountVault(
        state_store,
        key_file=tmp_path / ".secret.key",
        keyring_file=tmp_path / ".secret.keys.json",
    )
    vault.save_account(
        {
            "name": "Prod AWS",
            "account_id": "123456789012",
            "auth_type": "access_keys",
            "access_key_id": "AKIATESTKEY1234",
            "secret_access_key": "super-secret-value",
        }
    )

    original = vault.keyring_metadata()
    vault.rotate_active_key()
    reverted = vault.revert_active_key()

    assert reverted["active_key_id"] == original["active_key_id"]
    assert len(reverted["trusted_key_ids"]) == 2


def test_account_vault_delete_removes_record(tmp_path):
    state_store = WorkbenchState(tmp_path / "state.json")
    vault = AccountVault(state_store, key_file=tmp_path / ".secret.key")
    account = vault.save_account(
        {"name": "Audit", "auth_type": "profile", "profile": "default"}
    )

    vault.delete_account(account["id"])

    assert vault.list_accounts() == []


def test_account_vault_preserves_existing_credentials_on_edit(tmp_path):
    state_store = WorkbenchState(tmp_path / "state.json")
    vault = AccountVault(state_store, key_file=tmp_path / ".secret.key")
    account = vault.save_account(
        {
            "name": "Prod AWS",
            "account_id": "123456789012",
            "auth_type": "access_keys",
            "access_key_id": "AKIATESTKEY1234",
            "secret_access_key": "super-secret-value",
        }
    )

    vault.save_account(
        {
            "id": account["id"],
            "name": "Prod AWS Updated",
            "account_id": "123456789012",
            "auth_type": "access_keys",
        }
    )

    assert (
        vault.get_credentials(account["id"])["secret_access_key"]
        == "super-secret-value"
    )


def test_account_vault_rejects_invalid_account_id(tmp_path):
    state_store = WorkbenchState(tmp_path / "state.json")
    vault = AccountVault(state_store, key_file=tmp_path / ".secret.key")

    with pytest.raises(ValueError):
        vault.save_account(
            {
                "name": "Bad",
                "account_id": "1234",
                "auth_type": "profile",
                "profile": "default",
            }
        )


def test_runtime_settings_and_evidence_path_guard(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runtime = WorkbenchRuntime()
    runtime.save_settings(
        {
            "collectors": ["aws_inventory", "prowler"],
            "regions": "us-east-1,us-west-2",
            "max_threads": "4",
            "retry_count": "2",
            "parallel_execution": "false",
            "log_level": "warning",
            "reports_directory": "output/reports",
            "report_formats": ["generate_html", "generate_json"],
            "risk_enabled": "false",
        }
    )

    payload = runtime.settings_payload()
    assert payload["execution"]["parallel_execution"] is False
    assert payload["reports"]["generate_pdf"] is False
    assert payload["risk_scoring"]["enabled"] is False

    with pytest.raises(ValueError):
        runtime.resolve_evidence_path("../secrets.txt")


def test_access_requirements_view_model_contains_policy_and_markdown(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runtime = WorkbenchRuntime()

    model = runtime.access_requirements_view_model()

    services = {item["service"] for item in model["required_permissions"]}
    assert "IAM" in services
    assert "Organizations" in services
    assert any(
        statement["Sid"] == "CSAOIAMReadOnly"
        for statement in model["policy"]["Statement"]
    )
    assert "CSAO performs a read-only security assessment." in model["policy_markdown"]
    assert any(
        row["capability_href"] == "/capability-validation"
        for row in model["permission_explanations"]
    )
    assert model["policy"]["PolicyName"] == "CSAO_Assessment_ReadOnly"
    actions = {
        action for statement in model["policy"]["Statement"] for action in statement["Action"]
    }
    assert "iam:GenerateCredentialReport" in actions
    assert "iam:GetCredentialReport" in actions
    assert "securityhub:GetFindings" in actions
    assert "guardduty:GetFindings" in actions
    assert "s3:GetBucketEncryption" in actions
    assert all("*" not in action for action in actions)
    assert model["services_covered"]["required_services"]


def test_capability_validation_view_model_defaults_without_accounts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runtime = WorkbenchRuntime()

    model = runtime.capability_validation_view_model()

    assert model["accounts"] == []
    assert model["validation"]["status"] == "NOT_READY"
    assert "Select a cloud account to validate." in model["validation"]["warnings"]
    assert isinstance(model["collectors"], list)


def test_access_requirements_policy_filters_disabled_collectors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runtime = WorkbenchRuntime()
    runtime.save_settings(
        {
            "collectors": ["aws_inventory", "cloudsplaining"],
            "regions": "us-east-1",
        }
    )

    model = runtime.access_requirements_view_model()

    assert set(model["enabled_collectors"]) == {"aws_inventory", "cloudsplaining"}
    actions = {
        action
        for statement in model["policy"]["Statement"]
        for action in statement["Action"]
    }
    assert "iam:GetAccountAuthorizationDetails" in actions
    assert "cloudtrail:DescribeTrails" not in actions
    assert all(row["collector"] in {"AWS Inventory", "Cloudsplaining"} for row in model["permission_matrix"])


def test_access_requirements_trust_policy_validation_and_package(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runtime = WorkbenchRuntime()

    model = runtime.access_requirements_view_model(
        trust_account_id="111122223333",
        assessment_role_name="CSAO-Assessor",
        use_root_trust=False,
        use_external_id=True,
    )

    trust_policy = model["trust_policy"]
    statement = trust_policy["Statement"][0]
    assert statement["Principal"]["AWS"] == "arn:aws:iam::111122223333:role/CSAO-Assessor"
    assert statement["Condition"]["StringEquals"]["sts:ExternalId"]
    assert model["policy_validation"]["status"] == "PASS"
    assert model["policy_summary_rows"]

    package_path = Path(model["onboarding_package"]["path"])
    assert package_path.exists()
    with zipfile.ZipFile(package_path) as archive:
        assert sorted(archive.namelist()) == [
            "README.md",
            "assessment-policy.json",
            "collector-permission-matrix.csv",
            "collector-permission-matrix.json",
            "permission-guide.md",
            "services-covered.json",
            "trust-policy.json",
        ]
        trust_payload = json.loads(archive.read("trust-policy.json"))
        assert trust_payload["Statement"][0]["Principal"]["AWS"] == "arn:aws:iam::111122223333:role/CSAO-Assessor"
        matrix_payload = json.loads(archive.read("collector-permission-matrix.json"))
        assert any(row["iam_actions"] == ["iam:GetAccountAuthorizationDetails"] for row in matrix_payload)


def test_access_requirements_root_trust_remains_supported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runtime = WorkbenchRuntime()

    model = runtime.access_requirements_view_model(
        trust_account_id="444455556666",
        assessment_role_name="CSAO-Assessor",
        use_root_trust=True,
    )

    statement = model["trust_policy"]["Statement"][0]
    assert statement["Principal"]["AWS"] == "arn:aws:iam::444455556666:root"


def test_report_rows_include_diagnostics_bundle(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    output = Path("output")
    (output / "workbench").mkdir(parents=True, exist_ok=True)
    bundle = output / "diagnostics" / "run-1" / "assessment_diagnostics.zip"
    bundle.parent.mkdir(parents=True, exist_ok=True)
    bundle.write_text("bundle", encoding="utf-8")
    summary = {
        "diagnostics": {"bundle_path": str(bundle)},
        "reports": [],
    }
    (output / "workbench" / "assessment_summary.json").write_text(
        json.dumps(summary), encoding="utf-8"
    )

    runtime = WorkbenchRuntime()
    runtime.refresh()

    rows = runtime.report_rows()

    assert any(row["title"] == "Assessment Diagnostics Bundle" for row in rows)
    diagnostics_row = next(
        row for row in rows if row["title"] == "Assessment Diagnostics Bundle"
    )
    assert diagnostics_row["previewable"] is False
    assert diagnostics_row["download_href"].startswith("/diagnostics/download?path=")


def test_trust_center_view_model_exposes_tool_and_safety_validation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runtime = WorkbenchRuntime()

    model = runtime.trust_center_view_model()

    assert model["safety_validation"]["status"] in {"PASSED", "FAILED"}
    assert isinstance(model["tool_validation"], list)
    assert any(item["name"] == "IAM Access Analyzer" for item in model["tool_validation"])


def test_threat_detail_handles_fixture_scenarios_without_optional_fields(
    tmp_path, monkeypatch
):
    shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "raw", tmp_path / "output" / "raw")
    for resource_dir in ("checklists", "crown_jewels", "data"):
        shutil.copytree(REPO_ROOT / resource_dir, tmp_path / resource_dir)
    evidence_index = {
        "generated": "test",
        "evidence": {
            "prowler": ["output/raw/prowler/prowler_findings.json"],
            "cloudsplaining": [
                "output/raw/cloudsplaining/authorization-details.json",
                "output/raw/cloudsplaining/report/report.json",
            ],
            "steampipe": ["output/raw/steampipe/aws/ec2/public_instances.json"],
        },
    }
    (tmp_path / "output").mkdir(parents=True, exist_ok=True)
    (tmp_path / "output" / "evidence_index.json").write_text(
        json.dumps(evidence_index), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    run_pipeline()

    runtime = WorkbenchRuntime()
    detail = runtime.detail_context("threat", "TS-011")

    assert detail["identifier"] == "TS-011"
    assert any(section["label"] == "Affected Crown Jewels" for section in detail["sections"])
