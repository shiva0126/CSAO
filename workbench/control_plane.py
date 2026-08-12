from __future__ import annotations

import asyncio
import copy
import datetime as dt
import hashlib
import json
import os
import shutil
import threading
import traceback
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)
from cryptography.fernet import Fernet

import yaml

from arq import create_pool
from arq.connections import RedisSettings
from sqlalchemy import select

from core.file_utils import atomic_write_json, load_json_with_recovery
from workbench.db.base import Base, SyncSessionLocal, sync_engine
from workbench.db.models import WorkbenchStateRow
from core.orchestrator import STAGES, run_pipeline

WORKBENCH_DIR = Path("output/workbench")
STATE_FILE = WORKBENCH_DIR / "state.json"
KEY_FILE = WORKBENCH_DIR / ".secret.key"
KEYRING_FILE = WORKBENCH_DIR / ".secret.keys.json"
AUDIT_LOG = WORKBENCH_DIR / "audit.log"
HISTORY_DIR = Path("output/history")
REPORT_ARCHIVE_DIR = Path("output/report_archive")
SUMMARY_FILE = WORKBENCH_DIR / "assessment_summary.json"

SENSITIVE_FIELDS = {
    "profile",
    "access_key_id",
    "secret_access_key",
    "session_token",
    "role_arn",
    "external_id",
    "source_profile",
    "sso_start_url",
    "sso_account_id",
    "sso_role_name",
    "sso_region",
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def read_json(path: Path, default):
    return load_json_with_recovery(path, default)


def write_json(path: Path, data) -> None:
    atomic_write_json(path, data)


class WorkbenchState:
    """Postgres-backed singleton-row store. Same .load()/.save()/.update()
    contract as the original JSON-file implementation, so AccountVault,
    AssessmentRunner, and WorkbenchRuntime need no changes -- only the
    storage backend underneath this class changed.

    `path` is kept as a compatibility attribute (some callers reference it
    for display/logging) but is no longer used for I/O.

    `state_id` defaults to 1 -- the real app's one and only row, unchanged
    for every production call site (WorkbenchRuntime, worker.py). Tests
    that need an isolated row (not the shared production one) pass a
    different id -- see tests/conftest.py's `isolated_state_id` fixture.
    Before this parameter existed, every `WorkbenchState(tmp_path / ...)`
    construction in tests/test_workbench_control_plane.py *looked*
    isolated via a distinct path argument, but `path` was never used for
    I/O after the Postgres migration -- every one of those tests was
    silently reading and writing the real production row. See
    MIGRATION_LEDGER.md for the corruption that caused in practice.
    """

    def __init__(self, path: Path = STATE_FILE, state_id: int = 1):
        self.path = path
        self.state_id = state_id
        self._lock = threading.RLock()
        Base.metadata.create_all(sync_engine, tables=[WorkbenchStateRow.__table__])

    def _defaults(self, state: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(state, dict):
            state = {}
        state.setdefault("cloud_accounts", [])
        state.setdefault("assessments", [])
        state.setdefault("finding_validations", {})
        state.setdefault("settings_overrides", {})
        state.setdefault("stages", {})
        state.setdefault("monitor", {})
        state.setdefault("active_assessment_id", "")
        state.setdefault("active_output_root", "output")
        return state

    def load(self) -> Dict[str, Any]:
        with self._lock:
            with SyncSessionLocal() as db:
                row = db.get(WorkbenchStateRow, self.state_id)
                return self._defaults(dict(row.data) if row else {})

    def save(self, state: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            state["updated_at"] = utc_now_iso()
            with SyncSessionLocal() as db:
                row = db.get(WorkbenchStateRow, self.state_id)
                if row is None:
                    row = WorkbenchStateRow(id=self.state_id, data=state, updated_at=utc_now())
                    db.add(row)
                else:
                    row.data = state
                    row.updated_at = utc_now()
                db.commit()
            return state

    def update(self, mutator):
        with self._lock:
            with SyncSessionLocal() as db:
                row = db.get(WorkbenchStateRow, self.state_id, with_for_update=True)
                current = self._defaults(dict(row.data) if row else {})
                updated = mutator(copy.deepcopy(current)) or current
                updated["updated_at"] = utc_now_iso()
                if row is None:
                    row = WorkbenchStateRow(id=self.state_id, data=updated, updated_at=utc_now())
                    db.add(row)
                else:
                    row.data = updated
                    row.updated_at = utc_now()
                db.commit()
                return updated


class AuditLogger:
    def __init__(self, path: Path = AUDIT_LOG):
        self.path = path
        self._lock = threading.RLock()

    def log(self, action: str, details: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"timestamp": utc_now_iso(), "action": action, "details": details}
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str) + "\n")


class AccountVault:
    def __init__(
        self,
        state_store: WorkbenchState,
        key_file: Path = KEY_FILE,
        keyring_file: Path = KEYRING_FILE,
        audit: Optional[AuditLogger] = None,
    ):
        self.state_store = state_store
        self.key_file = key_file
        self.keyring_file = keyring_file
        self.audit = audit or AuditLogger()

    def _ensure_legacy_key_file(self, key: bytes) -> None:
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.key_file.exists():
            with open(self.key_file, "wb") as handle:
                handle.write(key)
            os.chmod(self.key_file, 0o600)

    def _normalize_key_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key = str(entry.get("key") or "").strip()
        key_id = str(entry.get("id") or "").strip()
        if not key:
            return None
        if not key_id:
            key_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        return {
            "id": key_id,
            "key": key,
            "created_at": entry.get("created_at") or utc_now_iso(),
            "status": entry.get("status") or "trusted",
        }

    def _create_keyring(self, key: bytes) -> Dict[str, Any]:
        key_text = key.decode("utf-8")
        key_id = hashlib.sha256(key_text.encode("utf-8")).hexdigest()[:12]
        return {
            "active_key_id": key_id,
            "previous_active_key_id": "",
            "keys": [
                {
                    "id": key_id,
                    "key": key_text,
                    "created_at": utc_now_iso(),
                    "status": "active",
                }
            ],
        }

    def _write_keyring(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.keyring_file.parent.mkdir(parents=True, exist_ok=True)
        write_json(self.keyring_file, payload)
        os.chmod(self.keyring_file, 0o600)
        active = self._active_key_entry(payload)
        if active:
            self._ensure_legacy_key_file(active["key"].encode("utf-8"))
        return payload

    def _active_key_entry(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        active_key_id = payload.get("active_key_id", "")
        keys = payload.get("keys", [])
        for entry in keys:
            if isinstance(entry, dict) and entry.get("id") == active_key_id:
                normalized = self._normalize_key_entry(entry)
                if normalized:
                    normalized["status"] = "active"
                return normalized
        return None

    def _load_keyring(self) -> Dict[str, Any]:
        self.keyring_file.parent.mkdir(parents=True, exist_ok=True)
        if self.keyring_file.exists():
            payload = read_json(self.keyring_file, {})
            keys = []
            seen = set()
            for raw in payload.get("keys", []):
                if not isinstance(raw, dict):
                    continue
                normalized = self._normalize_key_entry(raw)
                if not normalized or normalized["id"] in seen:
                    continue
                seen.add(normalized["id"])
                keys.append(normalized)
            active_key_id = str(payload.get("active_key_id") or "").strip()
            if not active_key_id and keys:
                active_key_id = keys[0]["id"]
            active_present = any(entry["id"] == active_key_id for entry in keys)
            if not active_present:
                if self.key_file.exists():
                    active_key = self.key_file.read_bytes().strip()
                    if active_key:
                        imported = self._normalize_key_entry(
                            {
                                "key": active_key.decode("utf-8"),
                                "status": "active",
                            }
                        )
                        if imported and imported["id"] not in seen:
                            keys.insert(0, imported)
                            active_key_id = imported["id"]
                elif keys:
                    active_key_id = keys[0]["id"]
            for entry in keys:
                entry["status"] = "active" if entry["id"] == active_key_id else "trusted"
            payload = {
                "active_key_id": active_key_id,
                "previous_active_key_id": str(
                    payload.get("previous_active_key_id") or ""
                ).strip(),
                "keys": keys,
            }
            if not active_key_id:
                key = Fernet.generate_key()
                payload = self._create_keyring(key)
            return self._write_keyring(payload)
        if self.key_file.exists():
            key = self.key_file.read_bytes().strip()
            if key:
                return self._write_keyring(self._create_keyring(key))
        key = Fernet.generate_key()
        payload = self._create_keyring(key)
        self._ensure_legacy_key_file(key)
        return self._write_keyring(payload)

    def _ciphers(self) -> List[Tuple[Dict[str, Any], Fernet]]:
        keyring = self._load_keyring()
        active_key_id = keyring.get("active_key_id", "")
        ordered = sorted(
            keyring.get("keys", []),
            key=lambda entry: (0 if entry.get("id") == active_key_id else 1, entry.get("created_at", "")),
        )
        return [
            (entry, Fernet(entry["key"].encode("utf-8")))
            for entry in ordered
            if isinstance(entry, dict) and entry.get("key")
        ]

    def _encrypt(self, payload: Dict[str, Any]) -> str:
        ciphers = self._ciphers()
        if not ciphers:
            raise RuntimeError("No account vault encryption keys are available.")
        token = ciphers[0][1].encrypt(json.dumps(payload).encode("utf-8"))
        return token.decode("utf-8")

    def _decrypt(self, token: str) -> Dict[str, Any]:
        if not token:
            return {}
        last_error = None
        for _, cipher in self._ciphers():
            try:
                data = cipher.decrypt(token.encode("utf-8"))
                payload = json.loads(data.decode("utf-8"))
                return payload if isinstance(payload, dict) else {}
            except Exception as exc:
                last_error = exc
        raise ValueError("Stored account credentials could not be decrypted with any trusted key.") from last_error

    def keyring_metadata(self) -> Dict[str, Any]:
        keyring = self._load_keyring()
        return {
            "active_key_id": keyring.get("active_key_id", ""),
            "previous_active_key_id": keyring.get("previous_active_key_id", ""),
            "trusted_key_ids": [entry.get("id", "") for entry in keyring.get("keys", [])],
        }

    def rotate_active_key(self) -> Dict[str, Any]:
        keyring = self._load_keyring()
        previous_active_key_id = keyring.get("active_key_id", "")
        new_key = Fernet.generate_key().decode("utf-8")
        new_entry = self._normalize_key_entry({"key": new_key, "status": "active"})
        if not new_entry:
            raise RuntimeError("Failed to generate a new account vault key.")
        keys = [
            {
                **entry,
                "status": "trusted",
            }
            for entry in keyring.get("keys", [])
            if isinstance(entry, dict)
        ]
        keys.insert(0, new_entry)
        payload = {
            "active_key_id": new_entry["id"],
            "previous_active_key_id": previous_active_key_id,
            "keys": keys,
        }
        self._write_keyring(payload)
        self.audit.log(
            "account_vault_key_rotated",
            {
                "active_key_id": new_entry["id"],
                "previous_active_key_id": previous_active_key_id,
            },
        )
        return self.keyring_metadata()

    def revert_active_key(self) -> Dict[str, Any]:
        keyring = self._load_keyring()
        current_active_key_id = keyring.get("active_key_id", "")
        previous_active_key_id = keyring.get("previous_active_key_id", "")
        if not previous_active_key_id:
            raise ValueError("No previous active account vault key is available for revert.")
        keys = []
        found_previous = False
        for entry in keyring.get("keys", []):
            if not isinstance(entry, dict):
                continue
            normalized = self._normalize_key_entry(entry)
            if not normalized:
                continue
            if normalized["id"] == previous_active_key_id:
                found_previous = True
            normalized["status"] = (
                "active" if normalized["id"] == previous_active_key_id else "trusted"
            )
            keys.append(normalized)
        if not found_previous:
            raise ValueError("The previous active account vault key is no longer trusted.")
        payload = {
            "active_key_id": previous_active_key_id,
            "previous_active_key_id": current_active_key_id,
            "keys": keys,
        }
        self._write_keyring(payload)
        self.audit.log(
            "account_vault_key_reverted",
            {
                "active_key_id": previous_active_key_id,
                "previous_active_key_id": current_active_key_id,
            },
        )
        return self.keyring_metadata()

    def list_accounts(self) -> List[Dict[str, Any]]:
        state = self.state_store.load()
        return [
            self._public_account_view(item)
            for item in state.get("cloud_accounts", [])
            if isinstance(item, dict)
        ]

    def get_account_record(self, account_id: str) -> Optional[Dict[str, Any]]:
        state = self.state_store.load()
        for item in state.get("cloud_accounts", []):
            if isinstance(item, dict) and item.get("id") == account_id:
                return item
        return None

    def get_account(self, account_id: str) -> Optional[Dict[str, Any]]:
        record = self.get_account_record(account_id)
        if not record:
            return None
        return self._public_account_view(record)

    def get_credentials(self, account_id: str) -> Dict[str, Any]:
        record = self.get_account_record(account_id)
        if not record:
            return {}
        encrypted = record.get("credentials_encrypted", "")
        return self._decrypt(encrypted) if encrypted else {}

    def save_account(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        account_id = payload.get("id") or f"acct-{uuid.uuid4().hex[:10]}"
        name = str(payload.get("name") or payload.get("alias") or "AWS Account").strip()
        auth_type = str(payload.get("auth_type") or "profile").strip().lower()
        existing = self.get_account_record(account_id) or {}
        metadata = {
            "account_id": str(payload.get("account_id") or "").strip(),
            "alias": str(payload.get("alias") or "").strip(),
            "regions": [
                item.strip()
                for item in str(payload.get("regions") or "").split(",")
                if item.strip()
            ],
            "notes": str(payload.get("notes") or "").strip(),
            "read_only_validated": False,
            "credential_expiry": "",
        }
        submitted_credentials = {
            key: str(payload.get(key) or "").strip()
            for key in SENSITIVE_FIELDS
            if str(payload.get(key) or "").strip()
        }
        if submitted_credentials:
            credentials = submitted_credentials
        elif existing:
            credentials = self._decrypt(existing.get("credentials_encrypted", ""))
        else:
            credentials = {}
        self._validate_account_payload(auth_type, metadata, credentials)
        encrypted = self._encrypt(credentials)

        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            accounts = []
            found = False
            for item in state.get("cloud_accounts", []):
                if not isinstance(item, dict):
                    continue
                if item.get("id") == account_id:
                    updated = copy.deepcopy(item)
                    updated.update(
                        {
                            "id": account_id,
                            "name": name,
                            "cloud": "aws",
                            "auth_type": auth_type,
                            "metadata": metadata,
                            "credentials_encrypted": encrypted,
                            "updated_at": utc_now_iso(),
                        }
                    )
                    accounts.append(updated)
                    found = True
                else:
                    accounts.append(item)
            if not found:
                accounts.append(
                    {
                        "id": account_id,
                        "name": name,
                        "cloud": "aws",
                        "auth_type": auth_type,
                        "metadata": metadata,
                        "credentials_encrypted": encrypted,
                        "created_at": utc_now_iso(),
                        "updated_at": utc_now_iso(),
                        "last_validated": "",
                        "last_validation_status": "NEVER_TESTED",
                        "last_validation_error": "",
                    }
                )
            state["cloud_accounts"] = accounts
            return state

        self.state_store.update(mutate)
        self.audit.log(
            "account_saved", {"account_id": account_id, "auth_type": auth_type}
        )
        return next(item for item in self.list_accounts() if item["id"] == account_id)

    def validate_account_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        auth_type = str(payload.get("auth_type") or "profile").strip().lower()
        metadata = {
            "account_id": str(payload.get("account_id") or "").strip(),
            "alias": str(payload.get("alias") or "").strip(),
            "regions": [
                item.strip()
                for item in str(payload.get("regions") or "").split(",")
                if item.strip()
            ],
            "notes": str(payload.get("notes") or "").strip(),
            "read_only_validated": False,
            "credential_expiry": "",
        }
        credentials = {
            key: str(payload.get(key) or "").strip()
            for key in SENSITIVE_FIELDS
            if str(payload.get(key) or "").strip()
        }
        self._validate_account_payload(auth_type, metadata, credentials)
        result = self._test_aws_connection(auth_type, credentials, metadata)
        self.audit.log(
            "account_payload_validated",
            {
                "auth_type": auth_type,
                "status": result["status"],
                "account_id": result["metadata"].get("account_id", ""),
            },
        )
        return result

    def _validate_account_payload(
        self, auth_type: str, metadata: Dict[str, Any], credentials: Dict[str, Any]
    ) -> None:
        if auth_type not in {"profile", "access_keys", "assume_role", "sso"}:
            raise ValueError(f"Unsupported auth type {auth_type}")
        if metadata.get("account_id") and (
            not metadata["account_id"].isdigit() or len(metadata["account_id"]) != 12
        ):
            raise ValueError("AWS account ID must be a 12-digit number.")
        required_by_type = {
            "profile": ["profile"],
            "access_keys": ["access_key_id", "secret_access_key"],
            "assume_role": ["role_arn"],
            "sso": ["profile"],
        }
        missing = [
            field for field in required_by_type[auth_type] if not credentials.get(field)
        ]
        if missing:
            raise ValueError(
                f"Missing required fields for {auth_type}: {', '.join(missing)}"
            )
        if auth_type == "assume_role" and not (
            credentials.get("source_profile") or credentials.get("profile")
        ):
            raise ValueError("Assume Role requires a source profile or profile.")

    def delete_account(self, account_id: str) -> None:
        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            state["cloud_accounts"] = [
                item
                for item in state.get("cloud_accounts", [])
                if not (isinstance(item, dict) and item.get("id") == account_id)
            ]
            return state

        self.state_store.update(mutate)
        self.audit.log("account_deleted", {"account_id": account_id})

    def test_connection(self, account_id: str) -> Dict[str, Any]:
        record = self.get_account_record(account_id)
        if not record:
            raise KeyError(f"Unknown account {account_id}")

        auth_type = record.get("auth_type", "profile")
        creds = self.get_credentials(account_id)
        metadata = copy.deepcopy(record.get("metadata", {}))
        result = self._test_aws_connection(auth_type, creds, metadata)

        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            for item in state.get("cloud_accounts", []):
                if isinstance(item, dict) and item.get("id") == account_id:
                    item["metadata"] = result["metadata"]
                    item["last_validated"] = result["validated_at"]
                    item["last_validation_status"] = result["status"]
                    item["last_validation_error"] = result["error"]
            return state

        self.state_store.update(mutate)
        self.audit.log(
            "account_tested", {"account_id": account_id, "status": result["status"]}
        )
        return self.get_account(account_id) or {}

    def _public_account_view(self, record: Dict[str, Any]) -> Dict[str, Any]:
        metadata = copy.deepcopy(record.get("metadata", {}))
        creds = (
            self._decrypt(record.get("credentials_encrypted", ""))
            if record.get("credentials_encrypted")
            else {}
        )
        masked = {}
        for key, value in creds.items():
            if key == "profile":
                masked[key] = value
            elif len(value) >= 8:
                masked[key] = value[:4] + "*" * (len(value) - 8) + value[-4:]
            else:
                masked[key] = "*" * len(value)
        expiry = metadata.get("credential_expiry", "")
        expired = False
        if expiry:
            try:
                expired = (
                    dt.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                    <= utc_now()
                )
            except ValueError:
                expired = False
        return {
            "id": record.get("id", ""),
            "name": record.get("name", ""),
            "cloud": record.get("cloud", "aws"),
            "auth_type": record.get("auth_type", "profile").upper(),
            "account_id": metadata.get("account_id", ""),
            "alias": metadata.get("alias", ""),
            "regions": metadata.get("regions", []),
            "notes": metadata.get("notes", ""),
            "last_validated": record.get("last_validated", ""),
            "last_validation_status": record.get(
                "last_validation_status", "NEVER_TESTED"
            ),
            "last_validation_error": record.get("last_validation_error", ""),
            "masked_credentials": masked,
            "read_only_validated": bool(metadata.get("read_only_validated")),
            "credential_expiry": expiry,
            "credential_expired": expired,
        }

    def _test_aws_connection(
        self, auth_type: str, credentials: Dict[str, Any], metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        validated_at = utc_now_iso()
        status = "FAILED"
        error = ""
        read_only_validated = False
        expiry = ""
        account_id = metadata.get("account_id", "")
        alias = metadata.get("alias", "")
        regions = metadata.get("regions", [])
        caller_arn = metadata.get("caller_arn", "")
        try:
            session, expiration = self._build_session(auth_type, credentials, metadata)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity.get("Account", account_id)
            caller_arn = identity.get("Arn", caller_arn)
            region_name = regions[0] if regions else "us-east-1"
            ec2 = session.client("ec2", region_name=region_name)
            describe = ec2.describe_regions(AllRegions=False)
            if not regions:
                regions = [item["RegionName"] for item in describe.get("Regions", [])]
            alias = self._fetch_account_alias(session, region_name) or alias
            read_only_validated = True
            status = "VALIDATED"
            if expiration:
                expiry = (
                    expiration.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")
                )
        except (ProfileNotFound, NoCredentialsError) as exc:
            error = str(exc)
        except (ClientError, BotoCoreError, ValueError) as exc:
            error = str(exc)

        metadata.update(
            {
                "account_id": account_id,
                "alias": alias,
                "caller_arn": caller_arn,
                "regions": regions,
                "read_only_validated": read_only_validated,
                "credential_expiry": expiry,
            }
        )
        return {
            "validated_at": validated_at,
            "status": status,
            "error": error,
            "metadata": metadata,
        }

    def _build_session(
        self, auth_type: str, credentials: Dict[str, Any], metadata: Dict[str, Any]
    ) -> Tuple[boto3.Session, Optional[dt.datetime]]:
        auth_type = auth_type.lower()
        if auth_type == "profile":
            return boto3.Session(profile_name=credentials.get("profile") or None), None
        if auth_type == "access_keys":
            return (
                boto3.Session(
                    aws_access_key_id=credentials.get("access_key_id"),
                    aws_secret_access_key=credentials.get("secret_access_key"),
                    aws_session_token=credentials.get("session_token") or None,
                ),
                None,
            )
        if auth_type == "assume_role":
            source_profile = credentials.get("source_profile") or credentials.get(
                "profile"
            )
            base = boto3.Session(profile_name=source_profile or None)
            sts = base.client("sts")
            response = sts.assume_role(
                RoleArn=credentials.get("role_arn"),
                RoleSessionName=f"csao-{uuid.uuid4().hex[:8]}",
                **(
                    {"ExternalId": credentials.get("external_id")}
                    if credentials.get("external_id")
                    else {}
                ),
            )
            assumed = response["Credentials"]
            expiration = assumed["Expiration"]
            return (
                boto3.Session(
                    aws_access_key_id=assumed["AccessKeyId"],
                    aws_secret_access_key=assumed["SecretAccessKey"],
                    aws_session_token=assumed["SessionToken"],
                ),
                expiration,
            )
        if auth_type == "sso":
            profile = credentials.get("profile")
            if not profile:
                raise ValueError(
                    "AWS SSO is future-ready but currently requires an existing AWS CLI SSO profile."
                )
            return boto3.Session(profile_name=profile), None
        raise ValueError(f"Unsupported auth type {auth_type}")

    def _fetch_account_alias(self, session: boto3.Session, region_name: str) -> str:
        try:
            iam = session.client("iam", region_name=region_name)
            response = iam.list_account_aliases()
            aliases = response.get("AccountAliases", [])
            return aliases[0] if aliases else ""
        except Exception:
            return ""


class AssessmentRunner:
    # Shared with main.py's CLI path via core/orchestrator.py -- no longer
    # defined twice.
    STAGES = STAGES

    def __init__(
        self,
        state_store: WorkbenchState,
        audit: Optional[AuditLogger] = None,
        exception_callback=None,
    ):
        self.state_store = state_store
        self.audit = audit or AuditLogger()
        self.exception_callback = exception_callback
        self._lock = threading.RLock()

    def active_monitor(self) -> Dict[str, Any]:
        state = self.state_store.load()
        return state.get("monitor", {})

    def start(
        self,
        base_config: Dict[str, Any],
        assessment: Dict[str, Any],
        account: Dict[str, Any],
        account_credentials: Dict[str, Any],
        validations: Dict[str, Any],
    ) -> Dict[str, Any]:
        with self._lock:
            monitor = self.active_monitor()
            if monitor.get("status") == "RUNNING":
                raise RuntimeError("An assessment is already running.")
            asyncio.run(
                self._enqueue(
                    copy.deepcopy(base_config),
                    copy.deepcopy(assessment),
                    copy.deepcopy(account),
                    copy.deepcopy(account_credentials),
                    copy.deepcopy(validations),
                )
            )
        return self.active_monitor()

    async def _enqueue(
        self,
        base_config: Dict[str, Any],
        assessment: Dict[str, Any],
        account: Dict[str, Any],
        account_credentials: Dict[str, Any],
        validations: Dict[str, Any],
    ) -> None:
        pool = await create_pool(RedisSettings.from_dsn(os.environ["REDIS_URL"]))
        try:
            await pool.enqueue_job(
                "run_assessment_job",
                base_config, assessment, account, account_credentials, validations,
            )
        finally:
            await pool.close()

    def retry_stage(self, stage_key: str) -> Dict[str, Any]:
        monitor = self.active_monitor()
        assessment = monitor.get("assessment")
        if not assessment:
            raise KeyError("No active assessment context")
        raise KeyError(
            f'Stage retry for "{stage_key}" is only available during a new assessment run.'
        )

    def cancel(self) -> Dict[str, Any]:
        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            monitor = state.setdefault("monitor", {})
            if monitor.get("status") != "RUNNING":
                raise RuntimeError("No running assessment to cancel.")
            monitor["cancel_requested"] = True
            monitor["status_message"] = (
                "Cancellation requested. The current stage will stop at the next checkpoint."
            )
            return state

        self.state_store.update(mutate)
        self.audit.log("assessment_cancel_requested", {})
        return self.active_monitor()

    def _run_assessment_body(
        self,
        base_config: Dict[str, Any],
        assessment: Dict[str, Any],
        account: Dict[str, Any],
        account_credentials: Dict[str, Any],
        validations: Dict[str, Any],
    ) -> None:
        started_at = utc_now()
        assessment_id = f"ASSESS-{started_at.strftime('%Y%m%d-%H%M%S')}"
        assessment_record = {
            "id": assessment_id,
            "name": assessment.get("name") or assessment_id,
            "client": assessment.get("client", ""),
            "cloud": "aws",
            "status": "RUNNING",
            "started": started_at.isoformat().replace("+00:00", "Z"),
            "completed": "",
            "duration": "",
            "account_id": account.get("id", ""),
            "account_name": account.get("name", ""),
            "regions": assessment.get("regions", []),
            "collectors": assessment.get("collectors", []),
            "output_location": "output",
            "report_files": [],
            "snapshot_directory": "",
            "diagnostics_bundle": "",
        }
        self._initialize_run(assessment_record)
        config = self._build_run_config(
            base_config, assessment, account, account_credentials
        )

        findings: List[Any] = []
        attack_path_candidates: List[Any] = []

        try:
            state_snapshot = self.state_store.load()
            assessment_metadata = {
                "permission_matrix": state_snapshot.get("preflight_validation", {}).get(
                    "permission_matrix", []
                ),
                "capability_validation": state_snapshot.get("preflight_validation", {}),
                "safety_validation": state_snapshot.get("safety_validation", {}),
                "tool_validation": [],
            }
            result = run_pipeline(
                config,
                assessment_id,
                stage_hook=self._mark_stage,
                cancel_check=lambda: bool(self.active_monitor().get("cancel_requested")),
                validations=validations,
                assessment_metadata=assessment_metadata,
            )
            findings = result.findings
            attack_path_candidates = result.attack_path_candidates

            diagnostics = self._build_diagnostics_bundle(
                assessment_id=assessment_id,
                started_at=started_at,
                account=account,
                assessment=assessment,
                execution_status=result.execution_status,
                discovery_summary=result.discovery_summary,
                risk_summary=result.risk_summary,
                report_files=result.report_files,
            )
            self.write_assessment_summary(
                assessment_id=assessment_id,
                findings=result.filtered_findings,
                assessment_register=result.filtered_register,
                checklist_coverage=result.checklist_coverage,
                threat_scenarios=result.threat_scenarios,
                correlated_threats=result.correlated_threats,
                attack_path_candidates=result.attack_path_candidates,
                risk_summary=result.risk_summary,
                recommendations=result.recommendations,
                discovery_summary=result.discovery_summary,
                evidence_index=result.evidence_index,
                report_files=result.report_files,
                diagnostics=diagnostics,
            )

            snapshot_dir = self._snapshot_outputs(assessment_id)
            self._complete_run(
                assessment_id,
                "COMPLETED",
                started_at,
                snapshot_dir,
                len(result.filtered_findings),
                len(result.attack_path_candidates),
                diagnostics.get("bundle_path", ""),
            )
        except RuntimeError as exc:
            if self.exception_callback and not str(exc).startswith("CANCELLED:"):
                self.exception_callback(
                    "assessment_runner",
                    exc,
                    assessment_id=assessment_id,
                    traceback=traceback.format_exc().strip(),
                )
            if str(exc).startswith("CANCELLED:"):
                self._complete_run(
                    assessment_id,
                    "CANCELLED",
                    started_at,
                    "",
                    len(findings),
                    len(attack_path_candidates),
                )
                self.audit.log(
                    "assessment_cancelled",
                    {
                        "assessment_id": assessment_id,
                        "checkpoint": str(exc).split(":", 1)[1].strip(),
                    },
                )
            else:
                self._mark_failure(str(exc))
                self._complete_run(
                    assessment_id,
                    "FAILED",
                    started_at,
                    "",
                    len(findings),
                    len(attack_path_candidates),
                )
                self.audit.log(
                    "assessment_failed", {"assessment_id": assessment_id, "error": str(exc)}
                )
        except Exception as exc:
            if self.exception_callback:
                self.exception_callback(
                    "assessment_runner",
                    exc,
                    assessment_id=assessment_id,
                    traceback=traceback.format_exc().strip(),
                )
            self._mark_failure(str(exc))
            self._complete_run(
                assessment_id,
                "FAILED",
                started_at,
                "",
                len(findings),
                len(attack_path_candidates),
            )
            self.audit.log(
                "assessment_failed", {"assessment_id": assessment_id, "error": str(exc)}
            )

    def _build_run_config(
        self,
        base_config: Dict[str, Any],
        assessment: Dict[str, Any],
        account: Dict[str, Any],
        account_credentials: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = copy.deepcopy(base_config)
        config["platform"] = "aws"
        config.setdefault("aws", {})
        config["aws"]["regions"] = (
            assessment.get("regions")
            or account.get("regions")
            or config["aws"].get("regions", [])
        )
        config["aws"]["profile"] = account_credentials.get("profile") or config[
            "aws"
        ].get("profile", "default")
        config["aws"]["account_ids"] = (
            [account.get("account_id")] if account.get("account_id") else []
        )
        config["aws"]["auth_type"] = account.get("auth_type", "profile").lower()
        config["aws"]["credentials"] = copy.deepcopy(account_credentials)
        config.setdefault("framework", {})
        config["framework"]["name"] = assessment.get("name") or config["framework"].get(
            "name", "CSAO"
        )
        modules = config.setdefault("modules", {})
        enabled = set(assessment.get("collectors") or [])
        for key in list(modules.keys()):
            modules[key] = (
                key in enabled
                if key != "aws_inventory"
                else ("aws_inventory" in enabled or modules.get(key, True))
            )
        overrides = assessment.get("settings_overrides", {})
        return deep_merge(config, overrides)

    def _initialize_run(self, assessment_record: Dict[str, Any]) -> None:
        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            state["active_assessment_id"] = assessment_record["id"]
            state["active_output_root"] = "output"
            state["stages"] = {
                key: {
                    "status": "NOT_RUN",
                    "start_time": "",
                    "finish_time": "",
                    "duration": "",
                    "errors": [],
                }
                for key, _ in self.STAGES
            }
            state["monitor"] = {
                "assessment": assessment_record,
                "status": "RUNNING",
                "status_message": "Assessment launched from the Analyst Console.",
                "current_stage": "",
                "current_collector": "",
                "current_api": "",
                "progress": 0,
                "resources_processed": 0,
                "failures": [],
                "warnings": [],
                "elapsed_time": "0s",
                "estimated_remaining_time": "",
                "started_at": utc_now_iso(),
                "cancel_requested": False,
                "timeline": [
                    {
                        "timestamp": utc_now_iso(),
                        "event": "Assessment launched",
                        "stage": "launch",
                        "status": "COMPLETED",
                        "detail": assessment_record["name"],
                    }
                ],
                "validation": state.get("preflight_validation", {}),
                "collector_validation": (
                    state.get("preflight_validation", {}).get("collectors", [])
                ),
                "permission_coverage": {
                    "status": state.get("preflight_validation", {}).get("status", "NOT_READY"),
                    "available_capabilities": sum(
                        1
                        for item in state.get("preflight_validation", {}).get("capabilities", [])
                        if item.get("status") == "Available"
                    ),
                    "total_capabilities": len(
                        state.get("preflight_validation", {}).get("capabilities", [])
                    ),
                },
                "safety_validation": state.get("safety_validation", {}),
            }
            assessments = [
                item
                for item in state.get("assessments", [])
                if item.get("id") != assessment_record["id"]
            ]
            assessments.insert(0, assessment_record)
            state["assessments"] = assessments
            return state

        self.state_store.update(mutate)
        self.audit.log(
            "assessment_started",
            {
                "assessment_id": assessment_record["id"],
                "name": assessment_record["name"],
            },
        )

    def _mark_stage(
        self,
        stage_key: str,
        status: str,
        current_collector: str = "",
        current_api: str = "",
        resources_processed: Optional[int] = None,
    ) -> None:
        stage_index = next(
            (index for index, (key, _) in enumerate(self.STAGES) if key == stage_key), 0
        )

        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            stage = state.get("stages", {}).setdefault(stage_key, {"errors": []})
            now = utc_now_iso()
            if status == "RUNNING" and not stage.get("start_time"):
                stage["start_time"] = now
            if status in {"COMPLETED", "FAILED"}:
                stage["finish_time"] = now
            stage["status"] = status
            if stage.get("start_time") and stage.get("finish_time"):
                start = dt.datetime.fromisoformat(
                    stage["start_time"].replace("Z", "+00:00")
                )
                finish = dt.datetime.fromisoformat(
                    stage["finish_time"].replace("Z", "+00:00")
                )
                stage["duration"] = str(finish - start).split(".")[0]
            monitor = state.setdefault("monitor", {})
            monitor["current_stage"] = stage_key
            monitor["current_collector"] = current_collector
            monitor["current_api"] = current_api
            monitor["status_message"] = (
                f"{status.title()} {stage_key.replace('_', ' ')}"
            )
            monitor["progress"] = round(
                ((stage_index + (1 if status == "COMPLETED" else 0)) / len(self.STAGES))
                * 100
            )
            if resources_processed is not None:
                monitor["resources_processed"] = resources_processed
            timeline = list(monitor.get("timeline", []))
            timeline.append(
                {
                    "timestamp": now,
                    "event": f"{stage_key.replace('_', ' ').title()} {status.lower()}",
                    "stage": stage_key,
                    "status": status,
                    "detail": current_api or current_collector or "",
                    "items_processed": resources_processed if resources_processed is not None else "",
                }
            )
            monitor["timeline"] = timeline[-200:]
            started_at = monitor.get("started_at")
            if started_at:
                start = dt.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                elapsed = utc_now() - start
                monitor["elapsed_time"] = str(elapsed).split(".")[0]
                if monitor["progress"]:
                    remaining = (
                        elapsed * (100 - monitor["progress"]) / monitor["progress"]
                    )
                    monitor["estimated_remaining_time"] = str(remaining).split(".")[0]
            return state

        self.state_store.update(mutate)

    def _mark_failure(self, message: str) -> None:
        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            monitor = state.setdefault("monitor", {})
            failures = list(monitor.get("failures", []))
            failures.append(message)
            monitor["failures"] = failures
            monitor["status"] = "FAILED"
            monitor["status_message"] = message
            timeline = list(monitor.get("timeline", []))
            timeline.append(
                {
                    "timestamp": utc_now_iso(),
                    "event": "Assessment failed",
                    "stage": monitor.get("current_stage", ""),
                    "status": "FAILED",
                    "detail": message,
                }
            )
            monitor["timeline"] = timeline[-200:]
            current_stage = monitor.get("current_stage")
            if current_stage:
                stage = state.setdefault("stages", {}).setdefault(
                    current_stage, {"errors": []}
                )
                stage["status"] = "FAILED"
                stage["errors"] = list(stage.get("errors", [])) + [message]
                stage["finish_time"] = utc_now_iso()
            return state

        self.state_store.update(mutate)

    def _complete_run(
        self,
        assessment_id: str,
        status: str,
        started_at: dt.datetime,
        snapshot_dir: str,
        finding_count: int,
        attack_path_count: int,
        diagnostics_bundle: str = "",
    ) -> None:
        finished = utc_now()
        duration = str(finished - started_at).split(".")[0]

        def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
            monitor = state.setdefault("monitor", {})
            monitor["status"] = status
            monitor["elapsed_time"] = duration
            monitor["estimated_remaining_time"] = (
                "0:00:00"
                if status == "COMPLETED"
                else monitor.get("estimated_remaining_time", "")
            )
            monitor["status_message"] = f"Assessment {status.lower()}."
            timeline = list(monitor.get("timeline", []))
            timeline.append(
                {
                    "timestamp": finished.isoformat().replace("+00:00", "Z"),
                    "event": f"Assessment {status.lower()}",
                    "stage": "complete",
                    "status": status,
                    "detail": duration,
                }
            )
            monitor["timeline"] = timeline[-200:]
            assessments = []
            report_files = [
                str(path) for path in sorted(Path("output/reports").glob("*.html"))
            ]
            for item in state.get("assessments", []):
                if item.get("id") == assessment_id:
                    item = copy.deepcopy(item)
                    item["status"] = status
                    item["completed"] = finished.isoformat().replace("+00:00", "Z")
                    item["duration"] = duration
                    item["report_files"] = report_files
                    item["snapshot_directory"] = snapshot_dir
                    item["finding_count"] = finding_count
                    item["attack_path_count"] = attack_path_count
                    item["diagnostics_bundle"] = diagnostics_bundle
                assessments.append(item)
            state["assessments"] = assessments
            return state

        self.state_store.update(mutate)
        self.audit.log(
            "assessment_completed", {"assessment_id": assessment_id, "status": status}
        )

    def write_assessment_summary(
        self,
        assessment_id: str,
        findings,
        assessment_register,
        checklist_coverage,
        threat_scenarios,
        correlated_threats,
        attack_path_candidates,
        risk_summary,
        recommendations,
        discovery_summary,
        evidence_index,
        report_files,
        diagnostics,
    ) -> None:
        findings_by_severity = {}
        for finding in findings:
            severity = getattr(finding, "severity", "INFO") or "INFO"
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

        checklist_progress = {
            "PASS": 0,
            "FAIL": 0,
            "MANUAL_REVIEW": 0,
            "NOT_EVALUATED": 0,
        }
        for item in checklist_coverage:
            status = item.get("status", "NOT_EVALUATED")
            checklist_progress[status] = checklist_progress.get(status, 0) + 1
        checklist_progress["total"] = sum(checklist_progress.values())

        evidence_rows = []
        for source, files in (evidence_index or {}).items():
            for file_path in files:
                path = Path(file_path)
                if not path.is_absolute():
                    path = (Path.cwd() / file_path).resolve()
                exists = path.exists()
                evidence_rows.append(
                    {
                        "source": source,
                        "path": str(path),
                        "name": path.name,
                        "exists": exists,
                        "size": path.stat().st_size if exists else 0,
                        "modified": (
                            dt.datetime.fromtimestamp(
                                path.stat().st_mtime, dt.UTC
                            ).isoformat().replace("+00:00", "Z")
                            if exists
                            else ""
                        ),
                        "kind": path.suffix.lstrip(".") or "file",
                    }
                )

        reports = []
        for report_path in report_files:
            path = Path(report_path)
            if not path.exists():
                continue
            reports.append(
                {
                    "name": path.name,
                    "title": path.stem.replace("_", " ").title(),
                    "path": str(path),
                    "size": path.stat().st_size,
                    "generated_at": dt.datetime.fromtimestamp(
                        path.stat().st_mtime, dt.UTC
                    ).isoformat().replace("+00:00", "Z"),
                }
            )

        summary = {
            "generated_at": utc_now_iso(),
            "assessment_id": assessment_id,
            "base_directory": "output",
            "resources_discovered": self._resource_count(discovery_summary),
            "findings": len(findings),
            "findings_by_severity": findings_by_severity,
            "register_entries": len(assessment_register),
            "checklist_progress": checklist_progress,
            "threat_scenarios": len(threat_scenarios),
            "correlated_threats": len(correlated_threats),
            "attack_paths": len(attack_path_candidates),
            "recommendations": len(recommendations),
            "manual_reviews_remaining": checklist_progress.get("MANUAL_REVIEW", 0),
            "high_risk_findings": sum(
                1 for finding in findings if (getattr(finding, "_risk_score", 0) or 0) >= 70
            ),
            "evidence_sources": len(evidence_index or {}),
            "evidence_rows": evidence_rows,
            "risk_summary": risk_summary or {},
            "reports": reports,
            "timeline": self.active_monitor().get("timeline", []),
            "diagnostics": diagnostics or {},
            "recent_activity": [
                {
                    "name": name,
                    "when": dt.datetime.fromtimestamp(
                        (Path("output") / name).stat().st_mtime, dt.UTC
                    ).isoformat().replace("+00:00", "Z"),
                }
                for name in (
                    "discovery/asset_inventory.json",
                    "evidence_index.json",
                    "normalized/findings.json",
                    "assessment_register/assessment_register.json",
                    "checklist/checklist_coverage.json",
                    "threats/threat_scenarios.json",
                    "threats/correlated_threats.json",
                    "attack_paths/attack_path_candidates.json",
                    "risk/risk_summary.json",
                    "reports/index.html",
                )
                if (Path("output") / name).exists()
            ],
        }
        write_json(SUMMARY_FILE, summary)

    def _build_diagnostics_bundle(
        self,
        assessment_id: str,
        started_at: dt.datetime,
        account: Dict[str, Any],
        assessment: Dict[str, Any],
        execution_status: Dict[str, Any],
        discovery_summary: Dict[str, Any],
        risk_summary: Dict[str, Any],
        report_files: List[str],
    ) -> Dict[str, Any]:
        diagnostics_dir = Path("output") / "diagnostics" / assessment_id
        diagnostics_dir.mkdir(parents=True, exist_ok=True)
        monitor = self.active_monitor()
        payload = {
            "assessment_id": assessment_id,
            "assessment_name": assessment.get("name", ""),
            "client": assessment.get("client", ""),
            "aws_account": account.get("account_id", ""),
            "regions": assessment.get("regions", []),
            "services": assessment.get("services", []),
            "collectors": assessment.get("collectors", []),
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "version": "2.0.0",
            "platform_build": "2.0.0",
            "execution_status": execution_status,
            "capability_validation": monitor.get("validation", {}),
            "permission_coverage": monitor.get("permission_coverage", {}),
            "skipped_collectors": [
                item.get("name")
                for item in monitor.get("collector_validation", [])
                if item.get("status") != "Ready"
            ],
            "skipped_services": [
                item.get("name")
                for item in monitor.get("validation", {}).get("capabilities", [])
                if item.get("status") != "Available"
            ],
            "api_failures": list(monitor.get("failures", [])),
            "warnings": list(monitor.get("warnings", [])),
            "logs": [str(AUDIT_LOG)] if AUDIT_LOG.exists() else [],
            "timeline": list(monitor.get("timeline", [])),
            "resources_discovered": self._resource_count(discovery_summary),
            "risk_summary": risk_summary or {},
            "report_files": report_files,
        }
        write_json(diagnostics_dir / "assessment_diagnostics.json", payload)
        if AUDIT_LOG.exists():
            shutil.copy2(AUDIT_LOG, diagnostics_dir / AUDIT_LOG.name)
        zip_path = diagnostics_dir / "assessment_diagnostics.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in diagnostics_dir.rglob("*"):
                if path == zip_path or path.is_dir():
                    continue
                archive.write(path, path.relative_to(diagnostics_dir))
        checksum = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        return {
            "bundle_path": str(zip_path),
            "checksum": checksum,
            "assessment_id": assessment_id,
            "platform_build": "2.0.0",
        }

    def _snapshot_outputs(self, assessment_id: str) -> str:
        snapshot = HISTORY_DIR / assessment_id
        snapshot.mkdir(parents=True, exist_ok=True)
        for name in [
            "discovery",
            "raw",
            "normalized",
            "assessment_register",
            "checklist",
            "threats",
            "attack_paths",
            "risk",
            "reports",
            "traceability",
            "crown_jewel",
            "evidence_index.json",
            "session.json",
        ]:
            source = Path("output") / name
            if source.is_dir():
                target = snapshot / name
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(source, target)
            elif source.is_file():
                shutil.copy2(source, snapshot / source.name)
        return str(snapshot)

    def archive_report(self, filename: str) -> str:
        source = Path("output/reports") / filename
        if not source.exists():
            raise FileNotFoundError(filename)
        REPORT_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = utc_now().strftime("%Y%m%d-%H%M%S")
        target = REPORT_ARCHIVE_DIR / f"{timestamp}-{filename}"
        shutil.copy2(source, target)
        self.audit.log("report_archived", {"filename": filename, "target": str(target)})
        return str(target)

    def _apply_validations(
        self, findings, register_entries, validations: Dict[str, Any]
    ):
        if not validations:
            return findings, register_entries
        confirmed_findings = []
        confirmed_register = []
        for entry in register_entries:
            validation = validations.get(entry.register_id, {})
            status = validation.get("status", entry.validation_status)
            entry.validation_status = status
            entry.analyst_notes = validation.get("notes", entry.analyst_notes)
            if status == "CONFIRMED":
                confirmed_register.append(entry)
        allowed_ids = {entry.register_id for entry in confirmed_register}
        for finding in findings:
            status = validations.get(finding.assessment_register_id, {}).get(
                "status", finding.validation_status
            )
            finding.validation_status = status
            finding.analyst_notes = validations.get(
                finding.assessment_register_id, {}
            ).get("notes", finding.analyst_notes)
            if finding.assessment_register_id in allowed_ids:
                confirmed_findings.append(finding)
        return confirmed_findings, confirmed_register

    def _resource_count(self, discovery_summary: Dict[str, Any]) -> int:
        counts = discovery_summary.get("resource_counts", {}) or {}
        return sum(counts.values())


def deep_merge(base: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base
