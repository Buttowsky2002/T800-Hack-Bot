"""
Tests for tools/prowler.py

Run with:  pytest tests/test_prowler.py -v
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from pentest_bot_t800.tools.prowler import (
    _check_credentials,
    _parse_prowler_ocsf,
    _parse_prowler_stdout,
    run_prowler,
)


# ── Binary / provider validation ──────────────────────────────────────────────

def test_prowler_not_installed():
    """run_prowler returns a failed ToolResult when the binary is absent."""
    r = run_prowler(provider="aws", prowler_path="/nonexistent/prowler")
    assert not r.success
    assert "prowler not found" in r.error


def test_unknown_provider():
    """run_prowler rejects unknown cloud providers immediately."""
    r = run_prowler(provider="badcloud", prowler_path="/nonexistent/prowler")
    assert not r.success
    assert "Unknown provider" in r.error


# ── Credential validation ──────────────────────────────────────────────────────

def test_check_credentials_aws_missing(monkeypatch, tmp_path):
    """Returns an error string when no AWS credentials exist."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    # Patch Path.exists so neither ~/.aws/credentials nor ~/.aws/config exist
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if ".aws" in str(self):
            return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    result = _check_credentials("aws")
    assert result is not None
    assert "AWS credentials not found" in result


def test_check_credentials_aws_env_vars(monkeypatch):
    """Returns None when both env vars are set."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert _check_credentials("aws") is None


def test_check_credentials_azure_missing(monkeypatch):
    """Returns an error string when Azure env vars are absent."""
    for var in ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"):
        monkeypatch.delenv(var, raising=False)
    result = _check_credentials("azure")
    assert result is not None
    assert "Azure credentials not found" in result


def test_check_credentials_azure_present(monkeypatch):
    """Returns None when all three Azure env vars are set."""
    monkeypatch.setenv("AZURE_CLIENT_ID",     "client-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("AZURE_TENANT_ID",     "tenant-id")
    assert _check_credentials("azure") is None


def test_check_credentials_gcp_missing(monkeypatch, tmp_path):
    """Returns an error string when no GCP credentials exist."""
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if "gcloud" in str(self):
            return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    result = _check_credentials("gcp")
    assert result is not None
    assert "GCP credentials not found" in result


def test_check_credentials_gcp_env(monkeypatch):
    """Returns None when GOOGLE_APPLICATION_CREDENTIALS is set."""
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/sa/key.json")
    assert _check_credentials("gcp") is None


def test_check_credentials_unknown_provider():
    """Returns None for an unrecognised provider (prowler handles it)."""
    assert _check_credentials("alibaba") is None


# ── OCSF JSON parser ──────────────────────────────────────────────────────────

def _write_json(items: list[dict]) -> Path:
    """Helper: write items to a temp JSON file and return its Path."""
    tf = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(items, tf)
    tf.close()
    return Path(tf.name)


def test_parse_prowler_ocsf():
    """Parses a standard OCSF finding and maps severity + OWASP correctly."""
    item = {
        "status": "FAILED",
        "severity": "high",
        "severity_id": 4,
        "finding_info": {"title": "S3 bucket public access enabled"},
        "message": "Bucket my-bucket has public access",
        "resources": [{"uid": "arn:aws:s3:::my-bucket", "region": "us-east-1"}],
        "product": {"name": "s3"},
        "remediation": {"desc": "Block public access on S3 bucket"},
    }
    path = _write_json([item])
    try:
        findings = _parse_prowler_ocsf(path, "aws")
    finally:
        path.unlink(missing_ok=True)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "High"
    assert "S3" in f.title
    assert "Prowler [AWS]" in f.title
    assert f.owasp == "A05-Security Misconfiguration"
    assert f.host == "arn:aws:s3:::my-bucket"
    assert "Block public access" in f.evidence


def test_ocsf_skips_passing_checks():
    """PASS status records are silently skipped; only FAIL records produce findings."""
    items = [
        {
            "status": "PASS",
            "severity": "high",
            "finding_info": {"title": "Should be skipped"},
            "product": {"name": "iam"},
        },
        {
            "status": "FAILED",
            "severity": "critical",
            "finding_info": {"title": "Root account has active keys"},
            "message": "Root account keys found",
            "resources": [{"uid": "root", "region": "us-east-1"}],
            "product": {"name": "iam"},
            "remediation": {"desc": "Delete root access keys"},
        },
    ]
    path = _write_json(items)
    try:
        findings = _parse_prowler_ocsf(path, "aws")
    finally:
        path.unlink(missing_ok=True)

    assert len(findings) == 1
    assert findings[0].severity == "Critical"
    assert "Root account" in findings[0].title


def test_ocsf_severity_id_fallback():
    """Uses severity_id when the severity string field is absent."""
    item = {
        "status": "FAILED",
        "severity_id": 3,          # Medium
        "finding_info": {"title": "Some medium finding"},
        "resources": [{"uid": "res-1", "region": "eu-west-1"}],
        "product": {"name": "cloudtrail"},
        "remediation": {},
    }
    path = _write_json([item])
    try:
        findings = _parse_prowler_ocsf(path, "aws")
    finally:
        path.unlink(missing_ok=True)

    assert len(findings) == 1
    assert findings[0].severity == "Medium"
    assert findings[0].owasp == "A09-Security Logging Failures"


def test_ocsf_empty_file():
    """Empty output file returns an empty list without raising."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as tf:
        path = Path(tf.name)      # write nothing
    try:
        findings = _parse_prowler_ocsf(path, "aws")
    finally:
        path.unlink(missing_ok=True)

    assert findings == []


def test_ocsf_jsonlines_format():
    """Handles newline-delimited JSON (one object per line)."""
    items = [
        {
            "status": "FAILED",
            "severity": "low",
            "finding_info": {"title": "Finding A"},
            "resources": [{"uid": "res-a", "region": "us-west-2"}],
            "product": {"name": "vpc"},
            "remediation": {"desc": "Fix it"},
        },
        {
            "status": "FAILED",
            "severity": "medium",
            "finding_info": {"title": "Finding B"},
            "resources": [{"uid": "res-b", "region": "us-west-2"}],
            "product": {"name": "eks"},
            "remediation": {"desc": "Fix it too"},
        },
    ]
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tf:
        # Write as JSON-lines, not a JSON array
        for item in items:
            tf.write(json.dumps(item) + "\n")
        path = Path(tf.name)
    try:
        findings = _parse_prowler_ocsf(path, "aws")
    finally:
        path.unlink(missing_ok=True)

    assert len(findings) == 2
    severities = {f.severity for f in findings}
    assert severities == {"Low", "Medium"}


def test_ocsf_azure_provider():
    """Provider label appears in title for non-AWS providers."""
    item = {
        "status": "FAILED",
        "severity": "high",
        "finding_info": {"title": "Storage account allows public access"},
        "resources": [{"uid": "/subscriptions/sub-1/storage/myaccount", "region": "westeurope"}],
        "product": {"name": "storage"},
        "remediation": {"desc": "Disable public access"},
    }
    path = _write_json([item])
    try:
        findings = _parse_prowler_ocsf(path, "azure")
    finally:
        path.unlink(missing_ok=True)

    assert len(findings) == 1
    assert "AZURE" in findings[0].title
    assert findings[0].owasp == "A05-Security Misconfiguration"


# ── Stdout fallback parser ────────────────────────────────────────────────────

def test_parse_prowler_stdout_fallback():
    """Extracts a FAIL line and skips PASS lines."""
    raw = (
        "FAIL on iam_user_mfa_enabled: User admin has no MFA [HIGH]\n"
        "PASS on s3_bucket_encrypted: Bucket is encrypted\n"
    )
    findings = _parse_prowler_stdout(raw, "aws")
    assert len(findings) == 1
    assert "iam_user_mfa_enabled" in findings[0].title
    assert findings[0].severity == "High"


def test_parse_prowler_stdout_severity_mapping():
    """Stdout parser maps severity keywords correctly."""
    raw = "\n".join([
        "FAIL critical_check: some critical issue [CRITICAL]",
        "FAIL high_check: high severity issue [HIGH]",
        "FAIL low_check: low severity issue [LOW]",
        "FAIL medium_check: medium severity by default",   # no keyword → Medium
    ])
    findings = _parse_prowler_stdout(raw, "aws")
    assert len(findings) == 4
    sev_map = {f.title.split(": ")[1][:10]: f.severity for f in findings}
    assert findings[0].severity == "Critical"
    assert findings[1].severity == "High"
    assert findings[2].severity == "Low"
    assert findings[3].severity == "Medium"


def test_parse_prowler_stdout_cap():
    """Stdout parser stops at 100 findings to prevent memory issues."""
    raw = "\n".join(f"FAIL check_{i}: something failed" for i in range(200))
    findings = _parse_prowler_stdout(raw, "aws")
    assert len(findings) == 100


def test_parse_prowler_stdout_empty():
    """Empty input returns an empty list."""
    assert _parse_prowler_stdout("", "aws") == []


def test_parse_prowler_stdout_no_fails():
    """Input with only PASS lines returns an empty list."""
    raw = "PASS check_1\nPASS check_2\nINFO Starting scan\n"
    assert _parse_prowler_stdout(raw, "aws") == []
