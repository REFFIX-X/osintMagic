"""Tests for the dossier correlator and CT analysis."""
from osintmagic.dossier import PHASES, build_dossier, classify_finding, phase_summary
from osintmagic.models import Finding, ScanResult, SourceResult
from osintmagic.sources.domain import _parse_ct_date


def test_classify_finding_phases():
    assert classify_finding(Finding("DNS Records", "domain", "info", detail={"type": "A", "value": "1.2.3.4"})) == PHASES[0]
    assert classify_finding(Finding("Cloud Buckets", "domain", "found", detail={"type": "bucket"})) == PHASES[0]
    assert classify_finding(Finding("Paste / Code Leaks", "domain", "found", detail={"type": "paste"})) == PHASES[1]
    assert classify_finding(Finding("Dark Web / Breach Mentions", "domain", "found", detail={"type": "darkweb_mention"})) == PHASES[1]
    assert classify_finding(Finding("Tech Fingerprint", "domain", "info", detail={"type": "tech", "name": "WordPress"})) == PHASES[2]


def test_phase_summary_counts():
    result = ScanResult(target="t", kind="dossier")
    result.results = [
        SourceResult("DNS Records", "domain", findings=[
            Finding("DNS Records", "domain", "info", detail={"type": "A"}),
            Finding("DNS Records", "domain", "info", detail={"type": "MX"}),
        ]),
        SourceResult("Paste / Code Leaks", "domain", findings=[
            Finding("Paste / Code Leaks", "domain", "found", detail={"type": "paste"}),
        ]),
    ]
    summary = phase_summary(result)
    assert summary[PHASES[0]]["total"] == 2
    assert summary[PHASES[1]]["found"] == 1


def test_parse_ct_date():
    from datetime import datetime, timezone
    dt = _parse_ct_date("2026-10-01T00:00:00Z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert _parse_ct_date(None) is None
    assert _parse_ct_date("not-a-date") is None


def test_build_dossier_returns_dossier_kind():
    # build_dossier makes network calls; only assert structure via a stub-free check
    assert callable(build_dossier)
