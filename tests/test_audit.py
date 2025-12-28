"""Test audit report structure."""

from mcp_security.audit import run_audit


def test_audit_report_structure():
    """Test that audit report has correct structure."""
    report = run_audit(mask_data=True, verbose=False)

    assert "timestamp" in report
    assert "hostname" in report
    assert "os" in report
    assert "kernel" in report
    assert "analysis" in report
    assert "recommendations" in report

    analysis = report["analysis"]
    assert "overall_status" in analysis
    assert "summary" in analysis
    assert "issues" in analysis
    assert "warnings" in analysis
    assert "good_practices" in analysis
    assert "score" in analysis

    assert isinstance(analysis["issues"], list)
    assert isinstance(analysis["warnings"], list)
    assert isinstance(analysis["good_practices"], list)
    assert isinstance(report["recommendations"], list)


def test_audit_masking():
    """Test that audit properly masks data when requested."""
    report = run_audit(mask_data=True, verbose=False)

    assert report["hostname"].startswith("srv-")
    assert "**" in report["hostname"]
