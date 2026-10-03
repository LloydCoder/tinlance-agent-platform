import pytest

from tinlance_agent_platform_operations import (
    AssuranceFinding,
    AssuranceReport,
    FindingState,
)


def test_assurance_report_certifies_only_resolved_findings() -> None:
    finding = AssuranceFinding("finding-1", FindingState.RESOLVED, "evidence://finding/1")
    report = AssuranceReport(
        "report-1",
        "independent-assessor",
        ("identity", "execution", "security"),
        (finding,),
        ("evidence://report/1",),
    )
    assert report.certifiable
    report.certify()


def test_assurance_report_blocks_open_findings() -> None:
    finding = AssuranceFinding("finding-open", FindingState.OPEN, "evidence://finding/open")
    report = AssuranceReport(
        "report-2",
        "independent-assessor",
        ("security",),
        (finding,),
        ("evidence://report/2",),
    )
    with pytest.raises(RuntimeError, match="unresolved"):
        report.certify()


def test_assurance_report_requires_scope_and_evidence() -> None:
    with pytest.raises(ValueError):
        AssuranceReport("report", "assessor", (), (), ("evidence://x",))
    with pytest.raises(ValueError):
        AssuranceReport("report", "assessor", ("security",), (), ())
