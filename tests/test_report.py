from devsecops_agent.report import Finding, score_findings, should_block


def test_score_findings_weights():
    findings = [
        Finding("a", "x", "critical", "e", "r"),
        Finding("b", "y", "low", "e", "r"),
    ]
    assert score_findings(findings) == 105


def test_should_block_threshold():
    assert should_block(80, 80)
    assert not should_block(79, 80)
