from pathlib import Path

from devsecops_agent.workflow import WorkflowConfig, run_workflow


def test_run_workflow_smoke(monkeypatch, tmp_path):
    monkeypatch.setattr("devsecops_agent.workflow.headers_scan.run", lambda _: [])
    monkeypatch.setattr("devsecops_agent.workflow.methods_scan.run", lambda _: [])
    monkeypatch.setattr("devsecops_agent.workflow.tls_scan.run", lambda _: [])
    monkeypatch.setattr("devsecops_agent.workflow.crawler.run", lambda _: [])
    monkeypatch.setattr("devsecops_agent.workflow.probes.run", lambda _: [])

    base = tmp_path / "base.md"
    base.write_text("base instructions", encoding="utf-8")

    out_json = tmp_path / "out.json"
    config = WorkflowConfig(
        target="https://example.com",
        provider="openai",
        base_instructions_path=str(base),
        custom_instructions_path=None,
        custom_mode="append",
        block_threshold=80,
        output_json=str(out_json),
    )

    report = run_workflow(config)
    assert report.score == 0
    assert report.blocked is False
    assert Path(out_json).exists()
