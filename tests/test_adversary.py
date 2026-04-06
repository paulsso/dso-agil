import json

from devsecops_agent.adversary import AdversaryConfig, run_adversary


def test_adversary_local_only_rejects_remote(tmp_path):
    config = AdversaryConfig(
        target="http://example.com",
        source_path=str(tmp_path),
        provider="openai",
        output_json=str(tmp_path / "out.json"),
        local_only=True,
        enable_online_intel=False,
    )
    try:
        run_adversary(config)
    except ValueError:
        assert True
        return
    assert False, "Expected ValueError for remote target in local-only mode"


def test_adversary_writes_report(monkeypatch, tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "package.json").write_text(json.dumps({"dependencies": {"react": "18.0.0"}}), encoding="utf-8")
    (source / "app.js").write_text("app.get('/api/test', (req, res) => res.send('ok'))", encoding="utf-8")

    monkeypatch.setattr("devsecops_agent.adversary.source_audit.run", lambda **_: [])
    monkeypatch.setattr("devsecops_agent.adversary.crawler.run", lambda *_ , **__: [])
    monkeypatch.setattr("devsecops_agent.adversary._probe_endpoints", lambda *_: [])

    config = AdversaryConfig(
        target="http://127.0.0.1:8080",
        source_path=str(source),
        provider="openai",
        output_json=str(tmp_path / "adversary.json"),
        enable_online_intel=False,
    )

    report = run_adversary(config)
    assert report.target == "http://127.0.0.1:8080"
    assert (tmp_path / "adversary.json").exists()
