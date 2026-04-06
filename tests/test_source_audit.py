from devsecops_agent.tooling.source_audit import run


def test_source_audit_detects_eval(tmp_path):
    app = tmp_path / "app.js"
    app.write_text("const x = eval('2+2')\n", encoding="utf-8")

    findings = run(str(tmp_path), enable_online_intel=False)
    titles = [f.title for f in findings]
    assert any("eval" in title.lower() for title in titles)


def test_source_audit_detects_framework_and_manager(tmp_path):
    pkg = tmp_path / "package.json"
    lock = tmp_path / "yarn.lock"
    lock.write_text("", encoding="utf-8")
    pkg.write_text(
        '{"dependencies":{"react":"18.0.0"},"devDependencies":{"typescript":"5.0.0"}}',
        encoding="utf-8",
    )

    findings = run(str(tmp_path), enable_online_intel=False)
    titles = [f.title for f in findings]
    assert any("Framework detected" in title for title in titles)
    assert any("dependency manifests detected" in title for title in titles)
