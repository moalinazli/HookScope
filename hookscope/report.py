"""Local JSON, SARIF, text and standalone HTML reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
import shlex
from typing import Any
from urllib.parse import quote

from . import __version__
from .models import SEVERITY


def finalize(result: dict[str, Any]) -> dict[str, Any]:
    severities = Counter(a["severity"] for a in result["artifacts"])
    result["schema_version"] = "1.0"
    result["tool"] = {"name": "HookScope", "version": __version__,
                      "technique": "T1546.018"}
    result["generated_at"] = datetime.now(timezone.utc).isoformat()
    result["summary"] = {"by_severity": {name: severities[name] for name in SEVERITY},
                         "artifacts_with_errors": sum(bool(a["errors"]) for a in result["artifacts"]),
                         "known_ioc_matches": sum(
                             bool(a.get("ioc_matches")) or any(
                                 (item.get("ioc_matches") or any(
                                     parent.get("ioc_matches") for parent in item.get("parent_initializers", [])
                                 )) for item in a.get("resolved_imports", []))
                             for a in result["artifacts"])}
    result["limitations"] = [
        "Static, offline artifact analysis; no target Python code is imported or executed.",
        "Startup status and module resolution are candidates, not proof of interpreter execution.",
        "Runtime flags, sys.path alterations, ._pth files, sitecustomize precedence and system-site inheritance are not fully modeled.",
        "A SHA-256 match identifies a reported artifact; it does not establish compromise by itself.",
    ]
    return result


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=True, indent=2) + "\n"


def _safe_terminal(value: str) -> str:
    """Escape control characters embedded in untrusted filesystem names."""
    result = []
    for char in value:
        number = ord(char)
        if number < 32 or number == 127:
            result.append("\\x" + format(number, "02x"))
        elif 0xD800 <= number <= 0xDFFF or number in range(0x202A, 0x202F) or number in range(0x2066, 0x206A):
            result.append("\\u" + format(number, "04x"))
        else:
            result.append(char)
    return "".join(result)


def to_text(result: dict) -> str:
    lines = [f"HookScope {__version__}  |  MITRE T1546.018",
             f"Target: {_safe_terminal(result['target'])}",
             f"Scan: {result['scan_type']}  |  Complete: {result['complete']}",
             f"Artifacts: {len(result['artifacts'])}  |  IOC matches: {result['summary']['known_ioc_matches']}", ""]
    for a in result["artifacts"]:
        lines.append(f"[{a['severity'].upper():6}] {_safe_terminal(a['path'])}")
        lines.append(f"         {a['kind']}  {a['startup_status']}  sha256={a['sha256'] or 'unavailable'}")
        for item in a["indicators"]:
            lines.append(f"         - {item['code']}" +
                         (f" (line {item['line']})" if "line" in item else ""))
        for item in a.get("resolved_imports", []):
            lines.append(f"         -> {_safe_terminal(item['module'])}: {item['status']}")
        for error in a["errors"]:
            lines.append(f"         ! {_safe_terminal(error)}")
    if result.get("scan_type") == "snapshot" and any(
        a.get("sha256") and a.get("severity") in ("medium", "high")
        for a in result["artifacts"]):
        lines += ["", "Manual remediation (never automatic):"]
        for a in result["artifacts"]:
            if a.get("sha256") and a.get("severity") in ("medium", "high"):
                lines.append("  " + _safe_terminal("hookscope quarantine --root " + shlex.quote(result["target"])
                             + " --path " + shlex.quote(a["path"])))
        lines.append("  Or run: hookscope scan --root " + shlex.quote(result["target"]) + " --review")
    if result["issues"]:
        lines += ["", f"Scan issues: {len(result['issues'])}"]
        lines += [f"  {issue['code']}: {_safe_terminal(issue['path'])}" for issue in result["issues"]]
    return "\n".join(lines) + "\n"


def to_sarif(result: dict) -> str:
    rules: dict[str, dict] = {}
    items: list[dict] = []
    for artifact in result["artifacts"]:
        for finding in artifact["indicators"]:
            code = finding["code"]
            rules.setdefault(code, {"id": code, "shortDescription": {"text": code.replace("_", " ")},
                                    "properties": {"tags": ["security", "T1546.018"]}})
            level = "error" if finding["severity"] == "high" else (
                "warning" if finding["severity"] == "medium" else "note")
            location: dict[str, Any] = {
                "physicalLocation": {"artifactLocation": {"uri": quote(_safe_terminal(artifact["path"]), safe="/-._~")}}
            }
            if finding.get("line"):
                location["physicalLocation"]["region"] = {"startLine": finding["line"]}
            items.append({"ruleId": code, "level": level,
                          "message": {"text": finding["detail"]},
                          "locations": [location],
                          "properties": {"startupStatus": artifact["startup_status"],
                                         "artifactSha256": artifact["sha256"],
                                         "scanType": result["scan_type"]}})
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "HookScope", "version": __version__,
                                     "informationUri": "https://attack.mitre.org/techniques/T1546/018/",
                                     "rules": [rules[k] for k in sorted(rules)]}},
                  "results": items,
                  "invocations": [{"executionSuccessful": result["complete"]}]}],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2) + "\n"


def to_html(result: dict) -> str:
    """Standalone, responsive, evidence-oriented report; no active content or external assets."""
    from collections import Counter

    def e(value: Any) -> str:
        return escape(_safe_terminal(str(value)), quote=True)

    artifacts = result.get("artifacts", [])
    issues = result.get("issues", [])
    complete = bool(result.get("complete"))
    stats = result.get("stats", {})
    environments = result.get("environments", [])
    risk_counts = Counter(a.get("severity", "info") for a in artifacts)
    notes = [i for i in issues if i.get("code") == "internal_symlink_alias"]
    gaps = [i for i in issues if i.get("code") != "internal_symlink_alias"]
    high = risk_counts["high"]
    known_matches = result.get("summary", {}).get("known_ioc_matches", 0)
    target = e(result.get("target", "Unknown target"))
    scan_kind = e(result.get("scan_type", "snapshot")).upper()

    if not complete:
        state_label, state_code, state_detail = (
            "Coverage limited", "limited",
            "At least one part of the requested scope was not inspected. Zero findings must not be interpreted as a clean bill of health.")
    elif high:
        state_label, state_code, state_detail = (
            "High-priority review", "review",
            "High-priority static indicators were identified. Review the underlying artifacts before drawing conclusions.")
    elif artifacts:
        state_label, state_code, state_detail = (
            "Artifacts require triage", "observed",
            "Startup configuration artifacts were inventoried. Their presence alone does not demonstrate malicious activity.")
    else:
        state_label, state_code, state_detail = (
            "No startup artifacts found", "clear",
            "No matching startup artifacts were discovered inside the inspected scope. This is not proof of a clean endpoint.")

    def metric(value: Any, label: str, hint: str = "") -> str:
        return (f'<div class="metric"><span class="metric-value">{e(value if value is not None else "—")}</span>'
                f'<span class="metric-label">{e(label)}</span>'
                f'<span class="metric-hint">{e(hint)}</span></div>')

    def detail_block(label: str, value: Any) -> str:
        return f'<div class="kv"><span>{e(label)}</span><code>{e(value)}</code></div>'

    environment_html = ""
    if environments:
        for env in environments[:80]:
            environment_html += (
                '<div class="env-row">'
                f'<div><strong>{e(env.get("site_directory", ""))}</strong>'
                f'<p>{"Virtual environment: " + e(env["venv_prefix"]) if env.get("venv_prefix") else "Site directory; environment type not established"}</p></div>'
                f'<span class="chip muted">{e(env.get("startup_artifact_count", 0))} artifacts</span></div>')
        if len(environments) > 80:
            environment_html += f'<p class="small">Displaying 80 of {len(environments)} directories. Export JSON for the complete inventory.</p>'
    elif result.get("scan_type") == "snapshot":
        if stats.get("site_directories") is None:
            environment_html = ('<div class="empty-inline"><strong>Site-directory inventory unavailable</strong>'
                                '<p>The supplied legacy HTML does not contain this count. Run the updated scanner and export JSON to establish directory coverage.</p></div>')
        else:
            environment_html = ('<div class="empty-inline"><strong>No recognized site directories found</strong>'
                                '<p>The selected root may not contain a Python site directory. Check the scan target before treating this as a meaningful negative result.</p></div>')
    else:
        environment_html = '<div class="empty-inline"><strong>Wheel inspection</strong><p>Installed environment resolution is not applicable to an uninstalled wheel.</p></div>'

    ranked = sorted(artifacts, key=lambda x: (-SEVERITY.get(x.get("severity", "info"), 0), x.get("path", "")))
    cards = []
    for idx, a in enumerate(ranked[:150]):
        indicators = a.get("indicators", [])
        indicator_list = "".join(
            f'<li><span class="chip {e(item.get("severity", "info"))}">{e(item.get("severity", "info"))}</span>'
            f'<strong>{e(item.get("code", "indicator"))}</strong>'
            f'<p>{e(item.get("detail", ""))}'
            f'{" · line " + e(item["line"]) if item.get("line") is not None else ""}</p></li>'
            for item in indicators
        ) or '<li><p>No static indicators recorded.</p></li>'
        resolved = a.get("resolved_imports", [])
        import_list = "".join(
            '<div class="import-row">'
            f'<code>{e(item.get("module", ""))}</code>'
            f'<span class="chip muted">{e(item.get("status", "unknown"))}</span>'
            f'<div class="small">{e(", ".join(item.get("candidates", [])) or "No local candidates reported")}</div>'
            '</div>' for item in resolved[:40]
        ) or '<p class="small">No imported modules resolved for this artifact.</p>'
        fs = a.get("filesystem") or {}
        location_html = ''.join([
            detail_block("SHA-256", a.get("sha256") or "Unavailable"),
            detail_block("Python", a.get("python_version") or "Undetermined"),
            detail_block("Context", a.get("environment") or a.get("location") or "Undetermined"),
            detail_block("Permissions", fs.get("mode", "Not available")),
        ])
        errors = ''.join(f'<li>{e(error)}</li>' for error in a.get("errors", []))
        remedy = ""
        if result.get("scan_type") == "snapshot" and a.get("sha256") and not a.get("errors"):
            cmd = ("hookscope quarantine --root " + shlex.quote(result["target"])
                   + " --path " + shlex.quote(a["path"]))
            remedy = (f'<h4>Manual quarantine (analyst approval required)</h4>'
                      f'<p class="small">This is a static finding, not a malware verdict. '
                      f'Quarantining removes the selected startup file from its active path; '
                      f'the original bytes and a SHA-256 receipt are retained for restoration.</p>'
                      f'<div class="commands"><code>{e(cmd)}</code></div>')
        cards.append(
            f'<details class="finding"{" open" if idx == 0 else ""}>'
            '<summary>'
            f'<span class="chip {e(a.get("severity", "info"))}">{e(a.get("severity", "info")).upper()}</span>'
            f'<span class="finding-title"><strong>{e(a.get("path", ""))}</strong>'
            f'<small>{e(a.get("kind", ""))} · {e(a.get("startup_status", "unknown"))}</small></span>'
            '<span class="expand-mark">Details</span></summary>'
            f'<div class="finding-detail"><div class="kv-grid">{location_html}</div>'
            f'<h4>Static indicators ({len(indicators)})</h4><ul class="indicator-list">{indicator_list}</ul>'
            f'<h4>Import analysis</h4>{import_list}'
            f'{remedy}'
            f'{"<h4>Artifact read/analysis errors</h4><ul class=\"error-list\">" + errors + "</ul>" if errors else ""}'
            '</div></details>'
        )

    if cards:
        artifact_html = ''.join(cards)
        if len(artifacts) > len(cards):
            artifact_html += (f'<p class="small">Showing the first {len(cards)} of {len(artifacts)} findings, ordered by priority. '
                              'Use the JSON export for all records.</p>')
    else:
        artifact_html = (
            '<div class="empty-state">'
            '<div class="empty-symbol" aria-hidden="true">—</div>'
            '<h3>Nothing to triage in this scope</h3>'
            '<p>No <code>.pth</code>, <code>.start</code>, or customize modules were reported. '
            'This is a negative inventory result—not a malware verdict.</p>'
            '<div class="next-action"><strong>What to do next</strong>'
            '<p>Zero matches only means nothing matched in this folder. If you quarantined the test hook earlier, this is expected. '
            'For a guided scan in Termux, open the terminal and type <code>hookscope start</code>. '
            'To see previous quarantined files, type <code>hookscope quarantine-list</code>. '
            'For instructions, type <code>hookscope help</code>.</p></div>'
            '</div>')

    def issue_item(i: dict) -> str:
        return (f'<div class="issue-item"><strong>{e(i.get("code", ""))}</strong>'
                f'<code>{e(i.get("path", ""))}</code>'
                f'<p>{e(i.get("detail", "No additional detail provided."))}</p></div>')

    if not gaps and not notes:
        issues_html = '<div class="empty-inline"><strong>No scan-level exceptions recorded.</strong><p>Per-artifact errors, if any, remain visible within their findings.</p></div>'
    else:
        issues_html = (f'<div class="issue-columns">'
                       f'<div><h3>Coverage gaps <span class="small">({len(gaps)})</span></h3>'
                       f'{"".join(issue_item(i) for i in gaps) if gaps else "<p class=\"small\">None reported.</p>"}</div>'
                       f'<div><h3>Traversal notes <span class="small">({len(notes)})</span></h3>'
                       f'{"".join(issue_item(i) for i in notes) if notes else "<p class=\"small\">None reported.</p>"}</div>'
                       '</div>')

    source_note = result.get("source_note")
    note_html = (f'<section class="panel provenance"><strong>Data provenance</strong><p>{e(source_note)}</p></section>'
                 if source_note else "")
    metrics = ''.join([
        metric(len(artifacts), "Startup artifacts", "Found in inspected content"),
        metric(stats.get("site_directories"), "Site directories", "Recognized by scanner"),
        metric(stats.get("visited_files"), "Files enumerated", "Reported traversal count"),
        metric(known_matches, "Known IOC matches", "Source-attributed hash matches"),
    ])
    diagnostics = f'{len(gaps)} coverage gaps · {len(notes)} traversal notes'
    meta = f'{scan_kind} · MITRE ATT&CK T1546.018 · HookScope {e(__version__)}'
    at = e(result.get("generated_at") or "Timestamp unavailable")
    if result.get("scan_type") == "snapshot" and "com.termux" in result.get("target", ""):
        commands = ('<code>find "$PREFIX/lib" -type d \\( -name site-packages -o -name dist-packages \\)</code>'
                    '<code>hookscope scan --root "$PREFIX/lib" --strict --format json --output "$HOME/hookscope.json"</code>')
    elif result.get("scan_type") == "snapshot":
        commands = ('<code>find /mnt/readonly-snapshot -type d -name site-packages</code>'
                    '<code>hookscope scan --root /mnt/readonly-snapshot --strict --format json --output findings.json</code>')
    else:
        commands = '<code>hookscope wheel package.whl --format json --output wheel-audit.json</code>'

    template = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="light"><title>HookScope · __TITLE__</title>
<style>
:root {color-scheme:light;--paper:#f4f6f8;--surface:#fff;--ink:#182331;--muted:#657388;--line:#dfe5eb;--dark:#102235;--teal:#147d79;--amber:#ad6c20;--red:#b2433b;--blue:#355b94; font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink)}.shell{max-width:1240px;margin:auto;padding:0 26px 52px}
.hero{background:var(--dark);color:#fff;padding:39px 0 32px;border-bottom:5px solid #22a39b}.hero .shell{padding-bottom:0}
.brand{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:28px;flex-wrap:wrap}.mark{display:flex;align-items:center;gap:11px;font-size:24px;font-weight:780;letter-spacing:-.7px}
.mark-square{display:inline-grid;place-items:center;width:38px;height:38px;border:1px solid #6cc0bd;border-radius:10px;color:#8aebe2;font-weight:800;font-size:20px}
.hero-tag,.overline{font-size:11px;font-weight:750;letter-spacing:1.65px;text-transform:uppercase}.hero-tag{color:#9db3c9}.overline{color:#617286}
.hero h1{font-size:clamp(29px,4.1vw,49px);line-height:1.15;letter-spacing:-1.6px;margin:0 0 14px;max-width:900px}
.hero p{margin:0;max-width:790px;color:#bbcad9;font-size:15px}.hero-meta{margin-top:24px;display:flex;gap:9px 18px;flex-wrap:wrap;color:#d2e1e9;font-size:12px}
.tag{padding:5px 10px;border-radius:4px;border:1px solid #466278;color:#d2e7ec;font-weight:700;text-transform:uppercase;letter-spacing:.65px;font-size:10px}
.provenance{border-left:4px solid #54789b;padding:12px 18px;font-size:12px;margin-top:18px;margin-bottom:25px}.provenance p{margin:4px 0 0;color:#5a6a7d}.panel{border:1px solid var(--line);border-radius:13px;background:var(--surface);box-shadow:0 7px 22px rgba(14,30,49,.025);padding:25px;margin-top:23px}
.status-panel{margin-top:-17px;position:relative;border-left:5px solid var(--teal);display:flex;gap:18px;align-items:flex-start}
.status-panel.limited{border-left-color:var(--amber)}.status-panel.review{border-left-color:var(--red)}
.status-bullet{width:13px;height:13px;background:var(--teal);border-radius:50%;margin-top:7px;flex:none;box-shadow:0 0 0 5px #e1f3ef}
.limited .status-bullet{background:var(--amber);box-shadow:0 0 0 5px #fbf1df}.review .status-bullet{background:var(--red);box-shadow:0 0 0 5px #f7e9e7}
.status-panel h2{font-size:22px;letter-spacing:-.4px;margin:0 0 5px}.status-panel p{color:#526177;margin:0;max-width:890px}
.section-head{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px;margin:29px 0 14px}.section-head h2{font-size:21px;letter-spacing:-.5px;margin:0}.section-head span{font-size:12px;color:var(--muted)}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px}.metric{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;min-height:133px;display:flex;flex-direction:column}
.metric-value{font-weight:780;font-size:35px;line-height:1.3;font-variant-numeric:tabular-nums;letter-spacing:-1px}.metric-label{font-weight:700;font-size:13px}.metric-hint{font-size:11px;color:var(--muted);margin-top:4px}
.pipeline{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:18px}.step{border-top:4px solid #9bb0c0;background:#f4f7fa;border-radius:6px;padding:13px 13px 12px;min-height:98px}
.step:nth-child(1){border-color:#147d79}.step:nth-child(4){border-color:#d39f56}.step b{font-size:11px;letter-spacing:1px;color:#253a4d}.step p{font-size:12px;color:#57687b;margin:5px 0 0}
.target{padding:14px 17px;background:#edf3f7;border:1px solid #dae5ec;border-radius:9px;overflow-wrap:anywhere;margin-top:18px}
.target label{display:block;font-size:10px;color:#657688;font-weight:800;letter-spacing:1px;margin-bottom:5px}.target code{font-size:12px}
.env-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid var(--line)}.env-row:last-child{border-bottom:none}.env-row strong{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-weight:600;overflow-wrap:anywhere;font-size:12px}.env-row p{color:var(--muted);font-size:12px;margin:3px 0 0}
.empty-state{border:1px dashed #b7c7d4;border-radius:12px;background:#f8fbfd;padding:29px;text-align:left}.empty-symbol{font-size:36px;color:#7f94a9;font-weight:300;line-height:1}.empty-state h3{margin:8px 0 5px;font-size:20px}.empty-state p{max-width:820px;color:#566478;margin:5px 0 0}
.next-action{background:white;border-left:3px solid #238983;padding:15px 17px;margin-top:20px;border-radius:4px}.next-action p{margin-top:6px}.empty-inline{background:#f7f9fc;border-radius:8px;padding:17px;color:#506279}.empty-inline strong{color:#25364a}.empty-inline p{margin:5px 0 0}
.finding{border:1px solid var(--line);border-radius:11px;margin-bottom:11px;background:white;overflow:hidden}.finding summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:12px;padding:17px}.finding summary::-webkit-details-marker{display:none}.finding-title{min-width:0;flex:1}.finding-title strong{display:block;overflow-wrap:anywhere;font-family:ui-monospace,Consolas,monospace;font-size:12px}.finding-title small{color:var(--muted);font-size:12px}.expand-mark{font-size:11px;color:var(--teal);font-weight:700}.finding-detail{border-top:1px solid var(--line);padding:20px}.finding h4{font-size:12px;letter-spacing:.6px;text-transform:uppercase;color:#506175;margin:20px 0 9px}
.kv-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.kv{background:#f7f9fb;border:1px solid #e8edf2;padding:10px 12px;border-radius:7px;min-width:0}.kv span{display:block;color:var(--muted);font-size:11px}.kv code{font-size:11px;word-break:break-all}.chip{display:inline-flex;align-items:center;white-space:nowrap;border-radius:5px;padding:4px 7px;font-size:10px;font-weight:800;letter-spacing:.4px;text-transform:uppercase;background:#edf0f4;color:#526176}.chip.high{background:#fce9e5;color:#9b3e32}.chip.medium{background:#fff0d5;color:#925b15}.chip.low{background:#e9f1fc;color:#355b94}.chip.info{background:#e2f3ed;color:#16685c}
.indicator-list{margin:0;padding:0;list-style:none}.indicator-list li{padding:10px 0;border-bottom:1px solid #edf0f4}.indicator-list li p{margin:4px 0 0;color:#536276;font-size:12px}.indicator-list strong{margin-left:8px;font-size:12px}.import-row{border:1px solid #e5eaee;border-radius:7px;padding:9px 11px;margin:7px 0}.import-row .chip{float:right}.small{font-size:12px;color:var(--muted)}
.issue-columns{display:grid;grid-template-columns:1fr 1fr;gap:20px}.issue-columns h3{font-size:14px;margin:0 0 10px}.issue-item{padding:11px 0;border-bottom:1px solid #e9edf1}.issue-item strong{display:block;font-size:12px;color:#27384d}.issue-item code{display:block;color:#184d6d;margin-top:3px;font-size:12px;overflow-wrap:anywhere}.issue-item p{color:var(--muted);font-size:12px;margin:5px 0 0}
.quicksteps code{font-weight:700;color:#176c66}.advanced-help summary{cursor:pointer;font-weight:700;color:#284c66}.commands code{display:block;background:#142639;color:#e1eaf0;border-radius:7px;padding:12px 14px;margin:10px 0;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}footer{padding:31px 0 0;color:#68798b;font-size:12px;border-top:1px solid #d6e0e7;margin-top:30px}
@media(max-width:750px){.shell{padding:0 16px 34px}.hero{padding:25px 0 25px}.brand{margin-bottom:22px}.hero h1{font-size:31px}.panel{padding:18px;margin-top:17px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.metric{padding:15px;min-height:115px}.metric-value{font-size:29px}.pipeline{grid-template-columns:repeat(2,minmax(0,1fr))}.issue-columns,.kv-grid{grid-template-columns:1fr}.status-panel{margin-top:-12px}.finding summary{align-items:flex-start}.expand-mark{display:none}}
@media print{body{background:white}.hero{background:white;color:#142639;border-bottom:2px solid #142639}.hero p,.hero-tag,.hero-meta{color:#253a4d}.panel,.metric{box-shadow:none}.status-panel{margin-top:12px}.finding{break-inside:avoid}details:not([open])>.finding-detail{display:block!important}}
</style></head>
<body><header class="hero"><div class="shell"><div class="brand"><span class="mark"><span class="mark-square">H</span>HookScope</span><span class="hero-tag">FORENSIC AUDIT / T1546.018</span></div>
<h1>Python startup exposure report</h1><p>Evidence-first, offline analysis of Python startup artifacts. No inspected application code was executed by this report generator.</p>
<div class="hero-meta"><span class="tag">__SCAN_KIND__</span><span>__META__</span><span>Generated: __GENERATED__</span></div></div></header>
<main class="shell">
__PROVENANCE__
<section class="panel status-panel __STATE_CODE__" aria-label="Scan status"><span class="status-bullet" aria-hidden="true"></span><div><p class="overline">SCANNER ASSESSMENT</p><h2>__STATE_LABEL__</h2><p>__STATE_DETAIL__</p><p class="small">__DIAGNOSTICS__</p></div></section>
<div class="section-head"><h2>Scan at a glance</h2><span>Inventory counts, not infection scores</span></div><div class="metrics">__METRICS__</div>
<section class="panel"><p class="overline">EVIDENCE CHAIN</p><div class="pipeline"><div class="step"><b>01 / DISCOVER</b><p>Enumerate requested filesystem scope</p></div><div class="step"><b>02 / MAP</b><p>Identify recognized site directories</p></div><div class="step"><b>03 / INSPECT</b><p>Analyze matching startup configuration</p></div><div class="step"><b>04 / VERIFY</b><p>Runtime execution requires external evidence</p></div></div><div class="target"><label>SCANNED TARGET</label><code>__TARGET__</code></div></section>
<div class="section-head"><h2>Startup configurations</h2><span>__ARTIFACT_COUNT__ artifacts</span></div><section aria-label="Artifact findings">__ARTIFACTS__</section>
<div class="section-head"><h2>Python environments</h2><span>Paths recognized in this scan</span></div><section class="panel">__ENVIRONMENTS__</section>
<div class="section-head"><h2>Coverage &amp; traversal diagnostics</h2><span>Incomplete coverage is not a malware finding</span></div><section class="panel">__ISSUES__</section>
<section class="panel quicksteps" aria-label="Getting started"><p class="overline">NEW TO HOOKSCOPE?</p><h2>How to use this report</h2><p>This page is a saved report, not a button to remove files. Open Termux and use the commands below.</p><p><strong>1.</strong> Type <code>hookscope</code> for a simple numbered menu.</p><p><strong>2.</strong> Type <code>hookscope start</code> to scan your Termux Python files without changing them.</p><p><strong>3.</strong> Type <code>hookscope report</code> to open your latest report; type <code>hookscope help</code> to see all options.</p><p><strong>4.</strong> To send both reports from Termux, type <code>hookscope export</code>, confirm, then attach the files from Downloads.</p><p class="small">If an earlier scan quarantined the lab hook, a later scan may correctly show zero findings. A startup file by itself is not a malware verdict.</p></section>
<details class="panel advanced-help"><summary>Advanced: verify folders and export evidence</summary><div class="commands"><p>These commands are for manual troubleshooting and automation; most users do not need them.</p>__COMMANDS__</div></details>
<footer>HookScope __VERSION__ · Offline static inventory · Startup candidates and hash matches are not proof of persistence or compromise. Report contents can include sensitive paths. No remote fonts, analytics, scripts, or external resources.</footer>
</main></body></html>'''
    fields = {
        "TITLE": target, "SCAN_KIND": scan_kind, "META": meta, "GENERATED": at,
        "STATE_CODE": e(state_code), "STATE_LABEL": e(state_label), "STATE_DETAIL": e(state_detail),
        "DIAGNOSTICS": e(diagnostics), "METRICS": metrics, "TARGET": target,
        "ARTIFACT_COUNT": e(len(artifacts)), "ARTIFACTS": artifact_html,
        "ENVIRONMENTS": environment_html, "ISSUES": issues_html,
        "COMMANDS": commands, "VERSION": e(__version__), "PROVENANCE": note_html,
    }
    import re
    return re.sub(r"__([A-Z_]+)__", lambda match: fields.get(match.group(1), match.group(0)), template)
