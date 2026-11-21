from __future__ import annotations

import json
import os
import sys
from collections import Counter, OrderedDict
from typing import Dict, List, Sequence

from . import __version__
from .frameworks import FRAMEWORKS
from .model import SEVERITIES, SEVERITY_RANK, SEVERITY_WEIGHT, Finding, ScanResult, merge_mappings

THREAT_CATEGORIES = {"malware", "supply-chain", "concealment", "credential-theft", "ai-agent"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def verdict(findings: Sequence[Finding]) -> Dict[str, str]:
    threat = [f for f in findings if f.rule.category in THREAT_CATEGORIES]
    if any(f.severity == "critical" for f in threat):
        return {
            "label": "MALICIOUS",
            "summary": "Malware or install-time execution indicators. Do not install, run, or open this repository in an IDE or AI agent with automatic execution.",
        }
    if any(f.severity == "high" for f in threat):
        return {
            "label": "SUSPICIOUS",
            "summary": "High-risk execution or concealment patterns. Inspect only in a disposable VM before trusting this code.",
        }
    if findings:
        return {"label": "REVIEW", "summary": "No malware indicators matched; security weaknesses need review."}
    return {"label": "NO FINDINGS", "summary": "No rule matched. This does not prove the code is safe."}


def risk_score(findings: Sequence[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))


def framework_coverage(findings: Sequence[Finding], selected: Sequence[str]) -> Dict[str, List[Dict]]:
    coverage: Dict[str, List[Dict]] = OrderedDict()
    for key in selected:
        framework = FRAMEWORKS[key]
        rows: Dict[str, Dict] = {}
        for finding in findings:
            for item in finding.all_mappings().get(key, ()):
                row = rows.setdefault(
                    item,
                    {"id": item, "title": framework.title(item), "url": framework.url_for(item), "count": 0, "max_severity": "info", "rules": []},
                )
                row["count"] += 1
                if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[row["max_severity"]]:
                    row["max_severity"] = finding.severity
                if finding.rule.id not in row["rules"]:
                    row["rules"].append(finding.rule.id)
        coverage[key] = sorted(rows.values(), key=lambda r: (-SEVERITY_RANK[r["max_severity"]], -r["count"], r["id"]))
    return coverage


def summarize(result: ScanResult, selected: Sequence[str]) -> Dict:
    severity_counts = Counter(f.severity for f in result.findings)
    return {
        "tool": {"name": "lurescan", "version": __version__},
        "target": result.target,
        "verdict": verdict(result.findings),
        "risk_score": risk_score(result.findings),
        "files_scanned": result.files_scanned,
        "files_binary": result.files_binary,
        "files_skipped": [{"path": p, "reason": r} for p, r in result.files_skipped],
        "rules_run": result.rules_run,
        "duration_seconds": round(result.duration_seconds, 3),
        "severity_counts": {s: severity_counts.get(s, 0) for s in reversed(SEVERITIES)},
        "category_counts": dict(Counter(f.rule.category for f in result.findings).most_common()),
        "frameworks": [{"key": k, "name": FRAMEWORKS[k].name, "url": FRAMEWORKS[k].url} for k in selected],
        "framework_coverage": framework_coverage(result.findings, selected),
    }


# ---------------------------------------------------------------- JSON


def render_json(result: ScanResult, selected: Sequence[str]) -> str:
    payload = summarize(result, selected)
    payload["findings"] = [f.to_dict(selected) for f in result.findings]
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- SARIF


def _rule_name(title: str) -> str:
    return "".join(word.capitalize() for word in "".join(c if c.isalnum() else " " for c in title).split())


def render_sarif(result: ScanResult, selected: Sequence[str]) -> str:
    used = OrderedDict()
    observed: Dict[str, Dict] = {}
    for finding in result.findings:
        used.setdefault(finding.rule.id, finding.rule)
        observed[finding.rule.id] = merge_mappings(observed.get(finding.rule.id), finding.all_mappings())
    rule_index = {rule_id: index for index, rule_id in enumerate(used)}
    sarif_rules = []
    for rule in used.values():
        tags = ["security", rule.category]
        help_lines = [rule.remediation, "", "Framework alignment:"]
        for key in selected:
            for item in observed[rule.id].get(key, ()):
                tags.append("%s:%s" % (FRAMEWORKS[key].short, item))
                help_lines.append("- %s %s %s" % (FRAMEWORKS[key].short, item, FRAMEWORKS[key].title(item)))
        sarif_rules.append(
            {
                "id": rule.id,
                "name": _rule_name(rule.title),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": "\n".join(help_lines)},
                "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": tags,
                    "precision": {"high": "high", "medium": "medium", "low": "low"}[rule.confidence],
                    "security-severity": SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    results = []
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule.id,
                "ruleIndex": rule_index[finding.rule.id],
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path, "uriBaseId": "SRCROOT"},
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
                "partialFingerprints": {"lurescan/v1": finding.fingerprint()},
                "properties": {"severity": finding.severity, "category": finding.rule.category},
            }
        )
    summary = summarize(result, selected)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "lurescan", "version": __version__, "rules": sarif_rules}},
                "originalUriBaseIds": {"SRCROOT": {"uri": _file_uri(result.target)}},
                "results": results,
                "properties": {"verdict": summary["verdict"], "riskScore": summary["risk_score"]},
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _file_uri(path: str) -> str:
    path = os.path.abspath(path).replace("\\", "/")
    if not path.startswith("/"):
        path = "/" + path
    if os.path.isdir(path.lstrip("/") if os.name == "nt" else path) and not path.endswith("/"):
        path += "/"
    return "file://" + path


# ---------------------------------------------------------------- Markdown


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult, selected: Sequence[str]) -> str:
    summary = summarize(result, selected)
    out: List[str] = []
    out.append("# lurescan report")
    out.append("")
    out.append("**Target:** `%s`  " % result.target)
    out.append("**Verdict:** **%s** — %s  " % (summary["verdict"]["label"], summary["verdict"]["summary"]))
    out.append("**Risk score:** %d / 100  " % summary["risk_score"])
    out.append(
        "**Files:** %d text scanned, %d binary, %d skipped · **Rules:** %d · **Time:** %.2fs"
        % (result.files_scanned, result.files_binary, len(result.files_skipped), result.rules_run, result.duration_seconds)
    )
    out.append("")
    out.append("## Findings by severity")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    for severity, count in summary["severity_counts"].items():
        out.append("| %s | %d |" % (severity, count))
    out.append("")
    if summary["category_counts"]:
        out.append("## Findings by category")
        out.append("")
        out.append("| Category | Count |")
        out.append("|---|---:|")
        for category, count in summary["category_counts"].items():
            out.append("| %s | %d |" % (category, count))
        out.append("")
    if selected:
        out.append("## Framework alignment")
        out.append("")
        for key, rows in summary["framework_coverage"].items():
            out.append("### %s" % FRAMEWORKS[key].name)
            out.append("")
            if not rows:
                out.append("No findings map to this framework.")
                out.append("")
                continue
            out.append("| ID | Title | Findings | Highest severity | Rules |")
            out.append("|---|---|---:|---|---|")
            for row in rows:
                out.append(
                    "| [%s](%s) | %s | %d | %s | %s |"
                    % (row["id"], row["url"], _md(row["title"]), row["count"], row["max_severity"], ", ".join(row["rules"]))
                )
            out.append("")
    out.append("## Findings")
    out.append("")
    if not result.findings:
        out.append("No findings.")
    for index, finding in enumerate(result.findings, start=1):
        out.append("### %d. [%s] %s — %s" % (index, finding.severity.upper(), finding.rule.id, finding.rule.title))
        out.append("")
        out.append("- **Location:** `%s:%d:%d`" % (finding.path, finding.line, finding.column))
        out.append("- **Category:** %s · **Confidence:** %s" % (finding.rule.category, finding.rule.confidence))
        out.append("- **Detail:** %s" % finding.message)
        if finding.snippet:
            out.append("- **Evidence:** `%s`" % finding.snippet.replace("`", "'"))
        out.append("- **Fix:** %s" % finding.rule.remediation)
        mappings = finding.mappings(selected)
        if mappings:
            out.append("- **Frameworks:**")
            for key, items in mappings.items():
                out.append(
                    "  - %s: %s"
                    % (FRAMEWORKS[key].short, ", ".join("%s %s" % (item, FRAMEWORKS[key].title(item)) for item in items))
                )
        out.append("")
    out.append("---")
    out.append("Static analysis only; the scanned code was not executed. Mappings are advisory and should be confirmed against the framework text.")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- terminal

_COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def render_text(result: ScanResult, selected: Sequence[str], color: bool = False) -> str:
    def paint(code: str, text: str) -> str:
        return "%s%s%s" % (code, text, _RESET) if color else text

    summary = summarize(result, selected)
    out: List[str] = []
    label = summary["verdict"]["label"]
    verdict_color = _COLORS["critical"] if label == "MALICIOUS" else _COLORS["high"] if label == "SUSPICIOUS" else _BOLD
    out.append(paint(_BOLD, "lurescan %s" % __version__) + "  " + result.target)
    out.append("Verdict: " + paint(verdict_color, " %s " % label) + "  " + summary["verdict"]["summary"])
    counts = "  ".join("%s %d" % (s, c) for s, c in summary["severity_counts"].items() if c)
    out.append(
        "Risk score %d/100 · %d findings (%s) · %d files scanned, %d binary, %d skipped · %.2fs"
        % (summary["risk_score"], len(result.findings), counts or "none", result.files_scanned, result.files_binary,
           len(result.files_skipped), result.duration_seconds)
    )
    out.append("")
    for finding in result.findings:
        tag = paint(_COLORS[finding.severity], "[%s]" % finding.severity.upper())
        out.append("%s %s %s" % (tag, paint(_BOLD, finding.rule.id), finding.rule.title))
        out.append("  %s:%d:%d" % (finding.path, finding.line, finding.column))
        out.append("  " + finding.message)
        if finding.snippet:
            out.append(paint(_DIM, "  > " + finding.snippet))
        mappings = finding.mappings(selected)
        if mappings:
            out.append(
                paint(_DIM, "  " + " | ".join("%s: %s" % (FRAMEWORKS[k].short, ", ".join(v)) for k, v in mappings.items()))
            )
        out.append("")
    if selected and result.findings:
        out.append(paint(_BOLD, "Framework alignment"))
        for key, rows in summary["framework_coverage"].items():
            if not rows:
                continue
            out.append("  " + FRAMEWORKS[key].name)
            for row in rows:
                out.append("    %-14s %-3d %-8s %s" % (row["id"], row["count"], row["max_severity"], row["title"]))
        out.append("")
    return "\n".join(out)


RENDERERS = {
    "json": (render_json, "json"),
    "sarif": (render_sarif, "sarif"),
    "markdown": (render_markdown, "md"),
}


def stdout_supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
