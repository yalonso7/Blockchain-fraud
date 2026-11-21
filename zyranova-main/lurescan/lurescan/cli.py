from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .engine import ScanOptions, Scanner
from .frameworks import FRAMEWORKS, resolve_frameworks
from .model import SEVERITIES, SEVERITY_RANK
from .reporters import RENDERERS, enable_windows_ansi, render_text, stdout_supports_color
from .rules import RULES, catalog_mappings, select_rules

FORMATS = ("text", "json", "sarif", "markdown")
EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _csv(value: Optional[str]) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lurescan",
        description="Static scanner for repositories delivered through fake blockchain and Web3 job offers. "
        "It reads files only; nothing in the target is installed or executed.",
    )
    parser.add_argument("--version", action="version", version="lurescan %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a directory, a single file, or a .zip archive (read in memory)")
    scan.add_argument("target", help="path to a repository directory, file, or zip archive")
    scan.add_argument("-f", "--format", default="text", help="output format(s), comma separated: %s" % ", ".join(FORMATS))
    scan.add_argument("-o", "--output", help="write the report to this file (single format only)")
    scan.add_argument("--output-dir", help="write one report per format into this directory")
    scan.add_argument(
        "--frameworks",
        default="all",
        help="frameworks to align findings to, comma separated, 'all' or 'none': %s" % ", ".join(FRAMEWORKS),
    )
    scan.add_argument("--min-severity", default="low", choices=SEVERITIES, help="hide findings below this severity (default: low)")
    scan.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITIES + ("none",),
        help="exit with code 1 when a finding at or above this severity exists (default: high)",
    )
    scan.add_argument("--rules", help="only run rules with these ids or prefixes, for example LS-SC,LS-AI-003")
    scan.add_argument("--disable", help="skip rules with these ids or prefixes")
    scan.add_argument("--exclude", action="append", default=[], help="glob of paths to skip (repeatable)")
    scan.add_argument("--include-deps", action="store_true", help="also scan node_modules")
    scan.add_argument("--max-file-size", type=float, default=5.0, help="skip files larger than this many MB (default: 5)")
    scan.add_argument(
        "--honor-suppressions",
        action="store_true",
        help="respect 'lurescan:ignore' comments. Off by default because an attacker controls the scanned repository.",
    )
    scan.add_argument("--no-color", action="store_true", help="disable colored terminal output")

    rules = sub.add_parser("rules", help="list rules and their framework alignment")
    rules.add_argument("--frameworks", default="all")
    rules.add_argument("-f", "--format", default="text", choices=("text", "json", "markdown"))

    frameworks = sub.add_parser("frameworks", help="list supported frameworks and the items rules map to")
    frameworks.add_argument("name", nargs="?", help="framework key to list items for")
    return parser


def _write(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _print(text: str) -> None:
    try:
        sys.stdout.write(text + ("" if text.endswith("\n") else "\n"))
    except UnicodeEncodeError:
        sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))


def cmd_scan(args: argparse.Namespace) -> int:
    if not os.path.exists(args.target):
        sys.stderr.write("lurescan: target not found: %s\n" % args.target)
        return EXIT_ERROR
    formats = [item.lower() for item in _csv(args.format)] or ["text"]
    unknown = [item for item in formats if item not in FORMATS]
    if unknown:
        sys.stderr.write("lurescan: unknown format(s): %s\n" % ", ".join(unknown))
        return EXIT_ERROR
    if args.output and len(formats) > 1:
        sys.stderr.write("lurescan: --output takes one format; use --output-dir for several\n")
        return EXIT_ERROR
    try:
        selected = resolve_frameworks(args.frameworks)
    except ValueError as error:
        sys.stderr.write("lurescan: %s\n" % error)
        return EXIT_ERROR
    rules = select_rules(_csv(args.rules), _csv(args.disable))
    if not rules:
        sys.stderr.write("lurescan: no rules selected\n")
        return EXIT_ERROR

    options = ScanOptions(
        include_deps=args.include_deps,
        excludes=args.exclude,
        max_file_size=int(args.max_file_size * 1024 * 1024),
        min_severity=args.min_severity,
        honor_suppressions=args.honor_suppressions,
        rules=rules,
    )
    result = Scanner(options).scan(args.target)

    for fmt in formats:
        if fmt == "text":
            color = not args.no_color and not args.output and not args.output_dir and stdout_supports_color()
            if color:
                enable_windows_ansi()
            content = render_text(result, selected, color=color)
            extension = "txt"
        else:
            renderer, extension = RENDERERS[fmt]
            content = renderer(result, selected)
        if args.output_dir:
            path = os.path.join(args.output_dir, "lurescan.%s" % extension)
            _write(path, content)
            sys.stderr.write("lurescan: wrote %s\n" % path)
        elif args.output:
            _write(args.output, content)
            sys.stderr.write("lurescan: wrote %s\n" % args.output)
        else:
            _print(content)

    if args.fail_on != "none" and any(
        SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.fail_on] for f in result.findings
    ):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    try:
        selected = resolve_frameworks(args.frameworks)
    except ValueError as error:
        sys.stderr.write("lurescan: %s\n" % error)
        return EXIT_ERROR
    if args.format == "json":
        payload = [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "confidence": rule.confidence,
                "category": rule.category,
                "description": rule.description,
                "remediation": rule.remediation,
                "frameworks": {
                    key: list(items) for key, items in catalog_mappings(rule).items() if key in selected
                },
            }
            for rule in RULES
        ]
        _print(json.dumps(payload, indent=2))
        return EXIT_OK
    if args.format == "markdown":
        header = ["ID", "Title", "Severity", "Category"] + [FRAMEWORKS[key].short for key in selected]
        lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
        for rule in RULES:
            mappings = catalog_mappings(rule)
            cells = [rule.id, rule.title, rule.severity, rule.category]
            cells += [", ".join(mappings.get(key, ())) or "—" for key in selected]
            lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
        _print("\n".join(lines))
        return EXIT_OK
    for rule in RULES:
        mappings = catalog_mappings(rule)
        _print("%-11s %-8s %-16s %s" % (rule.id, rule.severity, rule.category, rule.title))
        for key in selected:
            if mappings.get(key):
                _print("            %-10s %s" % (FRAMEWORKS[key].short, ", ".join(mappings[key])))
    return EXIT_OK


def cmd_frameworks(args: argparse.Namespace) -> int:
    if args.name:
        try:
            keys = resolve_frameworks(args.name)
        except ValueError as error:
            sys.stderr.write("lurescan: %s\n" % error)
            return EXIT_ERROR
        for key in keys:
            framework = FRAMEWORKS[key]
            _print("%s  (%s)" % (framework.name, framework.url))
            for item, title in framework.items.items():
                used = [rule.id for rule in RULES if item in catalog_mappings(rule).get(key, ())]
                _print("  %-14s %-62s %s" % (item, title, ", ".join(used) if used else "-"))
        return EXIT_OK
    for key, framework in FRAMEWORKS.items():
        _print("%-10s %-58s %d items  %s" % (key, framework.name, len(framework.items), framework.url))
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "rules":
        return cmd_rules(args)
    if args.command == "frameworks":
        return cmd_frameworks(args)
    parser.print_help()
    return EXIT_ERROR
