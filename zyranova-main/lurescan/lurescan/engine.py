"""File discovery and rule execution. Scanned content is only ever read, never executed."""

from __future__ import annotations

import fnmatch
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from . import checks
from .model import SEVERITY_RANK, FileContext, Finding, Hit, Rule, ScanResult, merge_mappings
from .rules import RULES, RULES_BY_ID

DEFAULT_EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}

NAME_LANG = {
    "package-lock.json": "lockfile",
    "npm-shrinkwrap.json": "lockfile",
    "yarn.lock": "lockfile",
    "pnpm-lock.yaml": "lockfile",
    "poetry.lock": "lockfile",
    "cargo.lock": "lockfile",
    "composer.lock": "lockfile",
    "gemfile.lock": "lockfile",
    "pipfile.lock": "lockfile",
    "dockerfile": "docker",
    "makefile": "shell",
    ".cursorrules": "markdown",
    ".windsurfrules": "markdown",
    ".clinerules": "markdown",
}
EXT_LANG = {
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mts": "js", ".cts": "js",
    ".vue": "js", ".svelte": "js", ".html": "html", ".htm": "html",
    ".sol": "solidity", ".vy": "vyper", ".move": "move", ".cairo": "cairo", ".rs": "rust", ".go": "go",
    ".py": "python", ".pyw": "python", ".ipynb": "python",
    ".json": "json", ".jsonc": "json", ".json5": "json", ".code-workspace": "json",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".command": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".bat": "batch", ".cmd": "batch",
    ".md": "markdown", ".mdx": "markdown", ".mdc": "markdown", ".rst": "markdown",
    ".txt": "text", ".ini": "text", ".cfg": "text", ".xml": "text",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".env": "env",
    ".svg": "svg", ".css": "css", ".scss": "css", ".less": "css",
    ".java": "java", ".kt": "java", ".rb": "ruby", ".php": "php",
}
CONTRACT_MARKERS = re.compile(
    r"(?:^|/)(?:hardhat\.config\.(?:js|ts|cjs|mjs)|foundry\.toml|truffle-config\.js|anchor\.toml|move\.toml|scarb\.toml)$",
    re.I,
)
_SUPPRESS = re.compile(r"lurescan:\s*ignore(?:\[([\w,\- ]+)\])?", re.I)
_WS_RUN = re.compile(r"[ \t]{16,}")
_SECRET_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{12,}")


def detect_lang(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if name in NAME_LANG:
        return NAME_LANG[name]
    if name.startswith(".env"):
        return "env"
    if name.endswith(".min.js"):
        return "js"
    extension = os.path.splitext(name)[1]
    return EXT_LANG.get(extension, "text")


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _extension(path: str) -> str:
    return os.path.splitext(path.rsplit("/", 1)[-1].lower())[1]


def mask_secret(text: str) -> str:
    words = text.split()
    if len(words) >= 12 and all(word.strip("'\"`").isalpha() for word in words[-12:]):
        return " ".join(words[:2] + ["••••"] * (len(words) - 2))
    return _SECRET_TOKEN.sub(lambda match: match.group(0)[:4] + "…" + "•" * 4, text)


def build_snippet(line: str, column: int, span: Optional[Tuple[int, int]] = None, mask: bool = False) -> str:
    if mask and span:
        start, end = span
        line = line[:start] + mask_secret(line[start:end]) + line[end:]
    parts: List[str] = []
    last, new_column = 0, column
    for match in _WS_RUN.finditer(line):
        parts.append(line[last: match.start()])
        token = " ⟨%d spaces⟩ " % len(match.group(0))
        parts.append(token)
        if match.end() <= column - 1:
            new_column -= (match.end() - match.start()) - len(token)
        last = match.end()
    parts.append(line[last:])
    collapsed = "".join(parts)
    start = max(0, new_column - 1 - 60)
    end = min(len(collapsed), new_column - 1 + 200)
    window = collapsed[start:end].strip()
    return ("…" if start > 0 else "") + window + ("…" if end < len(collapsed) else "")


@dataclass
class ScanOptions:
    include_deps: bool = False
    excludes: Sequence[str] = ()
    max_file_size: int = 5 * 1024 * 1024
    min_severity: str = "info"
    honor_suppressions: bool = False
    rules: Sequence[Rule] = field(default_factory=lambda: list(RULES))
    max_hits_per_rule_per_file: int = 25


Entry = Tuple[str, int, Callable[[], bytes]]


class Scanner:
    def __init__(self, options: Optional[ScanOptions] = None) -> None:
        self.options = options or ScanOptions()
        self.enabled = {rule.id for rule in self.options.rules}
        self.file_rules = [rule for rule in self.options.rules if not rule.repo_level]

    # ---------------------------------------------------------------- discovery

    def _excluded_dir(self, name: str) -> bool:
        if name == "node_modules" and self.options.include_deps:
            return False
        return name in DEFAULT_EXCLUDED_DIRS

    def _excluded_path(self, rel: str) -> bool:
        parts = rel.split("/")
        if any(self._excluded_dir(part) for part in parts[:-1]):
            return True
        return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(parts[-1], pattern) for pattern in self.options.excludes)

    def _entries(self, target: str) -> Iterator[Entry]:
        if os.path.isfile(target) and zipfile.is_zipfile(target):
            with zipfile.ZipFile(target) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    rel = info.filename.replace("\\", "/").lstrip("/")
                    yield rel, info.file_size, (lambda info=info: archive.read(info))
            return
        if os.path.isfile(target):
            yield os.path.basename(target), os.path.getsize(target), (lambda: _read(target))
            return
        root = os.path.abspath(target)
        for directory, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(name for name in dirnames if not self._excluded_dir(name))
            for filename in sorted(filenames):
                full = os.path.join(directory, filename)
                if os.path.islink(full):
                    continue
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                yield rel, size, (lambda full=full: _read(full))

    # ---------------------------------------------------------------- execution

    def scan(self, target: str) -> ScanResult:
        started = time.perf_counter()
        findings: List[Finding] = []
        skipped: List[Tuple[str, str]] = []
        scanned = binary = 0
        readmes: List[Tuple[str, str]] = []
        has_contracts = False

        for rel, size, load in self._entries(target):
            if self._excluded_path(rel):
                continue
            if size > self.options.max_file_size:
                skipped.append((rel, "larger than %d bytes" % self.options.max_file_size))
                continue
            try:
                data = load()
            except (OSError, zipfile.BadZipFile, RuntimeError) as error:
                skipped.append((rel, "unreadable: %s" % error))
                continue
            extension = _extension(rel)
            self._binary_checks(rel, extension, data, findings)
            if b"\x00" in data[:8192]:
                binary += 1
                continue
            scanned += 1
            text = data.decode("utf-8", errors="replace")
            lang = detect_lang(rel)
            if lang in ("solidity", "vyper", "move", "cairo") or CONTRACT_MARKERS.search(rel):
                has_contracts = True
            if rel.rsplit("/", 1)[-1].lower().startswith("readme"):
                readmes.append((rel, text))
            self._run_file_rules(FileContext(rel, lang, text), findings)

        if readmes:
            shallowest = min(rel.count("/") for rel, _ in readmes)
            readmes = [(rel, text) for rel, text in readmes if rel.count("/") == shallowest]
        self._repo_checks(readmes, has_contracts, findings)
        threshold = SEVERITY_RANK[self.options.min_severity]
        findings = [finding for finding in findings if SEVERITY_RANK[finding.severity] >= threshold]
        findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line, f.rule.id))
        return ScanResult(
            target=os.path.abspath(target),
            findings=findings,
            files_scanned=scanned,
            files_binary=binary,
            files_skipped=skipped,
            duration_seconds=time.perf_counter() - started,
            rules_run=len(self.options.rules),
        )

    def _binary_checks(self, rel: str, extension: str, data: bytes, findings: List[Finding]) -> None:
        executable = checks.inspect_executable(extension, data)
        if executable:
            rule_id, severity, message = executable
            if rule_id in self.enabled:
                findings.append(self._finding(RULES_BY_ID[rule_id], rel, 1, 1, severity, "", message))
            return
        if "LS-SUP-011" in self.enabled:
            asset = checks.inspect_asset(extension, data)
            if asset:
                severity, message = asset
                findings.append(self._finding(RULES_BY_ID["LS-SUP-011"], rel, 1, 1, severity, "", message))

    def _suppressed(self, line: str, rule_id: str) -> bool:
        if not self.options.honor_suppressions:
            return False
        match = _SUPPRESS.search(line)
        if not match:
            return False
        if not match.group(1):
            return True
        return rule_id in {item.strip().upper() for item in match.group(1).split(",")}

    def _run_file_rules(self, ctx: FileContext, findings: List[Finding]) -> None:
        for rule in self.file_rules:
            if not rule.applies_to(ctx):
                continue
            if rule._unless_file is not None and rule._unless_file.search(ctx.text):
                continue
            if rule._require_file is not None and not rule._require_file.search(ctx.text):
                continue
            try:
                hits = list(rule.check(ctx, rule)) if rule.check else list(self._regex_hits(ctx, rule))
            except RecursionError:
                continue
            by_line: Dict[int, Finding] = {}
            for hit in hits:
                existing = by_line.get(hit.line)
                if existing is not None:
                    existing.extra_mappings = merge_mappings(existing.extra_mappings, hit.extra_mappings)
                    continue
                if len(by_line) >= self.options.max_hits_per_rule_per_file:
                    continue
                line = ctx.line_text(hit.line)
                if self._suppressed(line, rule.id):
                    continue
                severity = hit.severity or rule.severity_by_lang.get(ctx.lang) or rule.severity
                snippet = build_snippet(line, hit.column, hit.span, rule.mask)
                message = hit.message or rule.description
                finding = self._finding(rule, ctx.path, hit.line, hit.column, severity, snippet, message)
                finding.extra_mappings = dict(hit.extra_mappings or {})
                by_line[hit.line] = finding
                findings.append(finding)

    @staticmethod
    def _regex_hits(ctx: FileContext, rule: Rule) -> Iterator[Hit]:
        for index, pattern in enumerate(rule.compiled):
            extra = rule.pattern_mappings[index] if rule.pattern_mappings else None
            for match in pattern.finditer(ctx.text):
                line, column = ctx.linecol(match.start())
                text = ctx.line_text(line)
                if rule._unless_line is not None and rule._unless_line.search(text):
                    continue
                if rule._require_line is not None and not rule._require_line.search(text):
                    continue
                line_start = ctx.line_starts[line - 1]
                end = min(match.end() - line_start, len(text))
                yield Hit(line, column, span=(column - 1, end), extra_mappings=extra)

    def _repo_checks(self, readmes, has_contracts: bool, findings: List[Finding]) -> None:
        hook_present = any(
            finding.rule.id in ("LS-SUP-001", "LS-SUP-003", "LS-SUP-007")
            and SEVERITY_RANK[finding.severity] >= SEVERITY_RANK["high"]
            for finding in findings
        )
        texts = dict(readmes)
        for rule_id, path, line, column, message, severity in checks.repo_lure_hits(readmes, has_contracts, hook_present):
            if rule_id not in self.enabled:
                continue
            rule = RULES_BY_ID[rule_id]
            ctx_line = texts[path].split("\n")[line - 1] if path in texts else ""
            findings.append(
                self._finding(rule, path, line, column, severity or rule.severity, build_snippet(ctx_line, column), message)
            )

    @staticmethod
    def _finding(rule: Rule, path: str, line: int, column: int, severity: str, snippet: str, message: str) -> Finding:
        return Finding(rule=rule, path=path, line=line, column=column, severity=severity, snippet=snippet, message=message)
