from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}
CONFIDENCES = ("low", "medium", "high")

JS_LANGS = frozenset({"js", "html"})
PY_LANGS = frozenset({"python"})
SHELL_LANGS = frozenset({"shell", "powershell", "batch", "docker"})
CODE_LANGS = JS_LANGS | PY_LANGS | SHELL_LANGS | frozenset(
    {"solidity", "vyper", "rust", "go", "java", "ruby", "php", "move", "cairo"}
)
SOL_LANGS = frozenset({"solidity"})


def severity_at_least(value: str, threshold: str) -> bool:
    return SEVERITY_RANK[value] >= SEVERITY_RANK[threshold]


@dataclass
class FileContext:
    path: str
    lang: str
    text: str
    lines: List[str] = field(init=False, repr=False)
    line_starts: List[int] = field(init=False, repr=False)
    cache: Dict[str, Any] = field(init=False, default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.lines = self.text.split("\n")
        starts = [0]
        position = self.text.find("\n")
        while position != -1:
            starts.append(position + 1)
            position = self.text.find("\n", position + 1)
        self.line_starts = starts

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    def linecol(self, offset: int) -> Tuple[int, int]:
        index = bisect.bisect_right(self.line_starts, offset) - 1
        return index + 1, offset - self.line_starts[index] + 1

    def line_text(self, number: int) -> str:
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1].rstrip("\r")
        return ""


@dataclass
class Hit:
    line: int
    column: int = 1
    message: Optional[str] = None
    severity: Optional[str] = None
    span: Optional[Tuple[int, int]] = None
    extra_mappings: Optional[Dict[str, Tuple[str, ...]]] = None


def merge_mappings(*sources: Optional[Dict[str, Tuple[str, ...]]]) -> Dict[str, Tuple[str, ...]]:
    merged: Dict[str, List[str]] = {}
    for source in sources:
        for key, items in (source or {}).items():
            bucket = merged.setdefault(key, [])
            bucket.extend(item for item in items if item not in bucket)
    return {key: tuple(items) for key, items in merged.items()}


CheckFn = Callable[[FileContext, "Rule"], Iterable[Hit]]


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    mappings: Dict[str, Tuple[str, ...]]
    confidence: str = "medium"
    patterns: Sequence[str] = ()
    pattern_mappings: Sequence[Dict[str, Tuple[str, ...]]] = ()
    flags: int = re.IGNORECASE
    langs: Optional[frozenset] = None
    exclude_langs: frozenset = frozenset({"lockfile"})
    path_regex: Optional[str] = None
    unless_line: Optional[str] = None
    require_line: Optional[str] = None
    unless_file: Optional[str] = None
    require_file: Optional[str] = None
    severity_by_lang: Dict[str, str] = field(default_factory=dict)
    mask: bool = False
    check: Optional[CheckFn] = None
    repo_level: bool = False

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError("%s: bad severity %s" % (self.id, self.severity))
        if self.confidence not in CONFIDENCES:
            raise ValueError("%s: bad confidence %s" % (self.id, self.confidence))
        if self.pattern_mappings and len(self.pattern_mappings) != len(self.patterns):
            raise ValueError("%s: pattern_mappings must align with patterns" % self.id)
        self.compiled = [re.compile(pattern, self.flags) for pattern in self.patterns]
        self._path = re.compile(self.path_regex, re.IGNORECASE) if self.path_regex else None
        self._unless_line = re.compile(self.unless_line, re.IGNORECASE) if self.unless_line else None
        self._require_line = re.compile(self.require_line, re.IGNORECASE) if self.require_line else None
        self._unless_file = re.compile(self.unless_file, re.IGNORECASE) if self.unless_file else None
        self._require_file = re.compile(self.require_file, re.IGNORECASE) if self.require_file else None

    def applies_to(self, ctx: FileContext) -> bool:
        if self.repo_level:
            return False
        if ctx.lang in self.exclude_langs:
            return False
        if self.langs is not None and ctx.lang not in self.langs:
            return False
        if self._path is not None and not self._path.search(ctx.path):
            return False
        return True


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    column: int
    severity: str
    snippet: str
    message: str
    extra_mappings: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    @property
    def rule_id(self) -> str:
        return self.rule.id

    def all_mappings(self) -> Dict[str, Tuple[str, ...]]:
        return merge_mappings(self.rule.mappings, self.extra_mappings)

    def fingerprint(self) -> str:
        import hashlib

        material = "|".join([self.rule.id, self.path, self.snippet.strip()])
        return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]

    def mappings(self, selected: Sequence[str]) -> Dict[str, Tuple[str, ...]]:
        merged = self.all_mappings()
        return {key: merged[key] for key in selected if merged.get(key)}

    def to_dict(self, selected: Sequence[str]) -> Dict[str, Any]:
        from .frameworks import FRAMEWORKS

        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity,
            "confidence": self.rule.confidence,
            "category": self.rule.category,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
            "description": self.rule.description,
            "remediation": self.rule.remediation,
            "fingerprint": self.fingerprint(),
            "frameworks": {
                key: [
                    {"id": item, "title": FRAMEWORKS[key].title(item), "url": FRAMEWORKS[key].url_for(item)}
                    for item in items
                ]
                for key, items in self.mappings(selected).items()
            },
        }


@dataclass
class ScanResult:
    target: str
    findings: List[Finding]
    files_scanned: int
    files_binary: int
    files_skipped: List[Tuple[str, str]]
    duration_seconds: float
    rules_run: int
