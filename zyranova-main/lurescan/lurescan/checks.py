"""Structural checks that need more than a single regular expression."""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import FileContext, Hit, Rule

# --------------------------------------------------------------------------
# helpers


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum(count / total * math.log2(count / total) for count in counts.values())


def strip_jsonc(text: str) -> str:
    out: List[str] = []
    index, length, in_string = 0, len(text), False
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end == -1 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def load_jsonc(ctx: FileContext):
    if "jsonc" in ctx.cache:
        return ctx.cache["jsonc"]
    data = None
    try:
        data = json.loads(ctx.text)
    except ValueError:
        try:
            data = json.loads(_TRAILING_COMMA.sub(r"\1", strip_jsonc(ctx.text)))
        except ValueError:
            data = None
    ctx.cache["jsonc"] = data
    return data


def key_position(ctx: FileContext, key: str, start: int = 0) -> Tuple[int, int]:
    match = re.compile(r'"%s"\s*:' % re.escape(key)).search(ctx.text, start)
    return ctx.linecol(match.start()) if match else (1, 1)


def shorten(value: str, limit: int = 160) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


# --------------------------------------------------------------------------
# editor and agent configuration

_NETWORK_OR_INSTALL = re.compile(
    r"curl|wget|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|https?://|"
    r"\bnpm\s+(?:i|install|ci)\b|\byarn(?:\s+install)?\b|\bpnpm\s+(?:i|install)\b|\bpip\s+install\b",
    re.I,
)


def _task_commands(task: dict) -> List[str]:
    commands: List[str] = []

    def collect(node) -> None:
        if not isinstance(node, dict):
            return
        command = node.get("command")
        if isinstance(command, str) and command.strip():
            args = node.get("args")
            if isinstance(args, list):
                command += " " + " ".join(str(item) for item in args)
            commands.append(command)

    collect(task)
    for platform in ("windows", "osx", "linux"):
        collect(task.get(platform))
    return commands


def check_vscode_tasks(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    positions = [match.start() for match in re.finditer(r'"runOn"\s*:\s*"folderOpen"', ctx.text)]
    if not positions:
        return
    data = load_jsonc(ctx)
    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    auto_tasks = [
        task
        for task in tasks
        if isinstance(task, dict)
        and isinstance(task.get("runOptions"), dict)
        and task["runOptions"].get("runOn") == "folderOpen"
    ]
    if auto_tasks and len(auto_tasks) == len(positions):
        for task, offset in zip(auto_tasks, positions):
            commands = _task_commands(task)
            presentation = task.get("presentation") if isinstance(task.get("presentation"), dict) else {}
            hidden = presentation.get("reveal") in ("never", "silent") or presentation.get("echo") is False
            risky = any(_NETWORK_OR_INSTALL.search(command) for command in commands)
            label = task.get("label", "unnamed")
            line, column = ctx.linecol(offset)
            yield Hit(
                line,
                column,
                message="Task '%s' runs automatically when the folder is opened%s: %s"
                % (label, " with its terminal hidden" if hidden else "", shorten(" || ".join(commands) or "(no command)", 240)),
                severity="critical" if risky else "high",
            )
        return
    commands = re.findall(r'"command"\s*:\s*"((?:[^"\\]|\\.)*)"', ctx.text)
    risky = any(_NETWORK_OR_INSTALL.search(command) for command in commands)
    for offset in positions:
        line, column = ctx.linecol(offset)
        yield Hit(
            line,
            column,
            message="A task runs automatically on folder open. Commands in this file: %s"
            % shorten(" || ".join(commands) or "(none parsed)", 240),
            severity="critical" if risky else "high",
        )


_MCP_RISKY = re.compile(
    r"curl|wget|https?://|powershell|pwsh|\bbash\s+-c\b|\bsh\s+-c\b|\bcmd(?:\.exe)?\s+/c\b|"
    r"(?:^|\s)(?:-y|--yes)(?:\s|$)|\.(?:js|cjs|mjs|py|sh|ps1|bat)\b",
    re.I,
)


def check_mcp_config(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    data = load_jsonc(ctx)
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        line, column = key_position(ctx, name)
        command = spec.get("command")
        if isinstance(command, str):
            args = spec.get("args") if isinstance(spec.get("args"), list) else []
            full = " ".join([command] + [str(arg) for arg in args])
            launcher = command.strip().lower().split("/")[-1].split("\\")[-1] in {
                "npx", "npx.cmd", "uvx", "bunx", "pnpx", "node", "python", "python3", "bash", "sh",
                "powershell", "pwsh", "cmd", "cmd.exe",
            }
            yield Hit(
                line,
                column,
                message="MCP server '%s' launches a local process when an AI agent loads this workspace: %s"
                % (name, shorten(full, 200)),
                severity="high" if (launcher or _MCP_RISKY.search(full)) else "medium",
            )
        url = spec.get("url") or spec.get("serverUrl")
        if isinstance(url, str):
            insecure = url.lower().startswith("http://") or re.search(r"//\d{1,3}(?:\.\d{1,3}){3}", url)
            yield Hit(
                line,
                column,
                message="MCP server '%s' connects an AI agent to %s" % (name, url),
                severity="high" if insecure else "medium",
            )


_AGENT_DIRECTIVES: Sequence[Tuple[str, str, str]] = (
    (
        r"(?:curl|wget|iwr|irm|invoke-webrequest)\b[^\n]*(?:\|\s*(?:sh|bash|cmd|powershell|iex)|https?://)",
        "high",
        "tells an AI agent to download remote content",
    ),
    (r"\b(?:powershell|pwsh)\b[^\n]*-e(?:nc|ncodedcommand)?\b", "high", "tells an AI agent to run encoded PowerShell"),
    (r"base64\s+(?:-d|--decode)\b[^\n]*\|", "high", "tells an AI agent to decode and run data"),
    (
        r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions|rules|prompts?)",
        "high",
        "attempts to override the agent's instructions",
    ),
    (
        r"(?:do\s+not|don't|never)\s+(?:tell|inform|alert|notify|mention\s+(?:this\s+)?to|show|warn)\s+(?:the\s+)?user",
        "high",
        "asks the agent to hide actions from the user",
    ),
    (
        r"without\s+(?:asking|confirmation|confirming|prompting|user\s+(?:approval|consent|confirmation))",
        "high",
        "asks the agent to act without user approval",
    ),
    (r"\b(?:silently|quietly|in\s+the\s+background)\b", "medium", "asks for silent or background execution"),
    (r"\bauto-?(?:approve|run|execute|accept)\b", "medium", "asks for automatic approval or execution"),
    (
        r"\b(?:npm|yarn|pnpm)\s+(?:i|install|ci|run|start)\b|\bnode\s+\S+\.(?:c|m)?js\b|\bpython\d?\s+\S+\.py\b",
        "medium",
        "tells an agent to execute project code, which also runs install hooks and loaders",
    ),
    (
        r"\.ssh\b|id_rsa|\bprivate\s+key\b|seed\s+phrase|\bmnemonic\b|\bwallet\b|\.env\b|keychain",
        "medium",
        "points the agent at credentials or wallet material",
    ),
)
_AGENT_COMPILED = [(re.compile(pattern, re.I), severity, why) for pattern, severity, why in _AGENT_DIRECTIVES]


def check_agent_instructions(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    for number, line in enumerate(ctx.lines, start=1):
        for pattern, severity, why in _AGENT_COMPILED:
            match = pattern.search(line)
            if match:
                yield Hit(number, match.start() + 1, message="Agent instruction file %s." % why, severity=severity)
                break


# --------------------------------------------------------------------------
# package manifests

LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish")
_BENIGN_LIFECYCLE = re.compile(
    r"^\s*(?:husky(?:\s+install)?|npx\s+husky(?:\s+install)?|is-ci\s*\|\|\s*husky(?:\s+install)?|"
    r"tsc(?:\s+[-\w./= ]*)?|npm\s+run\s+(?:build|compile)|yarn\s+(?:build|compile)|pnpm\s+(?:build|compile)|"
    r"patch-package|node-gyp\s+rebuild|ngcc|lerna\s+bootstrap|svelte-kit\s+sync|nuxt\s+prepare|nuxi\s+prepare|"
    r"prisma\s+generate|panda\s+codegen|ts-patch\s+install|simple-git-hooks|lefthook\s+install)\s*$",
    re.I,
)
_CRITICAL_LIFECYCLE = re.compile(
    r"curl|wget|https?://|\|\s*(?:sh|bash|cmd|powershell|pwsh)\b|\bnohup\b|start\s+/b|&\s*$|&\s*\)|"
    r"\bdisown\b|powershell|\biex\b|-enc(?:odedcommand)?\b|base64",
    re.I,
)
_HIGH_LIFECYCLE = re.compile(
    r"\bnode\s+(?!--version)\S+|\bpython\d?\s+\S+|\b(?:sh|bash)\s+\S+|\.(?:c|m)?js\b|\.(?:sh|ps1|bat|cmd|py)\b|"
    r"\bnpx\s+(?:-y|--yes)\b",
    re.I,
)


def check_npm_lifecycle(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    data = load_jsonc(ctx)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return
    scripts_at = ctx.text.find('"scripts"')
    for key in LIFECYCLE_SCRIPTS:
        value = scripts.get(key)
        if not isinstance(value, str) or not value.strip() or _BENIGN_LIFECYCLE.match(value):
            continue
        if _CRITICAL_LIFECYCLE.search(value):
            severity = "critical"
        elif _HIGH_LIFECYCLE.search(value):
            severity = "high"
        else:
            severity = "low"
        line, column = key_position(ctx, key, max(scripts_at, 0))
        yield Hit(
            line,
            column,
            message="`%s` runs automatically during npm install: %s" % (key, shorten(value, 200)),
            severity=severity,
        )


DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_GIT_DEP = re.compile(r"^(?:git\+|git://|github:|gitlab:|bitbucket:|gist:)|^[\w.-]+/[\w.-]+(?:#.+)?$", re.I)


def check_npm_remote_deps(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    data = load_jsonc(ctx)
    if not isinstance(data, dict):
        return
    for section in DEPENDENCY_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        section_at = max(ctx.text.find('"%s"' % section), 0)
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            lowered = spec.lower()
            if lowered.startswith(("http://", "https://")):
                severity = "high"
            elif _GIT_DEP.search(spec) and not lowered.startswith(("npm:", "workspace:", "file:", "link:")):
                severity = "medium"
            else:
                continue
            line, column = key_position(ctx, name, section_at)
            yield Hit(
                line,
                column,
                message="%s `%s` is fetched from `%s` instead of the registry, so its content is not pinned by the registry."
                % (section, name, shorten(spec, 120)),
                severity=severity,
            )


POPULAR_PACKAGES = frozenset(
    """
    ethers web3 viem wagmi hardhat truffle ganache solc bignumber.js bn.js bs58 tweetnacl bip39 hdkey keccak
    secp256k1 crypto-js ethereumjs-util ethereumjs-wallet @openzeppelin/contracts @solana/web3.js
    @coral-xyz/anchor @project-serum/anchor axios express lodash react react-dom dotenv chalk commander
    mongoose jsonwebtoken bcrypt bcryptjs socket.io nodemon typescript webpack eslint prettier moment dayjs
    uuid cors body-parser cookie-parser helmet request node-fetch yargs inquirer debug colors next vue vite
    jest mocha chai sequelize mysql2 redis ioredis puppeteer playwright cheerio openai langchain
    """.split()
)


def levenshtein(first: str, second: str, limit: int = 2) -> int:
    if abs(len(first) - len(second)) > limit:
        return limit + 1
    previous = list(range(len(second) + 1))
    for i, a in enumerate(first, start=1):
        current = [i]
        for j, b in enumerate(second, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a != b)))
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def check_typosquat(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    data = load_jsonc(ctx)
    if not isinstance(data, dict):
        return
    for section in DEPENDENCY_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        section_at = max(ctx.text.find('"%s"' % section), 0)
        for name in deps:
            lowered = name.lower()
            if lowered in POPULAR_PACKAGES or len(lowered) < 5:
                continue
            for popular in POPULAR_PACKAGES:
                if len(popular) >= 5 and levenshtein(lowered, popular, 1) == 1:
                    line, column = key_position(ctx, name, section_at)
                    yield Hit(
                        line,
                        column,
                        message="`%s` is one edit away from the popular package `%s`." % (name, popular),
                    )
                    break


_LOCK_URL = re.compile(r'(?:"resolved"\s*:\s*"|resolved\s+"|tarball:\s*)(https?://[^"\s,}]+)')
_TRUSTED_REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com", "registry.npmmirror.com")


def check_lockfile_sources(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    reported = 0
    for match in _LOCK_URL.finditer(ctx.text):
        url = match.group(1)
        host = re.sub(r"^https?://", "", url).split("/", 1)[0].lower()
        if host in _TRUSTED_REGISTRIES:
            continue
        line, column = ctx.linecol(match.start(1))
        yield Hit(
            line,
            column,
            message="Lockfile resolves a package from %s: %s" % (host, shorten(url, 160)),
            severity="medium" if host in ("codeload.github.com", "github.com") else "high",
        )
        reported += 1
        if reported >= 25:
            return


# --------------------------------------------------------------------------
# malware heuristics

_JS_NETWORK = re.compile(
    r"\bfetch\s*\(|\baxios\b|\bhttps?\.(?:get|request)\s*\(|require\(\s*['\"](?:https?|node-fetch|got|axios|request|needle|superagent|undici)['\"]\s*\)|"
    r"XMLHttpRequest|\bnew\s+WebSocket\s*\(|\bfrom\s+['\"](?:node-fetch|axios|got|undici)['\"]"
)
_JS_EVAL = re.compile(
    r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w.$])Function\s*\(\s*['\"\w]|\bvm\.runIn\w*\s*\(|\bnew\s+vm\.Script\s*\("
)
_PY_NETWORK = re.compile(r"\brequests\.(?:get|post|request)\b|urllib\.request|\burlopen\s*\(|\bhttpx\.|\baiohttp\b|\bsocket\.socket\s*\(")
_PY_EVAL = re.compile(r"(?<![\w.])(?:exec|eval)\s*\(|\bmarshal\.loads\s*\(")


def check_eval_of_network(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    if ctx.lang == "python":
        network, evaluator = _PY_NETWORK, _PY_EVAL
    else:
        network, evaluator = _JS_NETWORK, _JS_EVAL
    if not network.search(ctx.text):
        return
    for match in evaluator.finditer(ctx.text):
        line, column = ctx.linecol(match.start())
        yield Hit(
            line,
            column,
            message="This file makes network requests and also evaluates code at runtime; a downloaded payload can be executed.",
        )


_IP_URL = re.compile(r"\b(?:https?|wss?|tcp|ftp)://((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?", re.I)
_IP_PORT = re.compile(r"['\"`]((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})['\"`]")


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
        or address.is_multicast
    )


def check_hardcoded_ip(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    seen = set()
    for pattern in (_IP_URL, _IP_PORT):
        for match in pattern.finditer(ctx.text):
            ip = match.group(1)
            if not _public_ip(ip):
                continue
            line, column = ctx.linecol(match.start())
            if line in seen:
                continue
            seen.add(line)
            cleartext = match.group(0).lower().startswith(("http://", "ws://", "tcp://", "ftp://"))
            yield Hit(
                line,
                column,
                message="Hard-coded public IP endpoint %s%s." % (
                    shorten(match.group(0), 80),
                    " over a cleartext protocol" if cleartext else "",
                ),
                severity="high" if cleartext else "medium",
            )


_WALLET_EXTENSIONS = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
    "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
}
_CREDENTIAL_PATHS: Sequence[Tuple[str, str, float]] = (
    (r"Local Extension Settings", "browser extension storage", 1.0),
    (r"Login Data", "browser saved passwords", 1.0),
    (r"\bos_crypt\b", "browser master key", 1.0),
    (r"\.config[/\\]+solana|solana[/\\]+id\.json", "Solana keypair", 1.5),
    (r"exodus\.wallet", "Exodus wallet", 1.5),
    (r"Electrum[/\\]+wallets", "Electrum wallets", 1.5),
    (r"Atomic[/\\]+Local Storage", "Atomic wallet", 1.5),
    (r"login\.keychain|keychain-db", "macOS keychain", 1.0),
    (r"\bwallet\.dat\b", "Bitcoin Core wallet", 1.5),
    (r"\bkeystore[/\\]+UTC--", "Ethereum keystore", 1.5),
    (r"BraveSoftware|Brave-Browser", "Brave profile", 0.5),
    (r"Google[/\\]+Chrome[/\\]+User Data|Application Support[/\\]+Google[/\\]+Chrome", "Chrome profile", 0.5),
    (r"Mozilla[/\\]+Firefox[/\\]+Profiles", "Firefox profile", 0.5),
    (r"Local State", "browser Local State", 0.5),
    (r"\bWeb Data\b", "browser autofill", 0.5),
)
_CREDENTIAL_COMPILED = [(re.compile(p, re.I), label, weight) for p, label, weight in _CREDENTIAL_PATHS]


def check_wallet_targets(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    score, labels, first = 0.0, [], None
    for extension_id, wallet in _WALLET_EXTENSIONS.items():
        position = ctx.text.find(extension_id)
        if position != -1:
            score += 2
            labels.append("%s extension ID" % wallet)
            first = position if first is None else min(first, position)
    for pattern, label, weight in _CREDENTIAL_COMPILED:
        match = pattern.search(ctx.text)
        if match:
            score += weight
            labels.append(label)
            first = match.start() if first is None else min(first, match.start())
    if score < 2 or first is None:
        return
    severity = "critical" if score >= 3 else "high"
    if ctx.lang in ("markdown", "text"):
        severity = "medium"
    line, column = ctx.linecol(first)
    yield Hit(
        line,
        column,
        message="References credential or wallet stores used by infostealers: %s." % ", ".join(labels[:8]),
        severity=severity,
    )


# --------------------------------------------------------------------------
# concealment

_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x180E, 0xFEFF}


def check_invisible_unicode(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    reported = 0
    for number, line in enumerate(ctx.lines, start=1):
        tags, bidi, zero = [], None, None
        for index, char in enumerate(line):
            code = ord(char)
            if 0xE0000 <= code <= 0xE007F:
                tags.append((index, code))
            elif code in _BIDI and bidi is None:
                bidi = index
            elif code in _ZERO_WIDTH and zero is None and not (number == 1 and index == 0 and code == 0xFEFF):
                zero = index
        if tags:
            hidden = "".join(chr(code - 0xE0000) for _, code in tags if 0x20 <= code - 0xE0000 < 0x7F)
            yield Hit(
                number,
                tags[0][0] + 1,
                message="Invisible Unicode tag characters encode hidden text: %r" % shorten(hidden, 120),
                severity="critical" if re.search(r"run|exec|curl|ignore|instruction|install", hidden, re.I) else "high",
            )
        elif bidi is not None:
            yield Hit(
                number,
                bidi + 1,
                message="Bidirectional control character can make code display differently from how it runs (Trojan Source).",
                severity="medium" if ctx.lang in ("markdown", "text") else "high",
            )
        elif zero is not None:
            yield Hit(
                number,
                zero + 1,
                message="Zero-width character hidden in the line.",
                severity="low" if ctx.lang in ("markdown", "text") else "medium",
            )
        else:
            continue
        reported += 1
        if reported >= 25:
            return


_OBF_ID = re.compile(r"\b_0x[0-9a-fA-F]{4,6}\b")
_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")


def check_obfuscation_density(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    identifiers = _OBF_ID.findall(ctx.text)
    if len(identifiers) >= 25:
        match = _OBF_ID.search(ctx.text)
        line, column = ctx.linecol(match.start())
        yield Hit(line, column, message="%d javascript-obfuscator style identifiers (_0x…)." % len(identifiers), severity="high")
        return
    escapes = _HEX_ESCAPE.findall(ctx.text)
    if len(escapes) >= 300:
        match = _HEX_ESCAPE.search(ctx.text)
        line, column = ctx.linecol(match.start())
        yield Hit(line, column, message="%d hex-escaped characters in string literals." % len(escapes), severity="medium")


_HEX_BLOB = re.compile(r"(['\"`])([A-Fa-f0-9]{400,})\1")
_B64_BLOB = re.compile(r"(['\"`])([A-Za-z0-9+/_-]{600,}={0,2})\1")
_BYTE_ARRAY = re.compile(r"\[\s*(?:(?:0x)?[0-9a-fA-F]{1,3}\s*,\s*){300,}(?:0x)?[0-9a-fA-F]{1,3}\s*\]")


def check_encoded_blob(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    if ctx.name.endswith((".map", ".svg")):
        return
    reported = 0
    for pattern, kind, minimum in ((_HEX_BLOB, "hex", 3.0), (_B64_BLOB, "base64", 4.5), (_BYTE_ARRAY, "byte array", 0.0)):
        for match in pattern.finditer(ctx.text):
            body = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
            prefix = ctx.text[max(0, match.start() - 40): match.start()].lower()
            if "base64," in prefix or "integrity" in prefix or "sha512-" in body[:10]:
                continue
            if minimum and entropy(body[:4096]) < minimum:
                continue
            line, column = ctx.linecol(match.start())
            decoded = len(body) // 2 if kind == "hex" else (len(body) * 3 // 4 if kind == "base64" else body.count(",") + 1)
            yield Hit(
                line,
                column,
                message="Embedded %s blob of about %d decoded bytes." % (kind, decoded),
                severity="medium" if ctx.lang in ("json", "markdown", "text") else "high",
            )
            reported += 1
            if reported >= 10:
                return


# --------------------------------------------------------------------------
# Solidity


def blank_comments(text: str) -> str:
    chars = list(text)
    index, length, quote = 0, len(text), None
    while index < length:
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            for k in range(index, end):
                chars[k] = " "
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end == -1 else end + 2
            for k in range(index, end):
                if chars[k] != "\n":
                    chars[k] = " "
            index = end
            continue
        index += 1
    return "".join(chars)


def _match_close(text: str, open_index: int, opener: str = "{", closer: str = "}") -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


_SOL_FUNCTION = re.compile(r"\b(?:function\s+(\w+)|(receive|fallback))\s*\(([^)]*)\)([^{};]*)\{")


def sol_functions(ctx: FileContext) -> List[Dict]:
    if "sol_functions" in ctx.cache:
        return ctx.cache["sol_functions"]
    code = ctx.cache.setdefault("sol_code", blank_comments(ctx.text))
    functions = []
    for match in _SOL_FUNCTION.finditer(code):
        open_index = match.end() - 1
        close_index = _match_close(code, open_index)
        functions.append(
            {
                "name": match.group(1) or match.group(2),
                "params": match.group(3),
                "modifiers": match.group(4),
                "start": match.start(),
                "body_start": open_index + 1,
                "body": code[open_index + 1: close_index],
            }
        )
    ctx.cache["sol_functions"] = functions
    return functions


_SOL_LOW_LEVEL_CALL = re.compile(r"\.call\s*\{[^}]*\}\s*\(|\.call\.value\s*\(|\.call\s*\(|\.send\s*\(")
_SOL_STATE_WRITE = re.compile(
    r"\b[A-Za-z_]\w*\s*(?:\[[^\]\n]*\]\s*)+(?:\.\w+\s*)?(?:\+=|-=|=)(?!=)|"
    r"\b_?(?:balances?|totalSupply|shares|deposits|credits?|claimed|locked|rewards?)\w*\s*(?:\+=|-=|=)(?!=)",
    re.I,
)


def check_sol_reentrancy(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    for function in sol_functions(ctx):
        if re.search(r"\bnonReentrant\b|\bview\b|\bpure\b", function["modifiers"]):
            continue
        call = _SOL_LOW_LEVEL_CALL.search(function["body"])
        if not call:
            continue
        write = _SOL_STATE_WRITE.search(function["body"], call.end())
        if not write:
            continue
        line, column = ctx.linecol(function["body_start"] + call.start())
        yield Hit(
            line,
            column,
            message="In %s(), an external call is made before the state update `%s`."
            % (function["name"], shorten(write.group(0), 60)),
        )


_FLASH_CALLBACKS = {
    "executeOperation", "uniswapV2Call", "uniswapV3FlashCallback", "uniswapV3SwapCallback", "pancakeCall",
    "receiveFlashLoan", "onFlashLoan", "callFunction", "DVMFlashLoanCall", "DPPFlashLoanCall",
    "algebraFlashCallback", "pancakeV3FlashCallback",
}


def check_sol_flash_callback(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    for function in sol_functions(ctx):
        if function["name"] in _FLASH_CALLBACKS and "msg.sender" not in function["body"]:
            line, column = ctx.linecol(function["start"])
            yield Hit(line, column, message="%s() never checks msg.sender, so anyone can call it with crafted data." % function["name"])


_FROM_PARAM = re.compile(r"\baddress\s+(?:payable\s+)?(_?from|_?sender|_?owner|holder|victim|_?user|_?account)\b")


def check_sol_arbitrary_from(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    for function in sol_functions(ctx):
        param = _FROM_PARAM.search(function["params"])
        if not param or re.search(r"\bonly\w+|\bview\b|\bpure\b", function["modifiers"]):
            continue
        body = function["body"]
        name = param.group(1)
        call = re.search(r"\btransferFrom\s*\(\s*%s\b" % re.escape(name), body)
        if call and "msg.sender" not in body:
            line, column = ctx.linecol(function["body_start"] + call.start())
            yield Hit(
                line,
                column,
                message="%s() moves tokens from caller-supplied `%s` without tying it to msg.sender; any approval holder can be drained."
                % (function["name"], name),
            )


_SOL_LOOP = re.compile(r"\b(for|while)\s*\(")
_SOL_EXTERNAL = re.compile(r"\.call\s*[{(]|\.transfer\s*\(|\.send\s*\(|\.safeTransfer\w*\s*\(")


def check_sol_loop_calls(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    code = ctx.cache.setdefault("sol_code", blank_comments(ctx.text))
    for match in _SOL_LOOP.finditer(code):
        paren_close = _match_close(code, match.end() - 1, "(", ")")
        header = code[match.end(): paren_close]
        rest = code[paren_close + 1:]
        stripped = rest.lstrip()
        if stripped.startswith("{"):
            open_index = paren_close + 1 + (len(rest) - len(stripped))
            body = code[open_index: _match_close(code, open_index) + 1]
        else:
            end = code.find(";", paren_close)
            body = code[paren_close: end if end != -1 else len(code)]
        if _SOL_EXTERNAL.search(body):
            line, column = ctx.linecol(match.start())
            unbounded = ".length" in header
            yield Hit(
                line,
                column,
                message="External call inside a loop%s; one failing or gas-heavy recipient can block the whole operation."
                % (" over an array length" if unbounded else ""),
            )


_RUG_NAME = re.compile(r"withdraw|drain|sweep|rescue|emergency|migrate|skim|collect|claimfee|exit", re.I)
_FULL_BALANCE = re.compile(r"address\s*\(\s*this\s*\)\s*\.balance|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
_PRIVILEGED = re.compile(r"\bonly\w+|require\s*\(\s*(?:msg\.sender|_msgSender\(\))\s*==\s*(?:owner|_owner|admin|dev)\w*", re.I)


def check_sol_privileged_drain(ctx: FileContext, rule: Rule) -> Iterable[Hit]:
    for function in sol_functions(ctx):
        if not _RUG_NAME.search(function["name"] or ""):
            continue
        privileged = _PRIVILEGED.search(function["modifiers"]) or _PRIVILEGED.search(function["body"])
        if privileged and _FULL_BALANCE.search(function["body"]):
            line, column = ctx.linecol(function["start"])
            yield Hit(
                line,
                column,
                message="%s() lets a privileged account move the contract's entire balance." % function["name"],
            )


# --------------------------------------------------------------------------
# binary content


ASSET_SIGNATURES = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".ico": (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00", b"\x89PNG"),
    ".bmp": (b"BM",),
    ".webp": (b"RIFF",),
    ".woff": (b"wOFF",),
    ".woff2": (b"wOF2",),
    ".ttf": (b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf"),
    ".otf": (b"OTTO", b"\x00\x01\x00\x00"),
    ".pdf": (b"%PDF",),
    ".mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
}
_CODE_HINT = re.compile(
    rb"require\s*\(|\bimport\s+[\w{*]|function\s*\w*\s*\(|=>|eval\s*\(|child_process|module\.exports|^#!|"
    rb"powershell|curl\s|\bexec\s*\(|base64|\bconst\s+\w+\s*=|\bvar\s+\w+\s*=|\bdef\s+\w+\s*\(",
    re.I | re.M,
)
EXECUTABLE_EXTENSIONS = {
    ".exe": "high", ".dll": "high", ".scr": "high", ".msi": "high", ".com": "high", ".cpl": "high",
    ".node": "high", ".so": "high", ".dylib": "high", ".pyd": "high", ".jar": "medium", ".class": "medium",
    ".pyc": "medium", ".apk": "medium",
}
_PE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".node", ".pyd", ".msi", ".com", ".efi", ".ocx", ".cpl", ".mui"}
_ELF_EXTENSIONS = {".so", ".node", ".o", ".elf", ""}
_MACHO_EXTENSIONS = {".dylib", ".node", ".so", ".bundle", ""}


def _printable_ratio(sample: bytes) -> float:
    if not sample:
        return 0.0
    printable = sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128)
    return printable / len(sample)


def inspect_asset(extension: str, data: bytes) -> Optional[Tuple[str, str]]:
    signatures = ASSET_SIGNATURES.get(extension)
    if not signatures or not data or data.startswith(signatures):
        return None
    sample = data[:4096]
    textual = b"\x00" not in sample and _printable_ratio(sample) >= 0.9
    if textual and _CODE_HINT.search(sample):
        return "critical", "File named %s contains script code instead of %s data." % (extension, extension.lstrip(".").upper())
    if textual:
        return "high", "File named %s is plain text, not %s data." % (extension, extension.lstrip(".").upper())
    for other, other_signatures in ASSET_SIGNATURES.items():
        if other != extension and data.startswith(other_signatures):
            return "info", "File named %s is actually %s data (misnamed asset)." % (extension, other.lstrip(".").upper())
    return "medium", "File signature does not match the %s extension." % extension


def inspect_executable(extension: str, data: bytes) -> Optional[Tuple[str, str, str]]:
    """Return (rule_id, severity, message) for executable content."""
    head = data[:4]
    kind = None
    if head[:2] == b"MZ":
        kind, allowed = "Windows PE executable", _PE_EXTENSIONS
    elif head == b"\x7fELF":
        kind, allowed = "Linux ELF executable", _ELF_EXTENSIONS
    elif head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        kind, allowed = "macOS Mach-O executable", _MACHO_EXTENSIONS
    if kind and extension not in allowed:
        return "LS-SUP-011", "critical", "%s disguised with a %s extension." % (kind, extension or "missing")
    if kind:
        return "LS-SUP-010", "high", "Bundled %s in the source tree." % kind
    severity = EXECUTABLE_EXTENSIONS.get(extension)
    if severity:
        return "LS-SUP-010", severity, "Bundled compiled artifact (%s) in the source tree." % extension
    return None


# --------------------------------------------------------------------------
# repository-level lure analysis

_WEB3_CLAIMS = (
    "solidity", "smart contract", "hardhat", "foundry", "truffle", "nft", "defi", "web3", "polygon",
    "ethereum", "evm", "blockchain", "staking", "solana", "dex", "token",
)
_INSTALL_STEP = re.compile(r"\b(?:npm\s+(?:i|install|ci|start|run\s+dev)|yarn(?:\s+install|\s+dev|\s+start)?|pnpm\s+(?:i|install|dev))\b", re.I)
_HIRING = re.compile(
    r"technical\s+(?:assessment|test|task|challenge)|take-?home|coding\s+(?:challenge|test|assignment)|"
    r"interview\s+(?:task|assignment|project)|candidate|recruit",
    re.I,
)


def repo_lure_hits(
    readmes: Sequence[Tuple[str, str]], has_contracts: bool, install_hook_present: bool
) -> List[Tuple[str, str, int, int, str, Optional[str]]]:
    hits: List[Tuple[str, str, int, int, str, Optional[str]]] = []
    for path, text in readmes:
        ctx = FileContext(path, "markdown", text)
        lowered = text.lower()
        claims = [word for word in _WEB3_CLAIMS if re.search(r"\b%s\b" % re.escape(word), lowered)]
        if len(claims) >= 3 and not has_contracts:
            first = min(lowered.find(word) for word in claims)
            line, column = ctx.linecol(first)
            hits.append(
                (
                    "LS-LURE-001", path, line, column,
                    "README advertises %s, but the repository contains no smart-contract sources or toolchain config."
                    % ", ".join(claims[:6]),
                    None,
                )
            )
        install = _INSTALL_STEP.search(text)
        if install and install_hook_present:
            line, column = ctx.linecol(install.start())
            hits.append(
                (
                    "LS-LURE-002", path, line, column,
                    "README tells the reader to run `%s`, which triggers the install-time or folder-open execution found in this repository."
                    % install.group(0),
                    None,
                )
            )
        hiring = _HIRING.search(text)
        if hiring:
            line, column = ctx.linecol(hiring.start())
            hits.append(("LS-LURE-003", path, line, column, "README frames the repository as a hiring task (`%s`)." % hiring.group(0), None))
    return hits
