# lurescan

Static scanner for repositories delivered through fake blockchain and Web3 job offers. It reads files only. Nothing in the target is installed, imported, or executed, and `.zip` deliveries are read in memory without extraction.

Findings can be aligned to:

| Key | Framework |
|---|---|
| `owasp-sc` | OWASP Smart Contract Top 10 (2025) |
| `owasp-llm` | OWASP Top 10 for LLM Applications (2025) |
| `owasp-web` | OWASP Top 10 (2021) |
| `csa-ccm` | CSA Cloud Controls Matrix v4 |
| `attack` | MITRE ATT&CK Enterprise |
| `atlas` | MITRE ATLAS (AI and LLM systems) |
| `cwe` | MITRE CWE |
| `nist-ssdf` | NIST SP 800-218 SSDF 1.1 |

Mappings are advisory. Confirm control text against the published framework before using them as audit evidence.

 Usage

Python 3.9+ and no third-party dependencies.

```bash
python -m lurescan scan path/to/repo
python -m lurescan scan delivery.zip --frameworks mitre-attack,csa-ccm,owasp-sc
python -m lurescan scan path/to/repo -f json,sarif,markdown --output-dir reports
python -m lurescan scan path/to/repo --rules LS-SC,LS-AI --min-severity medium
python -m lurescan rules -f markdown --frameworks atlas,owasp-llm
python -m lurescan frameworks attack
```

Or `pip install .` and run `lurescan ...`.

Exit codes: `0` no finding at or above `--fail-on` (default `high`), `1` findings at or above it, `2` usage error.

`lurescan:ignore` comments are ignored unless `--honor-suppressions` is passed, because the scanned repository is attacker controlled.

 What it detects

| Prefix | Area |
|---|---|
| `LS-SUP` | Folder-open editor tasks, curl-to-shell, npm and pip install hooks, URL/git dependencies, typosquats, lockfile hosts, workspace settings that disable prompts, MCP servers, bundled binaries, files whose content does not match their extension |
| `LS-CON` | Code hidden behind whitespace padding, invisible or bidirectional Unicode, globals reached through computed names, obfuscator output, encoded blobs, XOR decoders, silenced console |
| `LS-MAL` | Network data evaluated as code, eval primitives, hard-coded public IPs, wallet and browser credential targeting, paste/webhook/tunnel endpoints, detached processes, obfuscated Python exec |
| `LS-W3`, `LS-SEC` | Private keys and seed phrases, unlimited approvals, eth_sign, hard-coded recipients, RPC/cloud/AI provider keys |
| `LS-SC` | Solidity: tx.origin, reentrancy, unchecked calls, delegatecall, selfdestruct, block randomness, pre-0.8 math, spot-price oracles, flash-loan callbacks, open initializers, arbitrary transferFrom, loop DoS, owner drains, honeypot lists |
| `LS-AI` | Agent instruction files with risky directives, prompt injection text, pickle/torch model loading, trust_remote_code, LLM output executed, unsafe YAML |
| `LS-APP` | Hard-coded auth success, weak JWT handling, hard-coded secrets, secrets in logs, TLS validation off, permissive CORS |
| `LS-LURE` | README advertising absent blockchain code, setup steps that trigger hidden execution, hiring-task framing |

The verdict is `MALICIOUS` when a malware, supply-chain, concealment, credential-theft, or AI-agent finding is critical, and `SUSPICIOUS` when one is high.

 CI

```yaml
- run: python -m lurescan scan . -f sarif -o lurescan.sarif --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: lurescan.sarif
```

 Tests

```bash
python -m unittest discover -s tests
```
