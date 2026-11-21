"""Catalogs of the security frameworks that findings can be aligned to.

Titles are abbreviated reference labels. Confirm control text against the
published framework before using a mapping as audit evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


@dataclass
class Framework:
    key: str
    name: str
    short: str
    url: str
    items: Dict[str, str]
    link: Optional[Callable[[str], str]] = None

    def title(self, item_id: str) -> str:
        return self.items.get(item_id, "")

    def url_for(self, item_id: str) -> str:
        return self.link(item_id) if self.link else self.url


OWASP_SC = {
    "SC01": "Access Control Vulnerabilities",
    "SC02": "Price Oracle Manipulation",
    "SC03": "Logic Errors",
    "SC04": "Lack of Input Validation",
    "SC05": "Reentrancy Attacks",
    "SC06": "Unchecked External Calls",
    "SC07": "Flash Loan Attacks",
    "SC08": "Integer Overflow and Underflow",
    "SC09": "Insecure Randomness",
    "SC10": "Denial of Service (DoS) Attacks",
}

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_WEB = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

CSA_CCM = {
    "AIS-04": "Secure Application Design and Development",
    "AIS-05": "Automated Application Security Testing",
    "AIS-07": "Application Vulnerability Remediation",
    "CCC-04": "Unauthorized Change Protection",
    "CEK-03": "Data Encryption",
    "CEK-12": "Key Rotation",
    "DSP-17": "Sensitive Data Protection",
    "HRS-11": "Security Awareness Training",
    "IAM-05": "Least Privilege",
    "IAM-14": "Strong Authentication",
    "IAM-15": "Passwords Management",
    "IAM-16": "Authorization Mechanisms",
    "IVS-03": "Network Security",
    "LOG-03": "Security Monitoring and Alerting",
    "STA-08": "Supply Chain Risk Management",
    "TVM-02": "Malware Protection Policy and Procedures",
    "TVM-05": "External Library Vulnerabilities",
    "TVM-07": "Vulnerability Identification",
    "UEM-09": "Anti-Malware Detection and Prevention",
}

ATTACK = {
    "T1027": "Obfuscated Files or Information",
    "T1027.013": "Obfuscated Files or Information: Encrypted/Encoded File",
    "T1036": "Masquerading",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1041": "Exfiltration Over C2 Channel",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1102": "Web Service",
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1190": "Exploit Public-Facing Application",
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    "T1197": "BITS Jobs",
    "T1204.002": "User Execution: Malicious File",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1546.016": "Event Triggered Execution: Installer Packages",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.004": "Unsecured Credentials: Private Keys",
    "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
    "T1562.006": "Impair Defenses: Indicator Blocking",
    "T1564": "Hide Artifacts",
    "T1564.003": "Hide Artifacts: Hidden Window",
    "T1566.003": "Phishing: Spearphishing via Service",
    "T1567": "Exfiltration Over Web Service",
    "T1657": "Financial Theft",
}

ATLAS = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0010.001": "AI Supply Chain Compromise: AI Software",
    "AML.T0010.003": "AI Supply Chain Compromise: Model",
    "AML.T0011": "User Execution",
    "AML.T0011.000": "User Execution: Unsafe AI Artifacts",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0068": "LLM Prompt Obfuscation",
}

CWE = {
    "CWE-20": "Improper Input Validation",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-252": "Unchecked Return Value",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-451": "User Interface Misrepresentation of Critical Information",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-506": "Embedded Malicious Code",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-778": "Insufficient Logging",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-807": "Reliance on Untrusted Inputs in a Security Decision",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-841": "Improper Enforcement of Behavioral Workflow",
    "CWE-863": "Incorrect Authorization",
    "CWE-912": "Hidden Functionality",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1188": "Initialization of a Resource with an Insecure Default",
    "CWE-1357": "Reliance on Insufficiently Trustworthy Component",
    "CWE-1427": "Improper Neutralization of Input Used for LLM Prompting",
}

NIST_SSDF = {
    "PO.5": "Implement and Maintain Secure Environments for Software Development",
    "PS.1": "Protect All Forms of Code from Unauthorized Access and Tampering",
    "PS.2": "Provide a Mechanism for Verifying Software Release Integrity",
    "PW.4": "Reuse Existing, Well-Secured Software When Feasible",
    "PW.5": "Create Source Code by Adhering to Secure Coding Practices",
    "PW.7": "Review and/or Analyze Human-Readable Code to Identify Vulnerabilities",
    "PW.9": "Configure Software to Have Secure Settings by Default",
    "RV.1": "Identify and Confirm Vulnerabilities on an Ongoing Basis",
}


def _attack_link(item_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + item_id.replace(".", "/") + "/"


def _atlas_link(item_id: str) -> str:
    return "https://atlas.mitre.org/techniques/" + ".".join(item_id.split(".")[:2])


def _cwe_link(item_id: str) -> str:
    return "https://cwe.mitre.org/data/definitions/%s.html" % item_id.split("-", 1)[1]


FRAMEWORKS: Dict[str, Framework] = {
    "owasp-sc": Framework(
        "owasp-sc",
        "OWASP Smart Contract Top 10 (2025)",
        "OWASP-SC",
        "https://owasp.org/www-project-smart-contract-top-10/",
        OWASP_SC,
    ),
    "owasp-llm": Framework(
        "owasp-llm",
        "OWASP Top 10 for LLM Applications (2025)",
        "OWASP-LLM",
        "https://genai.owasp.org/llm-top-10/",
        OWASP_LLM,
    ),
    "owasp-web": Framework(
        "owasp-web",
        "OWASP Top 10 (2021)",
        "OWASP-Web",
        "https://owasp.org/Top10/",
        OWASP_WEB,
    ),
    "csa-ccm": Framework(
        "csa-ccm",
        "CSA Cloud Controls Matrix v4",
        "CSA-CCM",
        "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        CSA_CCM,
    ),
    "attack": Framework(
        "attack",
        "MITRE ATT&CK Enterprise",
        "ATT&CK",
        "https://attack.mitre.org/",
        ATTACK,
        _attack_link,
    ),
    "atlas": Framework(
        "atlas",
        "MITRE ATLAS (AI and LLM systems)",
        "ATLAS",
        "https://atlas.mitre.org/",
        ATLAS,
        _atlas_link,
    ),
    "cwe": Framework(
        "cwe",
        "MITRE CWE",
        "CWE",
        "https://cwe.mitre.org/",
        CWE,
        _cwe_link,
    ),
    "nist-ssdf": Framework(
        "nist-ssdf",
        "NIST SP 800-218 Secure Software Development Framework 1.1",
        "NIST-SSDF",
        "https://csrc.nist.gov/pubs/sp/800/218/final",
        NIST_SSDF,
    ),
}

ALIASES = {
    "sc": "owasp-sc",
    "smart-contract": "owasp-sc",
    "owasp-smart-contract": "owasp-sc",
    "llm": "owasp-llm",
    "owasp": "owasp-web",
    "web": "owasp-web",
    "ccm": "csa-ccm",
    "csa": "csa-ccm",
    "mitre-attack": "attack",
    "att&ck": "attack",
    "mitre-atlas": "atlas",
    "ssdf": "nist-ssdf",
    "nist": "nist-ssdf",
}


def resolve_frameworks(spec: Optional[str]) -> List[str]:
    """Turn a comma-separated framework list into canonical keys."""
    if not spec or spec.strip().lower() in {"all", "*"}:
        return list(FRAMEWORKS)
    keys: List[str] = []
    for raw in spec.split(","):
        name = raw.strip().lower()
        if not name:
            continue
        if name in {"none", "off"}:
            return []
        key = ALIASES.get(name, name)
        if key not in FRAMEWORKS:
            raise ValueError(
                "unknown framework '%s' (choose from: %s)" % (raw.strip(), ", ".join(FRAMEWORKS))
            )
        if key not in keys:
            keys.append(key)
    return keys
