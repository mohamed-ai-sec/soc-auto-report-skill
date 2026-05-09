---
name: soc-auto-report
description: "SOC auto-report engine. Trigger on security artifacts such as logs, SIEM alerts, EDR telemetry, cloud events, Kubernetes audit logs, source control events, and email artifacts to generate incident reports, triage summaries, MITRE ATT&CK mapping, post-incident review drafts, detection queries, blast-radius analysis, and maliciousness assessments."
---

# 🛡️ SOC Auto-Report Engine v3.1.0

<div align="center">

![Version](https://img.shields.io/badge/version-3.1.0-blue?style=for-the-badge)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-supported-red?style=for-the-badge)
![D3FEND](https://img.shields.io/badge/D3FEND-supported-orange?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Claude Skills](https://img.shields.io/badge/Claude-Skills%20Ready-blueviolet?style=for-the-badge)

### Turns raw security artifacts into structured, evidence-based incident reports.
### Built for SOC analysts. Designed for defensible reporting and operational clarity.

⭐ If this project helps your team, consider starring or sharing it.

[Quick Start](#-quick-start) ·
[How It Works](#-how-it-works) ·
[What You Get](#-what-you-get) ·
[Supported Inputs](#-supported-inputs) ·
[Evidence Model](#-evidence-model) ·
[FAQ](#-faq)

</div>

---

# 💬 Why This Exists

SOC analysts often spend valuable investigation time manually rewriting the same incident structure across tickets, reports, escalations, and post-incident reviews.

This Skill is designed to transform raw security telemetry into a structured incident report while preserving:

- source fidelity,
- evidence transparency,
- timeline accuracy,
- and analyst accountability.

The goal is not to replace analysts.  
The goal is to reduce repetitive documentation overhead and accelerate incident response workflows.

---

# ⚡ What It Does

Paste a security artifact and generate a structured incident response output that may include:

- Incident metadata
- Executive summary
- Technical narrative
- Timeline reconstruction
- IOC extraction
- MITRE ATT&CK mapping
- Threat hunting leads
- Detection engineering recommendations
- KQL / SPL / Sigma / YARA examples
- Post-incident review drafts
- Stakeholder communications

---

# 🚀 Quick Start

## ▶️ Claude.ai Projects

1. Open Claude.ai
2. Create or open a Project
3. Paste the contents of `SKILL.md` into Project Instructions
4. Start a new chat
5. Paste a security artifact or alert

The Skill will generate a structured report using the provided evidence.

---

## ▶️ ZIP Upload Method

```text
soc-auto-report-skill/
├── SKILL.md
├── README.md
└── LICENSE
```

Upload the project into a compatible workflow environment and enable the Skill.

---

## ▶️ Any LLM / API

You can also:

1. Copy the contents of `SKILL.md`
2. Use it as a system prompt or developer instruction
3. Paste a security artifact
4. Generate a structured incident report

---

# ⚙️ How It Works

```text
INPUT — Security Artifact(s)
        │
        ▼
PHASE 0 — Evidence Processing
        │
        ├─ Format identification
        ├─ IOC extraction
        ├─ Timestamp normalization
        ├─ Entity extraction
        ├─ Severity estimation
        ├─ Confidence scoring
        ├─ MITRE ATT&CK mapping
        ├─ Timeline reconstruction
        └─ Blast-radius estimation
        │
        ▼
PHASE 1 — Report Generation
        │
        ├─ Incident metadata
        ├─ Executive summary
        ├─ Technical narrative
        ├─ Timeline
        ├─ IOC table
        ├─ Recommendations
        ├─ Hunting leads
        ├─ Detection queries
        ├─ PIR draft
        └─ Stakeholder communications
        │
        ▼
PHASE 2 — Quality Validation
        │
        ├─ Unsupported claim detection
        ├─ Evidence consistency checks
        ├─ Timestamp integrity checks
        ├─ Uncertainty visibility
        └─ Final report generation
```

---

# 📤 What You Get

| # | Section | Description |
|---|---|---|
| 1 | Incident Metadata | ID, severity, status, source |
| 2 | Executive Summary | Management-readable summary |
| 3 | Technical Narrative | Evidence-based reconstruction |
| 4 | Attack Timeline | Chronological event mapping |
| 5 | IOC Table | Extracted indicators |
| 6 | Actions & Recommendations | Containment and remediation |
| 7 | Forensic Collection Plan | Suggested evidence collection |
| 8 | Threat Hunting Leads | Follow-up investigative paths |
| 9 | Detection Query Suite | KQL, SPL, Sigma, YARA examples |
| 10 | Sign-Off Block | Review and escalation notes |
| 11 | Post-Incident Review | PIR draft and lessons learned |
| 12 | Stakeholder Communications | Executive and staff-ready summaries |

---

# 🎯 Supported Inputs

## Security Telemetry Sources

| Category | Examples |
|---|---|
| Windows Events | 4624, 4625, 4688, 4698, 4768, 7045 |
| SIEM Alerts | Microsoft Sentinel, Splunk ES, QRadar, Elastic |
| EDR / XDR | CrowdStrike, Defender XDR, SentinelOne, Cortex |
| Cloud | CloudTrail, GuardDuty, Azure AD |
| Identity | Okta, Auth0, Active Directory |
| Container | Kubernetes audit logs, Docker events |
| SCM | GitHub audit logs, GitLab events |
| Network | Firewall, proxy, DNS, NDR |
| Email | Headers, phishing artifacts, DMARC failures |
| Scripting | PowerShell, AMSI, WMI |

---

## Common Analyst Prompts

```text
generate report
triage this alert
is this malicious?
map to MITRE
write Sigma rule
create PIR
generate KQL
threat hunting leads
write IR
document incident
```

---

# 🔒 Evidence Model

This Skill separates direct evidence from analyst inference.

## Evidence Tags

| Tag | Meaning |
|---|---|
| `[CONFIRMED]` | Directly observable in the input |
| `[OBSERVED]` | Visible in telemetry but not confirmed malicious |
| `[SUSPECTED]` | Analyst inference with supporting logic |
| `[DERIVED]` | Logical conclusion from evidence |
| `[UNKNOWN]` | Missing from the available data |
| `[UNKNOWN GAP]` | Missing timeline or investigative visibility |

---

# 🧭 Operating Principles

- Do not invent IOCs.
- Do not invent timestamps.
- Do not fabricate attribution.
- Preserve uncertainty explicitly.
- Mark assumptions clearly.
- Distinguish evidence from inference.
- Keep missing evidence visible.
- Avoid unsupported severity escalation.
- Map MITRE ATT&CK only when supported by observable behavior.

---

# 🖥️ Example

## Input

```text
EventID: 4768
TargetUserName: svc_backup
IpAddress: 192.168.4.55
TicketEncryptionType: 0x17
Status: 0x0
Timestamp: 2025-05-09T02:14:33Z
```

## Output

```text
INCIDENT REPORT         INC-2025-0509-001

Severity  : HIGH
Status    : Needs Review
Verdict   : Suspected malicious activity

EXECUTIVE SUMMARY
A Kerberos authentication event involving service account
svc_backup was observed from 192.168.4.55 at
2025-05-09T02:14:33Z.

The use of encryption type 0x17 may indicate weak cipher usage
commonly associated with Kerberoasting-related activity.
Additional authentication and endpoint telemetry should be
reviewed before final classification.

IOC TABLE
IOC               Type         Tag
svc_backup        Account      [CONFIRMED]
192.168.4.55      IPv4         [CONFIRMED]
0x17              Encryption   [OBSERVED]

NOTES
- Evidence is limited to the provided event.
- Timeline gaps remain unresolved.
- Additional telemetry is recommended.
```

---

# ❓ FAQ

## Will it ask questions before generating a report?

Only when the input is too sparse to support meaningful analysis.

---

## Does it invent IOCs?

No. Missing fields remain `[UNKNOWN]`.

---

## Does it use external threat intelligence automatically?

Not by default.

Any future enrichment should remain explicitly separated from evidence-based findings.

---

## Can it work outside Claude.ai?

Yes.

You can adapt `SKILL.md` for:
- Anthropic API
- Claude Code
- Internal LLM platforms
- Other compatible environments

---

## Does it support mixed-format inputs?

Yes.

Multiple related artifacts can be analyzed together in the same workflow.

---

# 📁 Repository Structure

```text
soc-auto-report-skill/
├── SKILL.md
├── README.md
└── LICENSE
```

---

# 🔗 References

| Resource | Purpose |
|---|---|
| https://attack.mitre.org | MITRE ATT&CK |
| https://d3fend.mitre.org | MITRE D3FEND |
| https://github.com/SigmaHQ/sigma | Sigma Rules |
| https://yara.readthedocs.io | YARA Documentation |
| https://volatility3.readthedocs.io | Volatility3 |
| https://oasis-open.github.io/cti-documentation/stix/intro | STIX 2.1 |

---

# 👤 Author

**mohamed-ai-sec**

SOC Automation · Detection Engineering · AI-Augmented Security Operations

> Built to reduce reporting friction while preserving evidence integrity.

---

# 📄 License

Released under the MIT License.

Free to use, adapt, and share with attribution appreciated.

---

<div align="center">

## Paste it. Parse it. Map it. Hunt it. Contain it.

**SOC Auto-Report Engine v3.1.0**

</div>
