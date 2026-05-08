"""
enrichment/few_shot_examples.py
================================
Curated few-shot examples for MITRE ATT&CK TTP mapping.

These examples are consumed by attack_mapper.py when building the
LangChain FewShotPromptTemplate.  Each example contains:

  text   : a short, realistic threat-intelligence excerpt
  ttps   : a JSON string listing mapped TTP objects, each with:
             - id            : MITRE ATT&CK technique ID (Txxxx or Txxxx.yyy)
             - name          : official technique name
             - tactic        : ATT&CK tactic category
             - justification : one sentence citing the evidence in the text

Coverage
--------
  Example 1 — Initial Access (T1190 Exploit Public-Facing Application)
  Example 2 — Execution + Lateral Movement (T1059.001, T1021.002)
  Example 3 — Exfiltration (T1041, T1048)
  Example 4 — Persistence + Defense Evasion (T1053.005, T1112)
  Example 5 — Command and Control (T1071.001, T1573.002)

Usage
-----
    from enrichment.few_shot_examples import FEW_SHOT_EXAMPLES, EXAMPLE_PROMPT

    # In attack_mapper.py:
    from langchain.prompts import FewShotPromptTemplate
    prompt = FewShotPromptTemplate(
        examples=FEW_SHOT_EXAMPLES,
        example_prompt=EXAMPLE_PROMPT,
        prefix=SYSTEM_PREFIX,
        suffix=SUFFIX_TEMPLATE,
        input_variables=["threat_text"],
    )
"""

from __future__ import annotations

from langchain_core.prompts import PromptTemplate

# ── Prompt skeleton for a single example ─────────────────────────────────────

EXAMPLE_PROMPT = PromptTemplate(
    input_variables=["text", "ttps"],
    template=(
        "Threat text:\n{text}\n\n"
        "Mapped TTPs (JSON):\n{ttps}"
    ),
)

# ── System prefix used by attack_mapper.py ────────────────────────────────────

SYSTEM_PREFIX = (
    "You are a MITRE ATT&CK expert analyst. "
    "Given a threat intelligence excerpt, output a JSON array of TTP objects. "
    "Each object must have exactly these keys: id, name, tactic, justification. "
    "Use ONLY real ATT&CK technique IDs (Txxxx or Txxxx.yyy). "
    "Do NOT invent technique IDs. "
    "Here are examples:\n"
)

SUFFIX_TEMPLATE = (
    "\nNow map the following threat text:\n"
    "Threat text:\n{threat_text}\n\n"
    "CRITICAL RULE: The 'id' field MUST start with the letter 'T' (e.g., 'T1190'). Do NOT use simple numbers like 1, 2, 3.\n"
    "Mapped TTPs (JSON):"
)

# ── Five curated examples ─────────────────────────────────────────────────────

FEW_SHOT_EXAMPLES: list[dict[str, str]] = [ 

    # ------------------------------------------------------------------
    # Example 1 – Initial Access via unpatched web application (Log4Shell)
    # ------------------------------------------------------------------
    {
        "text": (
            "Threat actors exploited CVE-2021-44228 (Log4Shell) in internet-facing "
            "Apache servers to achieve remote code execution. The attackers sent "
            "crafted JNDI lookup strings inside HTTP User-Agent headers, triggering "
            "the vulnerable Log4j library to reach out to an attacker-controlled LDAP "
            "server and download a malicious Java class."
        ),
        "ttps": (
            '[\n'
            '  {{\n'
            '    "id": "T1190",\n'
            '    "name": "Exploit Public-Facing Application",\n'
            '    "tactic": "Initial Access",\n'
            '    "justification": "Attackers exploited CVE-2021-44228 in an '
            'internet-facing Apache server to gain initial access."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1059.007",\n'
            '    "name": "Command and Scripting Interpreter: JavaScript",\n'
            '    "tactic": "Execution",\n'
            '    "justification": "A malicious Java class was downloaded and executed '
            'on the victim host after the JNDI callback."\n'
            '  }}\n'
            ']'
        ),
    },

    # ------------------------------------------------------------------
    # Example 2 – Execution + Lateral Movement (PowerShell + SMB)
    # ------------------------------------------------------------------
    {
        "text": (
            "After establishing a foothold, the Lazarus Group operators dropped a "
            "PowerShell script that enumerated local credentials from LSASS memory. "
            "Using the harvested NTLM hashes they performed pass-the-hash attacks "
            "to move laterally across the network via SMB, reaching the domain "
            "controller within 90 minutes of initial compromise."
        ),
        "ttps": (
            '[\n'
            '  {{\n'
            '    "id": "T1059.001",\n'
            '    "name": "Command and Scripting Interpreter: PowerShell",\n'
            '    "tactic": "Execution",\n'
            '    "justification": "Operators dropped and ran a PowerShell script '
            'to enumerate LSASS credentials."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1003.001",\n'
            '    "name": "OS Credential Dumping: LSASS Memory",\n'
            '    "tactic": "Credential Access",\n'
            '    "justification": "The PowerShell script harvested NTLM hashes '
            'directly from LSASS memory."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1550.002",\n'
            '    "name": "Use Alternate Authentication Material: Pass the Hash",\n'
            '    "tactic": "Lateral Movement",\n'
            '    "justification": "Harvested NTLM hashes were reused via '
            'pass-the-hash over SMB to reach the domain controller."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1021.002",\n'
            '    "name": "Remote Services: SMB/Windows Admin Shares",\n'
            '    "tactic": "Lateral Movement",\n'
            '    "justification": "Lateral movement was performed over SMB '
            'using administrative shares."\n'
            '  }}\n'
            ']'
        ),
    },

    # ------------------------------------------------------------------
    # Example 3 – Exfiltration over C2 channel and cloud storage
    # ------------------------------------------------------------------
    {
        "text": (
            "The APT28 operators used their Cobalt Strike beacon to compress "
            "and stage roughly 40 GB of intellectual property in a hidden folder. "
            "Data was exfiltrated in two phases: first via encrypted HTTPS to the "
            "C2 server, then via a second channel using the Dropbox API to upload "
            "password-protected ZIP archives, bypassing DLP controls that only "
            "monitored standard email and FTP."
        ),
        "ttps": (
            '[\n'
            '  {{\n'
            '    "id": "T1560.001",\n'
            '    "name": "Archive Collected Data: Archive via Utility",\n'
            '    "tactic": "Collection",\n'
            '    "justification": "Intellectual property was compressed into '
            'password-protected ZIP archives before exfiltration."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1041",\n'
            '    "name": "Exfiltration Over C2 Channel",\n'
            '    "tactic": "Exfiltration",\n'
            '    "justification": "Data was exfiltrated over the encrypted HTTPS '
            'channel used by the Cobalt Strike beacon for C2 communication."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1048.002",\n'
            '    "name": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",\n'
            '    "tactic": "Exfiltration",\n'
            '    "justification": "A secondary Dropbox API channel was used to '
            'upload archives, bypassing DLP controls on standard protocols."\n'
            '  }}\n'
            ']'
        ),
    },

    # ------------------------------------------------------------------
    # Example 4 – Persistence via scheduled task + registry modification
    # ------------------------------------------------------------------
    {
        "text": (
            "WannaCry established persistence on infected hosts by creating a "
            "Windows scheduled task named 'MsWindowsUpdate' that re-executed the "
            "dropper every 30 minutes. Additionally, it modified the registry key "
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run to ensure "
            "the payload survived reboots. The malware also disabled Windows "
            "Defender and removed volume shadow copies to hinder recovery."
        ),
        "ttps": (
            '[\n'
            '  {{\n'
            '    "id": "T1053.005",\n'
            '    "name": "Scheduled Task/Job: Scheduled Task",\n'
            '    "tactic": "Persistence",\n'
            '    "justification": "A scheduled task named \'MsWindowsUpdate\' '
            're-executed the dropper every 30 minutes to maintain persistence."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1547.001",\n'
            '    "name": "Boot or Logon Autostart Execution: Registry Run Keys",\n'
            '    "tactic": "Persistence",\n'
            '    "justification": "The CurrentVersion\\\\Run registry key was modified '
            'to launch the payload on every reboot."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1562.001",\n'
            '    "name": "Impair Defenses: Disable or Modify Tools",\n'
            '    "tactic": "Defense Evasion",\n'
            '    "justification": "Windows Defender was disabled to prevent '
            'detection of the ransomware payload."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1490",\n'
            '    "name": "Inhibit System Recovery",\n'
            '    "tactic": "Impact",\n'
            '    "justification": "Volume shadow copies were deleted to prevent '
            'victims from recovering encrypted files."\n'
            '  }}\n'
            ']'
        ),
    },

    # ------------------------------------------------------------------
    # Example 5 – Command and Control via HTTPS and domain fronting
    # ------------------------------------------------------------------
    {
        "text": (
            "The implant communicated with its command-and-control infrastructure "
            "exclusively over TLS 1.3-encrypted HTTPS (port 443) to blend with "
            "legitimate web traffic. The malware employed domain fronting through "
            "a major CDN provider, routing C2 traffic via a trusted hostname in "
            "the CDN's shared certificate while the actual Host header pointed to "
            "the attacker's origin server. Beacon intervals were randomised between "
            "30 and 120 seconds with 15 % jitter to evade anomaly-based detection."
        ),
        "ttps": (
            '[\n'
            '  {{\n'
            '    "id": "T1071.001",\n'
            '    "name": "Application Layer Protocol: Web Protocols",\n'
            '    "tactic": "Command and Control",\n'
            '    "justification": "C2 traffic was carried over HTTPS (port 443) '
            'to mimic legitimate web browsing."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1573.002",\n'
            '    "name": "Encrypted Channel: Asymmetric Cryptography",\n'
            '    "tactic": "Command and Control",\n'
            '    "justification": "TLS 1.3 asymmetric encryption was used to '
            'protect the C2 channel from inspection."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1090.004",\n'
            '    "name": "Proxy: Domain Fronting",\n'
            '    "tactic": "Command and Control",\n'
            '    "justification": "The CDN shared certificate was used for domain '
            'fronting to disguise the true C2 origin server."\n'
            '  }},\n'
            '  {{\n'
            '    "id": "T1008",\n'
            '    "name": "Fallback Channels",\n'
            '    "tactic": "Command and Control",\n'
            '    "justification": "Randomised beacon intervals with jitter were '
            'used to evade anomaly-based network detection."\n'
            '  }}\n'
            ']'
        ),
    },
]
