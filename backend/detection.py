"""Explainable, rule-based threat detection engine.

Each rule carries its own metadata (category, MITRE ATT&CK technique, CWE,
remediation) so every finding can be explained to an analyst. Input is
inspected both as received and after URL/HTML decoding, so simple encoding
such as ``%27%20OR%201%3D1`` does not hide an indicator.

This is a triage aid, not a substitute for a WAF, endpoint sensor, SIEM, or
analyst review. A match is an indicator for investigation, not proof.
"""

import html
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

ENGINE_NAME = "transparent-rules"
ENGINE_VERSION = "2.0.0"
MAX_EVIDENCE_PER_RULE = 3
EVIDENCE_CONTEXT = 40


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    weight: int
    pattern: re.Pattern
    description: str
    remediation: str
    mitre: str
    mitre_name: str
    cwe: str


RULES = (
    Rule("SQL_INJECTION", "Possible SQL injection", "Injection", 40,
         re.compile(r"\bunion\s+(?:all\s+)?select\b|\bselect\b.{1,160}\bfrom\b"
                    r"|(?:'|\")\s*(?:or|and)\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+"
                    r"|;\s*(?:drop|truncate|alter)\s+table\b|\bsleep\s*\(\s*\d+\s*\)|\bwaitfor\s+delay\b", re.I),
         "SQL syntax in user-controlled input that could alter a database query.",
         "Use parameterized queries, validate input server-side, and review database logs for the source.",
         "T1190", "Exploit Public-Facing Application", "CWE-89"),
    Rule("XSS", "Possible cross-site scripting", "Injection", 40,
         re.compile(r"<\s*script\b|javascript\s*:|\bon(?:error|load|mouseover|focus)\s*=|<\s*iframe\b"
                    r"|<\s*svg[^>]*\bon\w+\s*=|\bdocument\.cookie\b", re.I),
         "Markup or script in input that could execute in a victim's browser.",
         "Encode output by context, enforce a Content-Security-Policy, and sanitize rich text.",
         "T1059.007", "Command and Scripting Interpreter: JavaScript", "CWE-79"),
    Rule("COMMAND_INJECTION", "Possible command injection", "Injection", 40,
         re.compile(r"(?:;|&&|\|\||\|)\s*(?:bash|sh|zsh|cmd(?:\.exe)?|powershell|curl|wget|nc|whoami|uname)\b"
                    r"|\$\([^)]{1,100}\)", re.I),
         "Shell metacharacters followed by a command interpreter or common tool.",
         "Avoid shell invocation with user input; use allow-lists and argument arrays.",
         "T1059", "Command and Scripting Interpreter", "CWE-78"),
    Rule("JNDI_INJECTION", "Possible JNDI / Log4Shell injection", "Injection", 50,
         re.compile(r"\$\{\s*jndi\s*:|\$\{[^}]{0,30}\$\{\s*(?:lower|upper|env|::-)", re.I),
         "JNDI lookup expression associated with Log4Shell (CVE-2021-44228) exploitation.",
         "Patch Log4j to a fixed version, block outbound LDAP/RMI, and hunt for follow-up callbacks.",
         "T1190", "Exploit Public-Facing Application", "CWE-917"),
    Rule("XXE", "Possible XML external entity", "Injection", 40,
         re.compile(r"<!ENTITY[^>]{0,200}\bSYSTEM\b|<!DOCTYPE[^>]{0,200}\[\s*<!ENTITY", re.I),
         "External entity declaration that could read local files or reach internal hosts.",
         "Disable DTDs and external entity resolution in every XML parser.",
         "T1190", "Exploit Public-Facing Application", "CWE-611"),
    Rule("PATH_TRAVERSAL", "Possible path traversal", "File Access", 30,
         re.compile(r"\.\.[\\/]", re.I),
         "Directory traversal sequence that may escape an intended directory.",
         "Canonicalize paths and confirm they stay under an allowed base directory.",
         "T1190", "Exploit Public-Facing Application", "CWE-22"),
    Rule("SENSITIVE_FILE_PROBE", "Sensitive file access attempt", "File Access", 25,
         re.compile(r"/\.env\b|/\.git(?:/|\b)|/etc/(?:passwd|shadow)\b|\bwp-config\.php\b"
                    r"|/\.aws/credentials\b|\bid_rsa\b|/\.htpasswd\b", re.I),
         "Request for a file that commonly contains credentials or secrets.",
         "Ensure these files are not web-accessible and rotate any secret that may have been exposed.",
         "T1552.001", "Unsecured Credentials: Credentials In Files", "CWE-538"),
    Rule("SSRF", "Possible server-side request forgery", "Network", 35,
         re.compile(r"169\.254\.169\.254|metadata\.google\.internal|\b(?:gopher|dict|file)://"
                    r"|\b(?:url|uri|dest|redirect|target)=https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0)", re.I),
         "Reference to cloud metadata, loopback, or unusual URL schemes in a parameter.",
         "Allow-list outbound destinations, block link-local ranges, and require IMDSv2.",
         "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "CWE-918"),
    Rule("BRUTE_FORCE", "Possible brute-force activity", "Authentication", 30,
         re.compile(r"failed login|login failed|failed password|multiple failed attempts"
                    r"|authentication failure|invalid user|brute force|account locked", re.I),
         "Authentication failures that can indicate password guessing.",
         "Enforce lockout or throttling, require MFA, and check the source for other targets.",
         "T1110", "Brute Force", "CWE-307"),
    Rule("SCANNER_ACTIVITY", "Known scanner or attack tool", "Reconnaissance", 20,
         re.compile(r"\b(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|zgrab|nuclei)\b", re.I),
         "Signature of an automated vulnerability scanner or attack tool.",
         "Confirm whether the scan was authorized; rate-limit or block the source if not.",
         "T1595.002", "Active Scanning: Vulnerability Scanning", "—"),
)

RULES_BY_ID = {rule.id: rule for rule in RULES}

ADVICE = {
    "CRITICAL": "Investigate immediately, preserve relevant logs, and contain confirmed activity.",
    "HIGH": "Review the source and affected service; apply appropriate security controls.",
    "MEDIUM": "Review the event and monitor for related activity.",
    "LOW": "No configured indicator matched. Continue routine monitoring.",
}


def risk_level_for(score):
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def _decoded_variants(text):
    """Return (label, text) pairs: the raw input plus distinct decoded forms."""
    variants = [("raw", text)]
    current = text
    for _ in range(2):  # handles single and double URL encoding
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current = decoded
        variants.append(("url-decoded", current))
    unescaped = html.unescape(current)
    if unescaped != current:
        variants.append(("html-decoded", unescaped))
    return variants


def _evidence(text, match):
    start, end = match.span()
    before = text[max(0, start - EVIDENCE_CONTEXT):start]
    after = text[end:end + EVIDENCE_CONTEXT]
    return {
        "match": text[start:end][:200],
        "before": ("…" if start > EVIDENCE_CONTEXT else "") + before,
        "after": after + ("…" if end + EVIDENCE_CONTEXT < len(text) else ""),
        "offset": start,
    }


def rule_catalog():
    return [{
        "id": rule.id, "name": rule.name, "category": rule.category, "weight": rule.weight,
        "description": rule.description, "remediation": rule.remediation,
        "mitre": rule.mitre, "mitre_name": rule.mitre_name, "cwe": rule.cwe,
    } for rule in RULES]


def assess_risk(event_data):
    variants = _decoded_variants(event_data)
    findings = []
    for rule in RULES:
        for label, text in variants:
            matches = list(rule.pattern.finditer(text))
            if matches:
                findings.append({
                    "rule_id": rule.id, "name": rule.name, "category": rule.category,
                    "weight": rule.weight, "mitre": rule.mitre, "mitre_name": rule.mitre_name,
                    "cwe": rule.cwe, "description": rule.description, "remediation": rule.remediation,
                    "decoded": label != "raw", "decoding": label, "match_count": len(matches),
                    "evidence": [_evidence(text, m) for m in matches[:MAX_EVIDENCE_PER_RULE]],
                })
                break
    findings.sort(key=lambda finding: finding["weight"], reverse=True)
    score = min(sum(finding["weight"] for finding in findings), 100)
    level = risk_level_for(score)
    return {
        "risk_score": score,
        "risk_level": level,
        "detected_threats": [finding["name"] for finding in findings] or ["No configured indicator matched"],
        "matched_rules": [finding["rule_id"] for finding in findings],
        "findings": findings,
        "recommendation": ADVICE[level],
        "engine": f"{ENGINE_NAME}-v{ENGINE_VERSION}",
    }
