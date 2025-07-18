from collections import Counter

import numpy as np
import pandas as pd

COLUMNS = [
    "timestamp",
    "flow_id",
    "pcap_cnt",
    "event_type",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
    "pkt_src",
    "alert_action",
    "alert_gid",
    "alert_signature_id",
    "alert_rev",
    "alert_signature",
    "alert_category",
    "alert_severity",
    "app_proto",
    "direction",
    "flow_pkts_toserver",
    "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
    "flow_start",
    "flow_src_ip",
    "flow_dest_ip",
    "flow_src_port",
    "flow_dest_port",
    "payload",
    "payload_printable",
    "stream",
    "packet",
    "linktype",
    "http_hostname",
    "http_url",
    "http_user_agent",
    "http_method",
    "http_protocol",
    "http_length",
    "zap_scan_id",
    "vuln_name",
]

FEATURES = [
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
    "app_proto",
    "direction",
    "flow_pkts_toserver",
    "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
    "payload",
    "payload_printable",
    "http_hostname",
    "http_url",
    "http_user_agent",
    "http_method",
    "http_protocol",
    "http_length",
]

NUMERIC_FEATURES = [
    "flow_pkts_toserver",
    "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
    "http_length",
]

TEXT_FEATURES = [
    "payload",
    "payload_printable",
    "http_hostname",
    "http_url",
    "http_user_agent",
]

CATEGORICAL_FEATURES = [
    "proto",
    "app_proto",
    "http_method",
    "http_protocol",
]

IP_FEATURES = [
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
]

TARGET = "vuln_name"

LABELS = [
    None,
    ".htaccess Information Leak",
    "XSLT Injection",
    "Cloud Metadata Potentially Exposed",
    "Parameter Tampering",
    "Source Code Disclosure - CVE-2012-1823",
    "XPath Injection",
    "Server Side Template Injection",
    "Buffer Overflow",
    "SQL Injection - Hypersonic SQL",
    "SQL Injection - SQLite",
    "Remote File Inclusion",
    "Cross Site Scripting (Persistent) - Spider",
    "Directory Browsing",
    "External Redirect",
    "Cross Site Scripting (Persistent) - Prime",
    "SQL Injection - PostgreSQL",
    "Source Code Disclosure - /WEB-INF Folder",
    "Server Side Include",
    "Remote OS Command Injection",
    "Path Traversal",
    ".env Information Leak",
    "Format String Error",
    "ELMAH Information Leak",
    "Hidden File Found",
    "Server Side Code Injection",
    "Trace.axd Information Leak",
    "SQL Injection",
    "Spring4Shell",
    "Remote Code Execution - CVE-2012-1823",
    "SQL Injection - Oracle",
    "Cross Site Scripting (Reflected)",
    "CRLF Injection",
    "Spring Actuator Information Leak",
    "SQL Injection - MsSQL",
    "User Agent Fuzzer",
    "SQL Injection - MySQL",
]


df = pd.read_csv("./csv/marked.csv")
vulns = pd.read_csv("./csv/vulns.csv")
df["x-zap-scan-id"] = (
    df["x-zap-scan-id"].fillna("-1").astype(np.int64).astype(str).str.strip()
)
merged_df = pd.merge(
    df,
    vulns[["id", "name"]],
    left_on="x-zap-scan-id",
    right_on="id",
    how="left",
)
merged_df = merged_df.replace({np.nan: None})
LABELS_COUNT = dict(Counter(merged_df["name"]))

ALIASES = {
    "CWE-78: OS Command Injection": (
        "Remote OS Command Injection",
        "Spring4Shell",
    ),
    "CWE-89: SQL Injection": (
        "SQL Injection",
        "SQL Injection - MySQL",
        "SQL Injection - PostgreSQL",
        "SQL Injection - Hypersonic SQL",
        "SQL Injection - MsSQL",
        "SQL Injection - Oracle",
        "SQL Injection - SQLite",
    ),
    "CWE-94: Code Injection": (
        "Server Side Template Injection",
        "Server Side Code Injection",
        "Remote Code Execution - CVE-2012-1823",
    ),
    "CWE-91: XML Injection": (
        "XSLT Injection",
        "XPath Injection",
    ),
    "CWE-113: CRLF Injection": ("CRLF Injection",),
    "CWE-79: XSS": (
        "Cross Site Scripting (Reflected)",
        "Cross Site Scripting (Persistent) - Prime",
        "Cross Site Scripting (Persistent) - Spider",
    ),
    "CWE-22: Path Traversal": ("Path Traversal",),
    "CWE-98: Remote File Inclusion": ("Remote File Inclusion",),
    "CWE-97: SSI": ("Server Side Include",),
    "CWE-200: Information Exposure": (
        "Directory Browsing",
        "Hidden File Found",
        "Source Code Disclosure - /WEB-INF Folder",
        ".htaccess Information Leak",
        ".env Information Leak",
        "Trace.axd Information Leak",
        "Spring Actuator Information Leak",
        "Cloud Metadata Potentially Exposed",
        "ELMAH Information Leak",
        "Source Code Disclosure - CVE-2012-1823",
    ),
    "CWE-601: Open Redirect": ("External Redirect",),
    "CWE-472: Parameter Tampering": ("Parameter Tampering",),
    "CWE-20: Input Validation": ("Remote Code Execution - CVE-2012-1823",),
    "CWE-120: Buffer Overflow": ("Buffer Overflow",),
    "CWE-134: Format String": ("Format String Error",),
    "NORMAL": (None,),
}

ALIASES_COUNT = {
    alias: sum(LABELS_COUNT[label] for label in ALIASES[alias])
    for alias in ALIASES
}
