import math
from collections import Counter

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


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    total = len(s)
    return -sum(
        (cnt / total) * math.log2(cnt / total) for cnt in counter.values()
    )


def extract_features(event):
    http = event.get("http", {})
    flow = event.get("flow", {})
    payload = event.get("payload", "") or ""
    payload_printable = event.get("payload_printable", "") or ""

    feat = {
        "flow_pkts_toserver": int(flow.get("pkts_toserver", 0)),
        "flow_pkts_toclient": int(flow.get("pkts_toclient", 0)),
        "flow_bytes_toserver": int(flow.get("bytes_toserver", 0)),
        "flow_bytes_toclient": int(flow.get("bytes_toclient", 0)),
        "http_length": int(http.get("length", 0) or 0),
        "proto": event.get("proto", "") or "unknown",
        "app_proto": event.get("app_proto", "") or "unknown",
        "http_method": http.get("http_method", "") or "unknown",
        "http_protocol": http.get("protocol", "") or "unknown",
        "payload_len": int(len(payload)),
        "payload_entropy": float(string_entropy(payload)),
        "payload_printable_len": int(len(payload_printable)),
        "payload_printable_entropy": float(string_entropy(payload_printable)),
        "http_hostname_len": int(len(http.get("hostname", "") or "")),
        "http_hostname_entropy": float(
            string_entropy(http.get("hostname", "") or "")
        ),
        "http_url_len": int(len(http.get("url", "") or "")),
        "http_url_entropy": float(string_entropy(http.get("url", "") or "")),
        "http_user_agent_len": int(len(http.get("http_user_agent", "") or "")),
        "http_user_agent_entropy": float(
            string_entropy(http.get("http_user_agent", "") or "")
        ),
    }
    return feat
