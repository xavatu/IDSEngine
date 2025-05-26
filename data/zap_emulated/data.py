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
    # "timestamp",
    # "flow_id",
    # "pcap_cnt",
    # "event_type",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
    # "pkt_src",
    # "alert_action",
    # "alert_gid",
    # "alert_signature_id",
    # "alert_rev",
    # "alert_signature",
    # "alert_category",
    # "alert_severity",
    "app_proto",
    "direction",
    "flow_pkts_toserver",
    "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
    # "flow_start",
    # "flow_src_ip",
    # "flow_dest_ip",
    # "flow_src_port",
    # "flow_dest_port",
    "payload",
    "payload_printable",
    # "stream",
    # "packet",
    # "linktype",
    "http_hostname",
    "http_url",
    "http_user_agent",
    "http_method",
    "http_protocol",
    "http_length",
    # "zap_scan_id",
    # "vuln_name",
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

# from collections import Counter
#
# import pandas as pd
#
# df = pd.read_csv("./csv/marked.csv")
# vulns = pd.read_csv("./csv/vulns.csv")
# df["x-zap-scan-id"] = (
#     df["x-zap-scan-id"].fillna("-1").astype(int64).astype(str).str.strip()
# )
# print(df["x-zap-scan-id"])
# merged_df = pd.merge(
#     df,
#     vulns[["id", "name"]],
#     left_on="x-zap-scan-id",
#     right_on="id",
#     how="left",
# )
# print(Counter(merged_df["name"]))

LABELS_COUNT = {
    None: 30770,
    "Remote OS Command Injection": 3367,
    "Path Traversal": 3273,
    "SQL Injection - SQLite": 2771,
    "Remote File Inclusion": 2131,
    "Server Side Template Injection": 1816,
    "SQL Injection": 1515,
    "SQL Injection - PostgreSQL": 716,
    "SQL Injection - MySQL": 672,
    "SQL Injection - Hypersonic SQL": 542,
    "SQL Injection - MsSQL": 480,
    "SQL Injection - Oracle": 422,
    "External Redirect": 402,
    "Server Side Code Injection": 304,
    "Parameter Tampering": 230,
    "CRLF Injection": 224,
    "XSLT Injection": 152,
    "Cross Site Scripting (Reflected)": 148,
    "Server Side Include": 144,
    "Hidden File Found": 141,
    "Cloud Metadata Potentially Exposed": 133,
    "Remote Code Execution - CVE-2012-1823": 112,
    "User Agent Fuzzer": 109,
    "Format String Error": 99,
    "XPath Injection": 96,
    "Spring Actuator Information Leak": 43,
    "Buffer Overflow": 33,
    "Cross Site Scripting (Persistent) - Prime": 32,
    "Spring4Shell": 16,
    "Source Code Disclosure - /WEB-INF Folder": 8,
    "Cross Site Scripting (Persistent) - Spider": 7,
    "Source Code Disclosure - CVE-2012-1823": 7,
    "Directory Browsing": 7,
    ".env Information Leak": 4,
    ".htaccess Information Leak": 4,
    "Trace.axd Information Leak": 4,
    "ELMAH Information Leak": 2,
}
# for k, v in sorted(LABELS_COUNT.items(), key=lambda x: x[1]):
#     print(k, "–", v)

ALIASES = {
    "CWE-78: OS Command Injection": (
        "Remote OS Command Injection",
        "Spring4Shell",
        "Remote Code Execution - CVE-2012-1823",
    ),
    "CWE-22: Path Traversal": (
        "Path Traversal",
        "Hidden File Found",
        "Directory Browsing",
    ),
    "CWE-89: SQL Injection": (
        "SQL Injection - SQLite",
        "SQL Injection",
        "SQL Injection - MySQL",
        "SQL Injection - PostgreSQL",
        "SQL Injection - Hypersonic SQL",
        "SQL Injection - MsSQL",
        "SQL Injection - Oracle",
    ),
    "CWE-98: Remote File Inclusion": ("Remote File Inclusion",),
    "CWE-94: Code Injection": (
        "Server Side Template Injection",
        "Server Side Code Injection",
    ),
    "CWE-601: Open Redirect": ("External Redirect",),
    "CWE-472: Parameter Tampering": ("Parameter Tampering",),
    "CWE-93: CRLF Injection": ("CRLF Injection",),
    "CWE-91: XML Injection": (
        "XSLT Injection",
        "XPath Injection",
    ),
    "CWE-97: SSI": ("Server Side Include",),
    "CWE-200: Information Leak": (
        "Cloud Metadata Potentially Exposed",
        "Spring Actuator Information Leak",
        "Source Code Disclosure - CVE-2012-1823",
        "Source Code Disclosure - /WEB-INF Folder",
        "Trace.axd Information Leak",
        ".htaccess Information Leak",
        ".env Information Leak",
        "ELMAH Information Leak",
    ),
    "CWE-79: XSS": (
        "Cross Site Scripting (Reflected)",
        "Cross Site Scripting (Persistent) - Prime",
        "Cross Site Scripting (Persistent) - Spider",
    ),
    "CWE-134: Format string": ("Format String Error",),
    "CWE-20: Fuzzing": ("User Agent Fuzzer",),
    "CWE-120: Buffer Overflow": ("Buffer Overflow",),
    "NORMAL": (None,),
}

# ALIASES_COUNT = {
#     alias: sum(LABELS_COUNT[label] for label in ALIASES[alias])
#     for alias in ALIASES
# }
# ALIASES_COUNT = {
#     k: v for k, v in sorted(ALIASES_COUNT.items(), key=lambda item: item[1])
# }
# print(ALIASES_COUNT)
ALIASES_COUNT = {
    "CWE-120: Buffer Overflow": 33,
    "CWE-134: Format string": 99,
    "CWE-20: Fuzzing": 109,
    "CWE-97: SSI": 144,
    "CWE-79: XSS": 187,
    "CWE-200: Information Leak": 205,
    "CWE-93: CRLF Injection": 224,
    "CWE-472: Parameter Tampering": 230,
    "CWE-91: XML Injection": 248,
    "CWE-601: Open Redirect": 402,
    "CWE-94: Code Injection": 2120,
    "CWE-98: Remote File Inclusion": 2131,
    "CWE-22: Path Traversal": 3421,
    "CWE-78: OS Command Injection": 3495,
    "CWE-89: SQL Injection": 7118,
    "NORMAL": 30770,
}
