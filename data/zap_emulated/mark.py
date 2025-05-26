import pandas as pd

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

import json
from data import ALIASES


def normalize_label(label):
    for alias, group in ALIASES.items():
        if label in group or label == alias:
            return alias
    return "NORMAL"


df_logs = pd.read_csv("csv/malicious_logs.csv")
df_benign = pd.read_csv("csv/benign.csv")

df_logs["vuln_name"] = df_logs["vuln_name"].apply(normalize_label)
df_benign["vuln_name"] = (
    df_benign["vuln_name"].apply(normalize_label)
    if "vuln_name" in df_benign.columns
    else "NORMAL"
)
df_benign["pcap_cnt"] = df_benign["pcap_cnt"] + max(df_logs["pcap_cnt"])

df_marked = pd.concat([df_logs, df_benign], ignore_index=True)
EVE_FIELDS = [
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
]


def extract_event_fields(event):
    d = {}
    alert = event.get("alert", {})
    http = event.get("http", {})
    flow = event.get("flow", {})

    d["timestamp"] = event.get("timestamp")
    d["flow_id"] = event.get("flow_id")
    d["pcap_cnt"] = event.get("pcap_cnt")
    d["event_type"] = event.get("event_type")
    d["src_ip"] = event.get("src_ip")
    d["src_port"] = event.get("src_port")
    d["dest_ip"] = event.get("dest_ip")
    d["dest_port"] = event.get("dest_port")
    d["proto"] = event.get("proto")
    d["pkt_src"] = event.get("pkt_src")
    d["alert_action"] = alert.get("action")
    d["alert_gid"] = alert.get("gid")
    d["alert_signature_id"] = alert.get("signature_id")
    d["alert_rev"] = alert.get("rev")
    d["alert_signature"] = alert.get("signature")
    d["alert_category"] = alert.get("category")
    d["alert_severity"] = alert.get("severity")
    d["app_proto"] = event.get("app_proto")
    d["direction"] = event.get("direction")
    d["flow_pkts_toserver"] = flow.get("pkts_toserver")
    d["flow_pkts_toclient"] = flow.get("pkts_toclient")
    d["flow_bytes_toserver"] = flow.get("bytes_toserver")
    d["flow_bytes_toclient"] = flow.get("bytes_toclient")
    d["flow_start"] = flow.get("start")
    d["flow_src_ip"] = flow.get("src_ip")
    d["flow_dest_ip"] = flow.get("dest_ip")
    d["flow_src_port"] = flow.get("src_port")
    d["flow_dest_port"] = flow.get("dest_port")
    d["payload"] = event.get("payload")
    d["payload_printable"] = event.get("payload_printable")
    d["stream"] = event.get("stream")
    d["packet"] = event.get("packet")
    d["linktype"] = event.get("linktype")
    d["http_hostname"] = http.get("hostname")
    d["http_url"] = http.get("url")
    d["http_user_agent"] = http.get("http_user_agent")
    d["http_method"] = http.get("http_method")
    d["http_protocol"] = http.get("protocol")
    d["http_length"] = http.get("length")
    return d


events = []
with open("json/malicious_alerts.json", "r") as f:
    for line in f:
        obj = json.loads(line)
        if obj.get("event_type") == "alert":
            events.append(extract_event_fields(obj))
df_alerts = pd.DataFrame(events)
extra_cols = ["pcap_cnt", "x-zap-scan-id", "vuln_name"]
df_alerts_enriched = pd.merge(
    df_alerts, df_marked[extra_cols], on="pcap_cnt", how="left"
)
df_alerts_enriched["vuln_name"] = df_alerts_enriched["vuln_name"].fillna(
    "NORMAL"
)
df_marked_not_in_alerts = df_marked[
    ~df_marked["pcap_cnt"].isin(df_alerts["pcap_cnt"])
]
all_columns = list(df_marked.columns)
for col in df_alerts_enriched.columns:
    if col not in all_columns:
        all_columns.append(col)
for col in all_columns:
    if col not in df_marked_not_in_alerts.columns:
        df_marked_not_in_alerts[col] = None
    if col not in df_alerts_enriched.columns:
        df_alerts_enriched[col] = None
final = pd.concat(
    [df_alerts_enriched[all_columns], df_marked_not_in_alerts[all_columns]],
    ignore_index=True,
)
cols_to_clear = [
    "alert_action",
    "alert_gid",
    "alert_signature_id",
    "alert_rev",
    "alert_signature",
    "alert_severity",
]
final.loc[
    final["alert_category"].isna() | (final["alert_category"] == ""),
    cols_to_clear,
] = None
final = final.loc[:, ~final.columns.str.contains("^Unnamed")]
final.to_csv("./csv/marked.csv", index=False)
