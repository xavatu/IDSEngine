import pandas as pd

import json

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)


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
with open("./json/benign_alerts.json", "r") as f:
    for line in f:
        obj = json.loads(line)
        if obj.get("event_type") == "alert":
            events.append(extract_event_fields(obj))
df_alerts = pd.DataFrame(events)

events = []
with open("./json/benign_logs.json", "r") as f:
    for line in f:
        obj = json.loads(line)
        if obj.get("event_type") == "alert":
            events.append(extract_event_fields(obj))
df_logs = pd.DataFrame(events)

df_logs_not_in_alerts = df_logs[
    ~df_logs["pcap_cnt"].isin(df_alerts["pcap_cnt"])
]
df_merged = pd.concat(
    [df_logs_not_in_alerts, df_alerts],
    ignore_index=True,
)
df_merged.to_csv("./csv/benign.csv")
