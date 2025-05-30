import json
import os
import re

import pandas as pd

INPUT_PATH = "./unix_socket.jsonl"
MAPPED_VULNS_PATH = "../zap_big/csv/vulns_mapped.csv"  # твой mapping CSV
OUT_DIR = "./split"
os.makedirs(OUT_DIR, exist_ok=True)

vulns_df = pd.read_csv(MAPPED_VULNS_PATH)
vulns_df["id"] = vulns_df["id"].astype(str)
id2alias = dict(zip(vulns_df["id"], vulns_df["alias"]))
print(id2alias)


def extract_zap_scan_id(payload_printable):
    if not isinstance(payload_printable, str):
        return None
    match = re.search(
        r"x-zap-scan-id[:=] (\d{1,6})", payload_printable, re.IGNORECASE
    )
    if match:
        return match.group(1)
    return None


writers = {}

with open(INPUT_PATH, "r", encoding="utf-8") as fin:
    for line in fin:
        try:
            obj = json.loads(line)
            payload = obj.get("payload_printable", "")
            scan_id = None
            if isinstance(obj, dict):
                scan_id = extract_zap_scan_id(payload)
            if isinstance(payload, list):
                for el in payload:
                    scan_id = extract_zap_scan_id(el)
                    if scan_id:
                        break
            if not scan_id:
                request_headers = obj.get("http", {}).get("request_headers", [])
                for header in request_headers:
                    if header["name"] == "x-zap-scan-id":
                        scan_id = header["value"]
                        break
            alias = id2alias.get(scan_id, None) if scan_id else "NORMAL"
        except Exception as e:
            raise
        if alias is None:
            continue
        if alias not in writers:
            fname = os.path.join(OUT_DIR, f"{alias}.jsonl")
            writers[alias] = open(fname, "w", encoding="utf-8")
        writers[alias].write(line)

for w in writers.values():
    w.close()
