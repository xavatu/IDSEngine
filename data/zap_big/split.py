import os
import re

import pandas as pd

import json

INPUT_PATH = "./json/zap.jsonl"
MAPPED_VULNS_PATH = "./csv/vulns_mapped.csv"  # твой mapping CSV
OUT_DIR = "./by_alias"
os.makedirs(OUT_DIR, exist_ok=True)

vulns_df = pd.read_csv(MAPPED_VULNS_PATH)
vulns_df["id"] = vulns_df["id"].astype(str)
id2alias = dict(zip(vulns_df["id"], vulns_df["alias"]))


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
            scan_id = extract_zap_scan_id(obj.get("payload_printable", ""))
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

print("Разделение по alias завершено!")
