import math
from collections import Counter

import numpy as np

from .data import CATEGORICAL_FEATURES

feature_columns = [
    "flow_pkts_toserver",
    "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
    "http_length",
    "proto",
    "app_proto",
    "http_method",
    "http_protocol",
    "payload_len",
    "payload_entropy",
    "payload_printable_len",
    "payload_printable_entropy",
    "http_hostname_len",
    "http_hostname_entropy",
    "http_url_len",
    "http_url_entropy",
    "http_user_agent_len",
    "http_user_agent_entropy",
]


def _string_entropy(s):
    if not s:
        return 0.0
    counter = Counter(s)
    total = len(s)
    return -sum(
        (count / total) * math.log2(count / total) for count in counter.values()
    )


def extract_features(event, label_encoders=None):
    http = event.get("http", {}) or {}
    payload = event.get("payload", "") or ""
    payload_printable = event.get("payload_printable", "") or ""

    feat = {
        "flow_pkts_toserver": int(
            event.get("flow", {}).get("pkts_toserver", 0)
        ),
        "flow_pkts_toclient": int(
            event.get("flow", {}).get("pkts_toclient", 0)
        ),
        "flow_bytes_toserver": int(
            event.get("flow", {}).get("bytes_toserver", 0)
        ),
        "flow_bytes_toclient": int(
            event.get("flow", {}).get("bytes_toclient", 0)
        ),
        "http_length": int(http.get("length", 0) or 0),
        "proto": event.get("proto", "") or "unknown",
        "app_proto": event.get("app_proto", "") or "unknown",
        "http_method": http.get("http_method", "") or "unknown",
        "http_protocol": http.get("protocol", "") or "unknown",
        "payload_len": int(len(payload)),
        "payload_entropy": float(_string_entropy(payload)),
        "payload_printable_len": int(len(payload_printable)),
        "payload_printable_entropy": float(_string_entropy(payload_printable)),
        "http_hostname_len": int(len(http.get("hostname", "") or "")),
        "http_hostname_entropy": float(
            _string_entropy(http.get("hostname", "") or "")
        ),
        "http_url_len": int(len(http.get("url", "") or "")),
        "http_url_entropy": float(_string_entropy(http.get("url", "") or "")),
        "http_user_agent_len": int(len(http.get("http_user_agent", "") or "")),
        "http_user_agent_entropy": float(
            _string_entropy(http.get("http_user_agent", "") or "")
        ),
    }

    if label_encoders:
        for col in CATEGORICAL_FEATURES:
            le = label_encoders.get(col)
            v = feat[col]
            if le:
                if v not in le.classes_:
                    if "unknown" not in le.classes_:
                        le.classes_ = np.append(le.classes_, "unknown")
                    v = "unknown"
                feat[col] = int(le.transform([v])[0])
            else:
                feat[col] = -1

    return {col: feat[col] for col in feature_columns}
