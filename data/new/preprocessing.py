import math
import os
import re
import string
from collections import Counter
from enum import IntEnum
from typing import List, Dict, Union

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

ID2ALIASES = {
    "0": "CWE-200: Information Exposure",
    "6": "CWE-22: Path Traversal",
    "6-1": "CWE-22: Path Traversal",
    "6-2": "CWE-22: Path Traversal",
    "6-3": "CWE-22: Path Traversal",
    "6-4": "CWE-22: Path Traversal",
    "6-5": "CWE-22: Path Traversal",
    "7": "CWE-98: Remote File Inclusion",
    "10033": "CWE-200: Information Exposure",
    "10045": "CWE-200: Information Exposure",
    "10045-1": "CWE-200: Information Exposure",
    "20017": "CWE-200: Information Exposure",
    "20018": "CWE-20: Input Validation",
    "20019": "CWE-601: Open Redirect",
    "20019-1": "CWE-601: Open Redirect",
    "20019-2": "CWE-601: Open Redirect",
    "20019-3": "CWE-601: Open Redirect",
    "20019-4": "CWE-601: Open Redirect",
    "30001": "CWE-120: Buffer Overflow",
    "30002": "CWE-134: Format String",
    "40003": "CWE-113: CRLF Injection",
    "40008": "CWE-472: Parameter Tampering",
    "40009": "CWE-97: SSI",
    "40012": "CWE-79: XSS",
    "40016": "CWE-79: XSS",
    "40017": "CWE-79: XSS",
    "40018": "CWE-89: SQL Injection",
    "40019": "CWE-89: SQL Injection",
    "40020": "CWE-89: SQL Injection",
    "40021": "CWE-89: SQL Injection",
    "40022": "CWE-89: SQL Injection",
    "40024": "CWE-89: SQL Injection",
    "40027": "CWE-89: SQL Injection",
    "40028": "CWE-200: Information Exposure",
    "40029": "CWE-200: Information Exposure",
    "40032": "CWE-200: Information Exposure",
    "40034": "CWE-200: Information Exposure",
    "40035": "CWE-200: Information Exposure",
    "40042": "CWE-200: Information Exposure",
    "40045": "CWE-78: OS Command Injection",
    "90017": "CWE-91: XML Injection",
    "90019": "CWE-94: Code Injection",
    "90020": "CWE-78: OS Command Injection",
    "90021": "CWE-91: XML Injection",
    "90034": "CWE-200: Information Exposure",
    "90035": "CWE-94: Code Injection",
}

TARGET = "vuln_name"


class HTTPMethod(IntEnum):
    GET = 0
    POST = 1
    PUT = 2
    DELETE = 3
    PATCH = 4
    OPTIONS = 5
    HEAD = 6
    TRACE = 7
    CONNECT = 8
    UNKNOWN = 9

    @classmethod
    def from_string(cls, s: str) -> int:
        try:
            return cls[s.upper()]
        except KeyError:
            return cls.UNKNOWN


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    total = len(s)
    counts = Counter(s)
    return -sum((v / total) * math.log2(v / total) for v in counts.values())


def noise_ratio(s: str) -> float:
    if not s:
        return 0.0
    clean_chars = string.ascii_letters + string.digits
    noisy_count = sum(1 for c in s if c not in clean_chars)
    return noisy_count / len(s)


class HTTPFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.common_request_headers = [
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language",
            "connection",
            "pragma",
            "cache-control",
            "x-zap-scan-id",
            "content-length",
            "content-type",
        ]
        self.common_response_headers = [
            "server",
            "date",
            "content-type",
            "content-length",
            "connection",
        ]

    def fit(self, X, y=None):
        return self

    def transform(
        self, X: Union[pd.DataFrame, List[Dict]]
    ) -> List[Dict[str, float]]:
        if isinstance(X, pd.DataFrame):
            records = X.to_dict(orient="records")
        else:
            records = X

        feature_dicts = []
        for event in records:
            features = {}
            http = event.get("http", {})
            req_headers = http.get("request_headers", [])

            if "x-zap-scan-id" in req_headers:
                req_headers.remove("x-zap-scan-id")

            if "X-Schemathesis-TestCaseId" in req_headers:
                req_headers.remove("X-Schemathesis-TestCaseId")

            res_headers = http.get("response_headers", [])

            features["http_status"] = http.get("status", 0)
            method = http.get("http_method", "")
            features["http_method"] = HTTPMethod.from_string(method)

            url = http.get("url", "")
            features["http_url_len"] = len(url)
            features["http_url_entropy"] = string_entropy(url)
            features["http_url_depth"] = url.count("/")
            features["http_url_noise_ratio"] = noise_ratio(url)

            # Request Headers
            req_keys = []
            req_values = []
            has_cookie = False

            for h in req_headers:
                if isinstance(h, dict):
                    name = h.get("name", "").lower()
                    value = h.get("value", "")
                    req_keys.append(name)
                    req_values.append(value)
                    if name == "cookie":
                        has_cookie = True

            features["http_req_headers_count"] = len(req_keys)
            value_lengths = [len(v) for v in req_values if isinstance(v, str)]
            features["http_req_headers_avg_value_len"] = (
                np.mean(value_lengths) if value_lengths else 0.0
            )
            features["http_req_has_cookie"] = int(has_cookie)

            # Response Headers
            res_keys = []
            res_values = []

            for h in res_headers:
                if isinstance(h, dict):
                    name = h.get("name", "").lower()
                    value = h.get("value", "")
                    res_keys.append(name)
                    res_values.append(value)

            features["http_res_headers_count"] = len(res_keys)
            value_lengths = [len(v) for v in res_values if isinstance(v, str)]
            features["http_res_headers_avg_value_len"] = (
                np.mean(value_lengths) if value_lengths else 0.0
            )
            feature_dicts.append(features)

        return feature_dicts


class FlowFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(
        self, X: Union[pd.DataFrame, List[Dict]]
    ) -> List[Dict[str, float]]:
        if isinstance(X, pd.DataFrame):
            records = X.to_dict(orient="records")
        else:
            records = X

        feature_dicts = []
        for event in records:
            flow = event.get("flow", {})
            if isinstance(flow, float) and pd.isna(flow):
                flow = {}
            features = {
                # "flow_pkts_toserver": flow.get("pkts_toserver", 0),
                # "flow_pkts_toclient": flow.get("pkts_toclient", 0),
                "flow_bytes_toserver": flow.get("bytes_toserver", 0),
                "flow_bytes_toclient": flow.get("bytes_toclient", 0),
            }
            feature_dicts.append(features)

        return feature_dicts


class FileFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(
        self, X: Union[pd.DataFrame, List[Dict]]
    ) -> List[Dict[str, float]]:
        if isinstance(X, pd.DataFrame):
            records = X.to_dict(orient="records")
        else:
            records = X

        feature_dicts = []
        for event in records:
            files = event.get("files", [])
            if not isinstance(files, list):
                files = [files]

            features = {
                "file_count": len(files),
                "file_total_size": sum(
                    f.get("size", 0) for f in files if isinstance(f, dict)
                ),
            }
            feature_dicts.append(features)

        return feature_dicts


class PayloadFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(
        self, X: Union[pd.DataFrame, List[Dict]]
    ) -> List[Dict[str, float]]:
        if isinstance(X, pd.DataFrame):
            records = X.to_dict(orient="records")
        else:
            records = X

        def classify_direction(payload: str) -> str:
            upper = payload.upper()
            if any(
                upper.startswith(m)
                for m in ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ")
            ):
                return "payload_to_server"
            if (
                upper.startswith("HTTP/1.")
                or "SERVER:" in upper
                or "200 OK" in upper
            ):
                return "payload_to_client"
            return None  # fallback — не будем использовать

        feature_dicts = []
        for event in records:
            by_dir = {
                "payload_to_server": [],
                "payload_to_client": [],
            }

            payloads = event.get("payload_printable", [])
            if isinstance(payloads, str):
                payloads = [payloads]
            if isinstance(payloads, float) and pd.isna(payloads):
                payloads = []
            for p in payloads:
                if not isinstance(p, str):
                    continue
                label = classify_direction(p)
                if label:
                    by_dir[label].append(p)

            features = {}
            for key in ("payload_to_server", "payload_to_client"):
                values = by_dir[key]
                lengths = [len(v) for v in values]
                entropies = [string_entropy(v) for v in values]
                noises = [noise_ratio(v) for v in values]

                features[f"{key}_avg_len"] = (
                    float(np.mean(lengths)) if lengths else 0.0
                )
                features[f"{key}_avg_entropy"] = (
                    float(np.mean(entropies)) if entropies else 0.0
                )
                features[f"{key}_avg_noise"] = (
                    float(np.mean(noises)) if noises else 0.0
                )

            feature_dicts.append(features)

        return feature_dicts


from sklearn.base import BaseEstimator, TransformerMixin


class CombinedFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.extractors = [
            ("http", HTTPFeatureExtractor()),
            ("flow", FlowFeatureExtractor()),
            # ("file", FileFeatureExtractor()),
            ("payload", PayloadFeatureExtractor()),
        ]
        self.label_encoders_ = {}

    def fit(self, X, y=None):
        for _, extractor in self.extractors:
            extractor.fit(X, y)
        return self

    def transform(self, X: Union[pd.DataFrame, List[Dict]]) -> pd.DataFrame:
        all_feature_dicts: List[Dict[str, float]] = []

        if isinstance(X, pd.DataFrame):
            records = X.to_dict(orient="records")
        else:
            records = X

        for record in records:
            merged = {}
            for _, extractor in self.extractors:
                feats = extractor.transform([record])[
                    0
                ]  # each returns List[Dict]
                merged.update(feats)
            all_feature_dicts.append(merged)

        return pd.DataFrame(all_feature_dicts)


extractor = CombinedFeatureExtractor()
df_features = extractor.transform(
    [
        {
            "timestamp": [
                "2025-05-29T22:28:25.509910+0000",
                "2025-05-29T22:28:25.507633+0000",
            ],
            "flow_id": 490741930586507,
            "event_type": ["http", "alert"],
            "src_ip": "127.0.0.1",
            "src_port": 57866,
            "dest_ip": "127.0.0.1",
            "dest_port": 8000,
            "proto": "TCP",
            "pkt_src": "wire/pcap",
            "tx_id": 0,
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 999990,
                "rev": 1,
                "signature": "pass through HTTP GET",
                "category": "Http Pass Through",
                "severity": 0,
            },
            "http": {
                "hostname": "localhost",
                "http_port": 8000,
                "url": "/",
                "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "http_method": "GET",
                "protocol": "HTTP/1.1",
                "length": 42,
                "http_content_type": "application/json",
                "status": 200,
                "request_headers": [
                    {"name": "host", "value": "localhost:8000"},
                    {
                        "name": "user-agent",
                        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    },
                    {"name": "pragma", "value": "no-cache"},
                    {"name": "cache-control", "value": "no-cache"},
                ],
                "response_headers": [
                    {
                        "name": "Server",
                        "value": "Werkzeug/3.1.3 Python/3.13.3+",
                    },
                    {"name": "Date", "value": "Thu, 29 May 2025 22:28:25 GMT"},
                    {"name": "Content-Type", "value": "application/json"},
                    {"name": "Content-Length", "value": "42"},
                    {"name": "Connection", "value": "close"},
                ],
            },
            "app_proto": "http",
            "direction": "to_server",
            "flow": {
                "pkts_toserver": 3,
                "pkts_toclient": 1,
                "bytes_toserver": 372,
                "bytes_toclient": 60,
                "start": "2025-05-29T22:28:25.507475+0000",
                "src_ip": "127.0.0.1",
                "dest_ip": "127.0.0.1",
                "src_port": 57866,
                "dest_port": 8000,
            },
            "payload_printable": "GET / HTTP/1.1\r\nhost: localhost:8000\r\nuser-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\npragma: no-cache\r\ncache-control: no-cache\r\n\r\n",
            "stream": 1,
        }
    ]
)

print(df_features.to_dict())
df_features = extractor.transform(
    [
        {
            "timestamp": [
                "2025-05-29T22:28:25.572125+0000",
                "2025-05-29T22:28:25.572782+0000",
                "2025-05-29T22:28:25.572919+0000",
            ],
            "flow_id": 486399875581157,
            "event_type": ["http", "alert"],
            "src_ip": "127.0.0.1",
            "src_port": [58966, 8000],
            "dest_ip": "127.0.0.1",
            "dest_port": [58966, 8000],
            "proto": "TCP",
            "pkt_src": "wire/pcap",
            "tx_id": 0,
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2101201,
                "rev": 12,
                "signature": "GPL WEB_SERVER 403 Forbidden",
                "category": "Attempted Information Leak",
                "severity": 2,
                "metadata": {
                    "created_at": ["2010_09_23"],
                    "signature_severity": ["Unknown"],
                    "updated_at": ["2024_03_08"],
                },
            },
            "http": {
                "hostname": "localhost",
                "http_port": 8000,
                "url": "/api/v3/notifications/threads/10",
                "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "http_method": "GET",
                "protocol": "HTTP/1.1",
                "length": 5,
                "http_content_type": "application/json",
                "status": 403,
                "request_headers": [
                    {"name": "host", "value": "localhost:8000"},
                    {
                        "name": "user-agent",
                        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    },
                    {"name": "pragma", "value": "no-cache"},
                    {"name": "cache-control", "value": "no-cache"},
                ],
                "response_headers": [
                    {
                        "name": "Server",
                        "value": "Werkzeug/3.1.3 Python/3.13.3+",
                    },
                    {"name": "Date", "value": "Thu, 29 May 2025 22:28:25 GMT"},
                    {"name": "Content-Type", "value": "application/json"},
                    {"name": "Content-Length", "value": "5"},
                    {"name": "Connection", "value": "close"},
                ],
            },
            "app_proto": "http",
            "direction": ["to_client", "to_server"],
            "flow": {
                "pkts_toserver": 3,
                "pkts_toclient": 3,
                "bytes_toserver": 403,
                "bytes_toclient": 336,
                "start": "2025-05-29T22:28:25.572000+0000",
                "src_ip": "127.0.0.1",
                "dest_ip": "127.0.0.1",
                "src_port": 58966,
                "dest_port": 8000,
            },
            "payload_printable": [
                "GET /api/v3/notifications/threads/10 HTTP/1.1\r\nhost: localhost:8000\r\nuser-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\npragma: no-cache\r\ncache-control: no-cache\r\n\r\n",
                "HTTP/1.1 403 FORBIDDEN\r\nServer: Werkzeug/3.1.3 Python/3.13.3+\r\nDate: Thu, 29 May 2025 22:28:25 GMT\r\nContent-Type: application/json\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
            ],
            "stream": 1,
        }
    ]
)
print(df_features.to_dict())
FEATURES = [
    "http_status",
    "http_method",
    "http_url_len",
    "http_url_entropy",
    "http_url_depth",
    "http_url_noise_ratio",
    "http_req_headers_count",
    "http_req_headers_avg_value_len",
    "http_req_has_cookie",
    "http_res_headers_count",
    "http_res_headers_avg_value_len",
    # "flow_pkts_toserver",
    # "flow_pkts_toclient",
    "flow_bytes_toserver",
    "flow_bytes_toclient",
    # "file_count",
    # "file_total_size",
    "payload_to_server_avg_len",
    "payload_to_server_avg_entropy",
    "payload_to_server_avg_noise",
    "payload_to_client_avg_len",
    "payload_to_client_avg_entropy",
    "payload_to_client_avg_noise",
]

DEFAULT_DATA_PATH = os.path.realpath("./alias/")
BATCH_SIZE = 10000


def extract_zap_scan_id(event: Dict | pd.Series) -> str | None:
    payloads = event.get("payload_printable", [])
    if isinstance(payloads, str):
        payloads = [payloads]
    if isinstance(payloads, float) and pd.isna(payloads):
        payloads = []
    for payload in payloads:
        if isinstance(payload, str):
            match = re.search(
                r"x-zap-scan-id[:=]\s*(\d{1,6})", payload, re.IGNORECASE
            )
            if match:
                return match.group(1)

    headers = event.get("http", {}).get("request_headers", [])
    for h in headers:
        if isinstance(h, dict) and h.get("name", "").lower() == "x-zap-scan-id":
            return h.get("value", None)

    return None


def load_dataframe(path: str) -> pd.DataFrame:
    all_batches = []
    files = sorted(os.listdir(path))

    for filename in files:
        filepath = os.path.join(path, filename)
        try:
            df = pd.read_json(filepath, lines=True, nrows=BATCH_SIZE)
            print(filename, df.shape)
            all_batches.append(df)
        except ValueError:
            continue

    df_raw = pd.concat(all_batches, ignore_index=True)

    df_raw["zap_scan_id"] = df_raw.apply(extract_zap_scan_id, axis=1)
    df_raw["vuln_name"] = df_raw["zap_scan_id"].map(ID2ALIASES).fillna("NORMAL")
    print(df_raw)
    return df_raw


pipeline = Pipeline(
    [
        ("feature_extractor", CombinedFeatureExtractor()),
        (
            "to_dataframe",
            FunctionTransformer(validate=False, func=lambda X: pd.DataFrame(X)),
        ),
        (
            "select_features",
            FunctionTransformer(validate=False, func=lambda df: df[FEATURES]),
        ),
    ]
)
