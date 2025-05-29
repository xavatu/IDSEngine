import math
import os
import re
from collections import Counter
from typing import Dict

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from data import *

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

DEFAULT_DATA_PATH = os.path.realpath("./by_alias/")
BATCH_SIZE = 10000


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    total = len(s)
    return -sum(
        (count / total) * math.log2(count / total) for count in counter.values()
    )


def encode_text_length(series: pd.Series):
    return series.fillna("").str.len().astype(np.int32)


def load_dataframe(path):
    all_batches = []
    files = sorted(os.listdir(path))
    for filename in files:
        filepath = os.path.join(path, filename)
        df = pd.read_json(filepath, lines=True, nrows=BATCH_SIZE)
        all_batches.append(df)
    df_raw = pd.concat(all_batches, ignore_index=True)

    df_enriched = TargetEnricher(ID2ALIASES, TARGET).fit_transform(df_raw)
    records = df_enriched.to_dict(orient="records")
    feats = []
    for event in records:
        http = event.get("http", {})
        flow = event.get("flow", {})
        row = {
            "src_ip": event.get("src_ip", ""),
            "src_port": event.get("src_port", ""),
            "dest_ip": event.get("dest_ip", ""),
            "dest_port": event.get("dest_port", ""),
            "proto": event.get("proto", "unknown"),
            "app_proto": event.get("app_proto", "unknown"),
            "http_method": http.get("http_method", "unknown"),
            "http_protocol": http.get("protocol", "unknown"),
            "flow_pkts_toserver": int(flow.get("pkts_toserver", 0)),
            "flow_pkts_toclient": int(flow.get("pkts_toclient", 0)),
            "flow_bytes_toserver": int(flow.get("bytes_toserver", 0)),
            "flow_bytes_toclient": int(flow.get("bytes_toclient", 0)),
            "http_length": int(http.get("length", 0)),
            "direction": event.get("direction", ""),
            "payload": event.get("payload", ""),
            "payload_printable": event.get("payload_printable", ""),
            "http_hostname": http.get("hostname", ""),
            "http_url": http.get("url", ""),
            "http_user_agent": http.get("http_user_agent", ""),
            "vuln_name": event.get("vuln_name", "NORMAL"),  # ключевая строка
        }
        feats.append(row)

    return pd.DataFrame(feats)


class FeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.label_encoders_: Dict[str, LabelEncoder] = {}

    def fit(self, X, y=None):  # noqa
        for col in CATEGORICAL_FEATURES:
            le = LabelEncoder()
            le.fit(X[col].fillna("unknown").astype(str))
            self.label_encoders_[col] = le
        return self

    def transform(self, X):
        feats = [X[NUMERIC_FEATURES].astype(np.float32).to_numpy()]

        cat_cols = []
        for col in CATEGORICAL_FEATURES:
            le = self.label_encoders_[col]
            cat_encoded = le.transform(X[col].fillna("unknown").astype(str))
            cat_cols.append(
                np.array(cat_encoded, dtype=np.int32).reshape(-1, 1)
            )
        if cat_cols:
            feats.append(np.hstack(cat_cols))

        text_len_cols = []
        text_entropy_cols = []
        for col in TEXT_FEATURES:
            text_len = encode_text_length(X[col])
            text_len_cols.append(
                np.array(text_len, dtype=np.float32).reshape(-1, 1)
            )

            entropy_col = X[col].fillna("").apply(string_entropy)
            entropy_col = np.array(entropy_col, dtype=np.float32).reshape(-1, 1)
            text_entropy_cols.append(entropy_col)

        if text_len_cols:
            feats.append(np.hstack(text_len_cols))
            feats.append(np.hstack(text_entropy_cols))

        return np.hstack(feats)

    def fit_transform(self, X, y=None, **kwargs):
        return self.fit(X, y).transform(X)


class TargetEnricher(BaseEstimator, TransformerMixin):
    def __init__(self, id2target, target_col):
        self.id2target = id2target
        self.target_col = target_col

    @staticmethod
    def extract_zap_scan_id(payload_printable):
        if not isinstance(payload_printable, str):
            return None
        payload_printable = payload_printable.strip()
        m = re.search(
            r"x-zap-scan-id:\s*([^\r\n]+)", payload_printable, re.IGNORECASE
        )
        return m.group(1).strip() if m else None

    def fit(self, X, y=None):  # noqa
        return self

    def transform(self, X):
        X = X.copy()
        X["x-zap-scan-id"] = X["payload_printable"].apply(
            self.extract_zap_scan_id
        )
        X[self.target_col] = (
            X["x-zap-scan-id"].map(self.id2target).fillna("NORMAL")
        )
        return X

    def fit_transform(self, X, y=None, **kwargs):
        X = self.fit(X, y).transform(X)
        return X


pipeline = Pipeline(
    [
        ("feature_extractor", FeatureExtractor()),
    ]
)
