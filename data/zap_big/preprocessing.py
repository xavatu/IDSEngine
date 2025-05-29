import os
import re

import numpy as np
import pandas as pd

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder, LabelEncoder

from data import (
    TARGET,
    NUMERIC_FEATURES,
    CATEGORICAL_FEATURES,
    TEXT_FEATURES,
)


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    import math

    counter = Counter(s)
    total = len(s)
    return -sum(
        (cnt / total) * math.log2(cnt / total) for cnt in counter.values()
    )


class FeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if isinstance(X, pd.DataFrame):
            records = X.to_dict(orient="records")
        else:
            records = X
        feats = []
        for event in records:
            http = event.get("http", {}) or {}
            flow = event.get("flow", {}) or {}
            row = {
                "src_ip": event.get("src_ip", ""),
                "src_port": event.get("src_port", ""),
                "dest_ip": event.get("dest_ip", ""),
                "dest_port": event.get("dest_port", ""),
                "proto": event.get("proto", "") or "unknown",
                "app_proto": event.get("app_proto", "") or "unknown",
                "http_method": http.get("http_method", "") or "unknown",
                "http_protocol": http.get("protocol", "") or "unknown",
                "flow_pkts_toserver": int(flow.get("pkts_toserver", 0) or 0),
                "flow_pkts_toclient": int(flow.get("pkts_toclient", 0) or 0),
                "flow_bytes_toserver": int(flow.get("bytes_toserver", 0) or 0),
                "flow_bytes_toclient": int(flow.get("bytes_toclient", 0) or 0),
                "http_length": int(http.get("length", 0) or 0),
                "direction": event.get("direction", ""),
                "payload": event.get("payload", "") or "",
                "payload_printable": event.get("payload_printable", "") or "",
                "http_hostname": http.get("hostname", "") or "",
                "http_url": http.get("url", "") or "",
                "http_user_agent": http.get("http_user_agent", "") or "",
            }
            feats.append(row)
        return pd.DataFrame(feats)


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

    def fit(self, X, y=None):
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


class TextStatsTransformer(BaseEstimator, TransformerMixin):
    def __init__(self, text_columns):
        self.text_columns = text_columns

    def fit(self, X, y=None):
        return self

    def transform(self, x: pd.DataFrame):
        feats = []
        for col in self.text_columns:
            col_data = x[col].fillna("")
            feats.append(col_data.str.len().to_numpy()[:, None])
            feats.append(col_data.apply(string_entropy).to_numpy()[:, None])
        return np.hstack(feats)

    def get_feature_names_out(self):
        names = []
        for col in self.text_columns:
            names.extend([f"{col}_len", f"{col}_entropy"])
        return np.array(names)


def build_enrichment_pipeline(id2target, target_col):
    return Pipeline(
        [
            ("feature_extractor", FeatureExtractor()),
            ("target_enricher", TargetEnricher(id2target, target_col)),
        ]
    )


def build_ml_preprocessor(
    numeric_features, categorical_features, text_features
):
    numeric_pipe = Pipeline(
        steps=[("imputer", SimpleImputer(strategy="median"))]
    )
    categorical_pipe = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(strategy="constant", fill_value="unknown"),
            ),
            (
                "encoder",
                OrdinalEncoder(
                    handle_unknown="use_encoded_value", unknown_value=-1
                ),
            ),
        ]
    )
    text_pipe = Pipeline(
        steps=[("stats", TextStatsTransformer(text_columns=text_features))]
    )

    return ColumnTransformer(
        transformers=[
            ("num", numeric_pipe, numeric_features),
            ("cat", categorical_pipe, categorical_features),
            ("txt", text_pipe, text_features),
        ],
        remainder="drop",
    )


DATA_PATH = "./json/zap.jsonl"
MAPPED_VULNS_PATH = "./csv/vulns_mapped.csv"

vulns_df = pd.read_csv(MAPPED_VULNS_PATH)
vulns_df["id"] = vulns_df["id"].astype(str)
id2target = dict(zip(vulns_df["id"], vulns_df["alias"]))
enrichment_pipeline = build_enrichment_pipeline(id2target, TARGET)
ml_preproc = build_ml_preprocessor(
    NUMERIC_FEATURES, CATEGORICAL_FEATURES, TEXT_FEATURES
)

BATCH_SIZE = 10000
ALIAS_DIR = "./by_alias"


# Склеиваем всё в один DataFrame (если хватает памяти)
all_batches = []
files = sorted(os.listdir(ALIAS_DIR))
for fname in files:
    path = os.path.join(ALIAS_DIR, fname)
    df = pd.read_json(path, lines=True, nrows=BATCH_SIZE)
    all_batches.append(df)
    print(fname, df.shape)
df_raw = pd.concat(all_batches, ignore_index=True)
df_enriched = enrichment_pipeline.fit_transform(df_raw)

X = ml_preproc.fit_transform(df_enriched)

le_target = LabelEncoder()
y = le_target.fit_transform(df_enriched[TARGET])
label_encoders = None
