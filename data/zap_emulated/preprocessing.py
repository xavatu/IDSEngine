import math
import os
from collections import Counter

import pandas as pd
from sklearn.preprocessing import LabelEncoder

from data import *

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

DATA_PATH = os.environ.get("DATA_PATH", "marked.csv")
df = pd.read_csv(DATA_PATH)
df[TARGET] = df[TARGET].fillna("NORMAL")

value_counts = df[TARGET].value_counts()
valid_labels = value_counts[value_counts >= 100].index
df = df[df[TARGET].isin(valid_labels)]

df = df[[TARGET] + FEATURES].dropna()


def apply_aliases():
    global df
    for new_label, old_labels in ALIASES.items():
        df[TARGET] = df[TARGET].replace(old_labels, new_label)


apply_aliases()

le_target = LabelEncoder()
X = df[NUMERIC_FEATURES].copy()
y = le_target.fit_transform(df[TARGET])


def _encode_categorial_feature(series: pd.Series) -> pd.Series:
    codes, _ = pd.factorize(series, sort=True)
    return pd.Series(codes, index=series.index, name=series.name)


def _encode_text_feature(series: pd.Series) -> pd.Series:
    return series.fillna("").str.len().astype(int)


def _string_entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    total = len(s)
    return -sum(
        (count / total) * math.log2(count / total) for count in counter.values()
    )


def extract_features():
    global X

    for col in CATEGORICAL_FEATURES:
        X[col] = _encode_categorial_feature(df[col])

    for col in TEXT_FEATURES:
        X[col + "_len"] = _encode_text_feature(df[col])
        X[col + "_entropy"] = df[col].fillna("").apply(_string_entropy)


extract_features()
