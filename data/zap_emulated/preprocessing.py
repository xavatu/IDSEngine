import os

import pandas as pd
from sklearn.preprocessing import LabelEncoder

from data import *

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

DATA_PATH = os.environ.get("DATA_PATH", "marked.csv")
df = pd.read_csv(DATA_PATH)
df[TARGET] = df[TARGET].fillna("NORMAL")
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


def extract_features():
    global X

    for col in CATEGORICAL_FEATURES:
        X[col] = _encode_categorial_feature(df[col])

    for col in TEXT_FEATURES:
        X[col + "_len"] = _encode_text_feature(df[col])


extract_features()
