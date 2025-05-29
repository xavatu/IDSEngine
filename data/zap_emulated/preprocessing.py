import math
import os
from typing import Dict

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from data import *

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

DEFAULT_DATA_PATH = os.path.realpath("./csv/marked.csv")
MIN_SAMPLES_PER_LABEL = 100


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
    df = pd.read_csv(path)
    df[TARGET] = df[TARGET].fillna("NORMAL")

    for new_label, old_labels in ALIASES.items():
        df[TARGET] = df[TARGET].replace(old_labels, new_label)

    value_counts = df[TARGET].value_counts()
    valid_labels = value_counts[value_counts >= MIN_SAMPLES_PER_LABEL].index
    df = df[df[TARGET].isin(valid_labels)]
    df = df[[TARGET] + FEATURES].dropna()

    return df.reset_index(drop=True)


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


pipeline = Pipeline(
    [
        ("feature_extractor", FeatureExtractor()),
    ]
)
