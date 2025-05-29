import argparse
import importlib
import os
import sys
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    accuracy_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

parser = argparse.ArgumentParser()
parser.add_argument(
    "--model_module",
    required=True,
    help="Импорт-путь к файлу, где объявлен `model`",
)
parser.add_argument(
    "--dataset_module",
    required=True,
    help="Полный или относительный путь к каталогу с датасетом (должен содержать preprocessing.py)",
)
args, unknown = parser.parse_known_args()

module = importlib.import_module(args.model_module)

dataset_module = Path(args.dataset_module).resolve()
DATASET_NAME = dataset_module.name


def import_preprocessed_dataset():
    global prep

    @contextmanager
    def import_from(dir_path: Path):
        prev_cwd = Path.cwd()
        prev_path0 = sys.path[0]

        os.chdir(dir_path)
        sys.path.insert(0, str(dir_path))
        try:
            yield
        finally:
            os.chdir(prev_cwd)
            sys.path.pop(0)
            if prev_path0 != sys.path[0]:
                sys.path.insert(0, prev_path0)

    with import_from(dataset_module):
        prep = importlib.import_module("preprocessing")


import_preprocessed_dataset()
df = prep.load_dataframe(prep.DEFAULT_DATA_PATH)
X = prep.pipeline.fit_transform(df)

le_target = LabelEncoder()
y = le_target.fit_transform(df[prep.TARGET])

label_encoders = {}
fe = prep.pipeline.named_steps.get("feature_extractor")
label_encoders = fe.label_encoders_


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

model = module.model
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

# ATTACK PREDICTION (VULN/NORMAL)
attack_y_test = y_test != le_target.transform(["NORMAL"])
attack_y_pred = y_pred != le_target.transform(["NORMAL"])
cm_bin = confusion_matrix(attack_y_test, attack_y_pred, labels=[False, True])
realP = np.sum(attack_y_test == True)
realN = np.sum(attack_y_test == False)
TN, FP, FN, TP = cm_bin.ravel()
precision, recall, fscore, support = precision_recall_fscore_support(
    attack_y_test, attack_y_pred, average="binary", zero_division=0
)
acc = accuracy_score(attack_y_test, attack_y_pred)
metrics = [
    [
        TP,
        FN,
        realP,
        FP,
        TN,
        realN,
        precision,
        recall,
        fscore,
        support,
        acc,
    ]
]
columns = [
    "TP",
    "FN",
    "realP",
    "FP",
    "TN",
    "realN",
    "precision",
    "recall",
    "fscore",
    "support",
    "acc",
]
metrics_df = pd.DataFrame(metrics, columns=columns)
metrics_df.to_csv(
    f"./stats/{DATASET_NAME}_attack_prediction.csv",
    index=False,
)

# ATTACK CLASSIFICATION
classes = le_target.classes_
malicious_idx = [i for i, label in enumerate(classes)]
malicious_labels = [classes[i] for i in malicious_idx]
malicious_mask = np.isin(y_test, malicious_idx) | np.isin(y_pred, malicious_idx)
malicious_y_test = y_test[malicious_mask]
malicious_y_pred = y_pred[malicious_mask]
cm = confusion_matrix(malicious_y_test, malicious_y_pred, labels=malicious_idx)
metrics_df = pd.DataFrame(
    classification_report(
        malicious_y_test,
        malicious_y_pred,
        labels=malicious_idx,
        target_names=malicious_labels,
        zero_division=0,
        output_dict=True,
    )
).T
metrics_df.to_csv(
    f"./stats/{DATASET_NAME}_attack_classification.csv",
    index=True,
)

# ATTACK CLASSIFICATION ERRORS
classification_pairs = [
    (classes[t], classes[p])
    for t, p in zip(malicious_y_test, malicious_y_pred)
    if t != p
]
classification_errors_counter = Counter(classification_pairs)
classification_errors_df = (
    pd.DataFrame(
        [
            (true, pred, cnt)
            for (true, pred), cnt in classification_errors_counter.items()
        ],
        columns=["true_label", "pred_label", "count"],
    )
    .sort_values("count", ascending=False)
    .reset_index(drop=True)
)
classification_errors_df.to_csv(
    f"./stats/{DATASET_NAME}_attack_misclassification.csv",
    index=False,
)

artifacts = {
    "model": model,
    "label_encoders": label_encoders,
    "le_target": le_target,
}
joblib.dump(artifacts, "./model_artifacts.pkl")
