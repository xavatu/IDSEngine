import pandas as pd

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
)

df_marked = pd.read_csv("./csv/marked.csv")

df_marked["is_attack_true"] = df_marked["vuln_name"] != "NORMAL"
df_marked["is_attack_pred"] = df_marked["alert_category"].notna()

y_true = df_marked["is_attack_true"]
y_pred = df_marked["is_attack_pred"]

cm_bin = confusion_matrix(y_true, y_pred, labels=[False, True])
tn, fp, fn, tp = cm_bin.ravel()
realP = (y_true == True).sum()
realN = (y_true == False).sum()
precision, recall, fscore, support = precision_recall_fscore_support(
    y_true, y_pred, average="binary", zero_division=0
)
acc = accuracy_score(y_true, y_pred)

metrics_bin = [
    [
        tp,
        fn,
        realP,
        fp,
        tn,
        realN,
        precision,
        recall,
        fscore,
        support,
        acc,
    ]
]
columns_bin = [
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
metrics_bin_df = pd.DataFrame(metrics_bin, columns=columns_bin)
metrics_bin_df.to_csv("./stats/suricata_attack_detection.csv", index=False)

df_marked["is_attack"] = (df_marked["vuln_name"] != "NORMAL").astype(bool)
df_marked["is_detected"] = (df_marked["alert_category"].notna()).astype(bool)

results = []

for vuln in sorted(df_marked["vuln_name"].unique()):
    mask = df_marked["vuln_name"] == vuln
    if vuln == "NORMAL":
        y_true = ~df_marked["is_attack"]
        y_pred = ~df_marked["is_detected"]
    else:
        y_true = df_marked["is_attack"][mask].values
        y_pred = df_marked["is_detected"][mask].values
    tp = (y_true & y_pred).sum()
    fn = (y_true & ~y_pred).sum()
    fp = (~y_true & y_pred).sum()
    tn = (~y_true & ~y_pred).sum()

    support = len(y_true)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
    f1 = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0
    )

    results.append(
        {
            "vuln_name": vuln,
            "TP": tp,
            "FN": fn,
            "FP": fp,
            "TN": tn,
            "support": support,
            "precision": precision,
            "recall": recall,
            "f1-score": f1,
            "accuracy": accuracy,
        }
    )

df_results = pd.DataFrame(results)
df_results.to_csv("./stats/suricata_attack_classification.csv", index=False)
print(df_results)
print("False Positives per class:")
fp_normal = df_marked[
    (df_marked["vuln_name"] == "NORMAL") & (df_marked["is_detected"])
]
print(fp_normal)
