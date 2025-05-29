from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 0)
pd.set_option("display.max_colwidth", None)

from matplotlib.colors import Normalize

DATASET_NAME = "zap_big"
MODELS_ROOT = Path("./")
MODEL_EXCLUDE = ["naive_bayes", "logistic_regression"]

all_dfs = []
for model_dir in MODELS_ROOT.iterdir():
    csv_path = model_dir / "stats" / f"{DATASET_NAME}_attack_classification.csv"
    if model_dir.name in MODEL_EXCLUDE:
        continue
    if csv_path.is_file():
        df = pd.read_csv(csv_path, index_col=0)
        df = df[["precision", "recall", "f1-score"]]
        df["model"] = model_dir.name
        df["class"] = df.index
        all_dfs.append(df.reset_index(drop=True))

existing_classes = set()
for df_model in all_dfs:
    existing_classes.update(df_model["class"].unique())

# df = pd.read_csv(
#     f"../data/{DATASET_NAME}/stats/suricata_attack_classification.csv",
#     index_col=0,
# )
# df = df[["precision", "recall", "f1-score"]]
# df["model"] = "suricata"
# df["class"] = df.index
#
# for cls in existing_classes:
#     if cls not in df["class"].values:
#         df.loc[cls] = [0.0, 0.0, 0.0, "suricata", cls]
#
# df = df[df["class"].isin(existing_classes)]
# all_dfs.append(df)

full_df = pd.concat(all_dfs, ignore_index=True)

aux_labels = ("NORMAL", "accuracy", "weighted avg", "macro avg")
primary_classes = sorted(
    [cls for cls in full_df["class"].unique() if cls not in aux_labels]
)
classes = primary_classes[::-1] + list(aux_labels)[::-1]
metrics = ["precision", "recall", "f1-score"]
models = (
    full_df[full_df["class"] == "weighted avg"]
    .sort_values(by="recall", ascending=False)["model"]
    .values
)

columns_ordered = []
for i, model in enumerate(models):
    for metric in metrics:
        columns_ordered.append(f"{metric.capitalize()}:{model}")
    if i < len(models) - 1:
        columns_ordered.append(f"SEP{i}")

data = []
for cls in classes:
    row = {}
    for col in columns_ordered:
        if col.startswith("SEP"):
            row[col] = np.nan
        else:
            metric, model = col.split(":")
            value = full_df[
                (full_df["model"] == model) & (full_df["class"] == cls)
            ][metric.lower()]
            row[col] = value.values[0] if not value.empty else np.nan
    row["Class"] = cls
    data.append(row)

heatmap_df = pd.DataFrame(data).set_index("Class")

col_widths = [
    0.2 if col.startswith("SEP") else 1.0 for col in heatmap_df.columns
]

# сетка координат
x_edges = np.cumsum([0] + col_widths)
y_edges = np.arange(len(heatmap_df) + 1)
x_centers = [
    (x_edges[i] + x_edges[i + 1]) / 2 for i in range(len(heatmap_df.columns))
]

fig, ax = plt.subplots(
    figsize=(max(12, sum(col_widths) * 0.5), max(6, len(classes) * 0.4))
)

cmap = plt.get_cmap("YlGnBu")
norm = Normalize(vmin=0, vmax=1)

mesh = ax.pcolormesh(
    x_edges,
    y_edges,
    heatmap_df.values,
    cmap=cmap,
    norm=norm,
    edgecolors="white",
    linewidth=0.4,
)

# значения цвет текста зависит от значения
for i in range(heatmap_df.shape[0]):
    for j in range(heatmap_df.shape[1]):
        val = heatmap_df.values[i, j]
        if not np.isnan(val):
            color = "white" if val > 0.5 else "black"
            ax.text(
                x_centers[j],
                i + 0.5,
                f"{val:.2f}",
                ha="center",
                va="center",
                fontsize=7,
                color=color,
            )

# подписи по оси Y
ax.set_yticks(np.arange(len(heatmap_df)) + 0.5)
ax.set_yticklabels(heatmap_df.index, fontsize=9)
ax.set_xticks([])

# подписи метрик сверху
for j, col in enumerate(heatmap_df.columns):
    if not col.startswith("SEP"):
        metric = col.split(":")[0]
        ax.text(
            x_centers[j],
            -0.5,
            metric,
            ha="center",
            va="center",
            fontsize=8,
            color="black",
        )

model_ticks = []
model_labels = []
col_idx = 0
for i, model in enumerate(models):
    center = np.mean(x_centers[col_idx : col_idx + len(metrics)])
    model_ticks.append(center)
    model_labels.append(model)
    col_idx += len(metrics) + 1  # +1 за SEP

ax2 = ax.twiny()
ax2.set_xlim(ax.get_xlim())
ax2.set_xticks(model_ticks)
ax2.set_xticklabels(model_labels, fontsize=10)
ax2.tick_params(length=0, pad=10)
ax2.xaxis.set_label_position("top")
ax2.xaxis.tick_top()

ax.set_title(
    f"Per-class metrics across all models ({DATASET_NAME})", fontsize=14, pad=20
)
ax.set_ylabel("Class")

fig.tight_layout()
fig.savefig("heatmap_with_thin_separators.png", dpi=600)
plt.close()
