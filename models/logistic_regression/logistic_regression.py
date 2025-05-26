from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

model = make_pipeline(
    StandardScaler(),
    SelectKBest(mutual_info_classif, k=13),
    LogisticRegression(
        penalty="l2",
        C=1,
        # solver="saga",
        max_iter=5000,
        n_jobs=-1,
        class_weight="balanced",
    ),
)
