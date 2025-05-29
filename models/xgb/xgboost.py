from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

model = make_pipeline(
    StandardScaler(),
    SelectKBest(mutual_info_classif, k=13),
    XGBClassifier(
        n_estimators=1000,
        max_depth=13,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softmax",
        eval_metric="mlogloss",
        n_jobs=-1,
    ),
)
