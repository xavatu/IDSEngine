from sklearn.model_selection import GridSearchCV
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

pipeline = Pipeline(
    [
        (
            "model",
            XGBClassifier(
                objective="multi:softmax",
                eval_metric="mlogloss",
                n_jobs=-1,
            ),
        ),
    ]
)

param_grid = {
    "model__n_estimators": [500, 700, 1000],
    "model__max_depth": [8, 10, 13],
    "model__learning_rate": [0.05, 0.1],
    "model__subsample": [0.7, 0.8],
    "model__colsample_bytree": [0.7, 0.8],
}


class LazyBestEstimator(GridSearchCV):
    def fit(self, *args, **kwargs):
        super().fit(*args, **kwargs)
        best_model = self.best_estimator_.named_steps["model"]
        print(best_model)
        return best_model


model = LazyBestEstimator(
    estimator=pipeline,
    param_grid=param_grid,
    scoring="f1_macro",
    n_jobs=-1,
    verbose=1,
)

# XGBClassifier(
#     colsample_bytree=0.7,
#     eval_metric="mlogloss",
#     learning_rate=0.05,
#     n_estimators=700,
#     n_jobs=-1,
# )
