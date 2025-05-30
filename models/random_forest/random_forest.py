from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.pipeline import Pipeline

pipeline = Pipeline(
    [
        (
            "model",
            RandomForestClassifier(
                n_jobs=-1,
                random_state=42,
            ),
        ),
    ]
)

param_grid = {
    "model__n_estimators": [300, 500, 700],
    "model__max_depth": [None, 10],
    "model__max_features": ["sqrt"],
    "model__bootstrap": [True, False],
    "model__criterion": ["gini", "entropy"],
    "model__class_weight": ["balanced"],
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

# RandomForestClassifier(bootstrap=False, class_weight='balanced',
#                        criterion='entropy', n_estimators=300, n_jobs=-1,
#                        random_state=42)
