from sklearn.model_selection import GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC

pipeline = Pipeline(
    [
        (
            "model",
            SVC(
                kernel="rbf",
                probability=True,
            ),
        ),
    ]
)

param_grid = {
    "model__C": [0.1, 1.0, 10.0, 100.0],
    "model__gamma": ["scale", "auto", 0.01, 0.001],
    "model__kernel": ["rbf", "poly", "sigmoid"],
    "model__degree": [2, 3],
    "model__shrinking": [True, False],
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
