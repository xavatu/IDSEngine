import pandas as pd

from data.new.preprocessing import CombinedFeatureExtractor, FEATURES


def extract_features(event, *args) -> dict:  #  noqa
    if isinstance(event, pd.Series):
        event = event.to_dict()

    extractor = CombinedFeatureExtractor()
    features_df = extractor.transform([event])

    feature_dict = features_df.iloc[0].to_dict()

    feature_dict = {k: feature_dict.get(k, 0) for k in FEATURES}
    return feature_dict
