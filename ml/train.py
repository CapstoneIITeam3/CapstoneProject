import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.pipeline import Pipeline
from ml.data import load_nsl_kdd, add_target, split_xy
from ml.preprocess import build_preprocessor

def train_random_forest(X, y):
    return Pipeline([
        ("prep", build_preprocessor(X)),
        ("clf", RandomForestClassifier(n_estimators=100, n_jobs=2, random_state=42)),
    ]).fit(X, y)

def train_isolation_forest(X, y):
    # sirf normal traffic par train
    return Pipeline([
        ("prep", build_preprocessor(X)),
        ("clf", IsolationForest(n_estimators=100, contamination=0.1, random_state=42)),
    ]).fit(X[y == 0])

if __name__ == "__main__":
    X, y = split_xy(add_target(load_nsl_kdd("data/KDDTrain+.txt")))
    joblib.dump(train_random_forest(X, y), "ml/rf_model.pkl")
    joblib.dump(train_isolation_forest(X, y), "ml/iso_model.pkl")
    print("Models saved")