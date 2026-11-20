from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from ml.data import CATEGORICAL

def build_preprocessor(X):
    numeric = [c for c in X.columns if c not in CATEGORICAL]
    return ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
        ("num", StandardScaler(), numeric),
    ])