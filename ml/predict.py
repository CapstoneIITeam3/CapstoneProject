import joblib
import pandas as pd
from pathlib import Path
from ml.data import COLUMNS, CATEGORICAL

_DIR = Path(__file__).parent
_RF = joblib.load(_DIR / "rf_model.pkl")
_ISO = joblib.load(_DIR / "iso_model.pkl")

FEATURES = [c for c in COLUMNS if c not in ("label", "difficulty")]

def _to_frame(row):
    df = pd.DataFrame([row]).reindex(columns=FEATURES)
    for c in FEATURES:
        df[c] = df[c].fillna("other" if c in CATEGORICAL else 0)
    return df

def _label(score, anomaly):
    if score >= 0.5:
        return "Malicious"      # RF ko yakeen hai (known attack)
    if score >= 0.2 or anomaly:
        return "Suspicious"     # RF ko shak hai ya traffic normal se alag hai
    return "Normal"

def predict(row):
    """row: dict of 41 NSL-KDD features -> {"label": ..., "score": ...}"""
    df = _to_frame(row)
    score = float(_RF.predict_proba(df)[0][1])
    anomaly = bool(_ISO.predict(df)[0] == -1)
    return {"label": _label(score, anomaly), "score": round(score, 2)}