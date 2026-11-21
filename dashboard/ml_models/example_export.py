"""Reference for the ML teammate: how to save models so the dashboard picks them up.

This trains toy models on the dashboard's synthetic traffic just to prove the
hand-off format. Replace the data part with the real NSL-KDD / CICIDS2017
training — the three joblib.dump() calls at the bottom are the contract.

    python ml_models/example_export.py      # writes 3 .joblib files next to this script
"""
import os
import sys

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector import ATTACK_MAP, CATEGORICAL, NSL_KDD_FEATURES  # noqa: E402
from simulator import synth_record  # noqa: E402

# ---- data (swap for real dataset: df = pd.read_csv("KDDTrain+.txt", names=NSL_KDD_FEATURES+["label","difficulty"]))
rows = [synth_record()[:2] for _ in range(6000)]
df = pd.DataFrame([f for f, _ in rows])[NSL_KDD_FEATURES]
y = [ATTACK_MAP.get(lbl, "Other") or "normal" for _, lbl in rows]  # normal | DoS | Probe | R2L | U2R

# ---- preprocessing: must accept a DataFrame with the 41 NSL-KDD columns
cat = sorted(CATEGORICAL)
num = [c for c in NSL_KDD_FEATURES if c not in CATEGORICAL]
pre = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore"), cat),
    ("num", StandardScaler(), num),
])
X = pre.fit_transform(df)

# ---- models
iforest = IsolationForest(n_estimators=200, contamination=0.15, random_state=42).fit(X[[i for i, l in enumerate(y) if l == "normal"]])
rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1).fit(X, y)

# ---- THE CONTRACT: these three file names in ml_models/
out = os.path.dirname(os.path.abspath(__file__))
joblib.dump(pre, os.path.join(out, "preprocessor.joblib"))
joblib.dump(iforest, os.path.join(out, "isolation_forest.joblib"))
joblib.dump(rf, os.path.join(out, "random_forest.joblib"))
print("Saved models to", out, "— click 'Reload models' on the Settings page (or restart the app).")
