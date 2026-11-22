"""Detection engine adapter: the single place the dashboard talks to ML.

The dashboard calls `detector.score(features)` and gets back:

    {
        "threat_score":    float 0-1   (the score tiers are decided on)
        "anomaly_score":   float 0-1 or None  (Isolation Forest, higher = more anomalous)
        "anomaly_flag":    bool        (Isolation Forest says "outlier")
        "rf_probability":  float 0-1 or None  (Random Forest P(attack))
        "attack_category": str or None (attack family, or what triggered the flag)
        "explanation":     list of {"feature", "value", "note"}
        "model_version":   str
    }

Backends, first one found wins:
  1. Team ML module: the `ml/` package from the CapstoneProject repo
     (ml/predict.py + ml/rf_model.pkl + ml/iso_model.pkl). Looked for next to
     this file, or one folder up (when the dashboard lives inside the repo).
  2. Generic joblib files in ./ml_models/ (preprocessor / isolation_forest / random_forest).
  3. Demo heuristic, so the UI works before any model exists.

Decision rule, which reproduces ml.predict._label() with the default settings
(suspicious 0.20, malicious 0.50, IF flag on):
    threat_score = Random Forest P(attack)
    threat_score >= malicious_threshold                      -> Malicious
    threat_score >= suspicious_threshold OR IF anomaly flag  -> Suspicious
    otherwise                                                -> Normal
Thresholds and the IF-flag switch are adjustable in Settings (SRS 3.2.7).
"""
import logging
import os
import random
import threading

log = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_models")

# NSL-KDD's 41 feature columns, in dataset order.
NSL_KDD_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
CATEGORICAL = {"protocol_type", "service", "flag"}

# Fields /api/classify insists on; anything else missing defaults to 0.
REQUIRED_FIELDS = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes"]
VALID_PROTOCOLS = {"tcp", "udp", "icmp"}

# NSL-KDD attack label -> category
ATTACK_MAP = {
    "normal": None,
    **dict.fromkeys(["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
                     "udpstorm", "processtable", "mailbomb"], "DoS"),
    **dict.fromkeys(["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"], "Probe"),
    **dict.fromkeys(["guess_passwd", "ftp_write", "imap", "phf", "multihop", "warezmaster",
                     "warezclient", "spy", "xlock", "xsnoop", "snmpguess", "snmpgetattack",
                     "httptunnel", "sendmail", "named"], "R2L"),
    **dict.fromkeys(["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
                     "xterm", "ps"], "U2R"),
}


class ValidationError(ValueError):
    pass


def validate(record: dict) -> dict:
    """Reject malformed / out-of-range records (SRS §3.2.1). Returns a clean feature dict."""
    import math

    if not isinstance(record, dict):
        raise ValidationError("Request body must be a JSON object.")
    missing = [f for f in REQUIRED_FIELDS if record.get(f) in (None, "")]
    if missing:
        raise ValidationError(f"Missing required field(s): {', '.join(missing)}")
    clean = {}
    for f in NSL_KDD_FEATURES:
        v = record.get(f, 0 if f not in CATEGORICAL else "")
        if f in CATEGORICAL:
            s_val = str(v).replace("\x00", "").strip()
            if len(s_val) > 64:
                raise ValidationError(f"Field '{f}' exceeds maximum permitted length of 64 characters.")
            clean[f] = s_val.lower() if f == "protocol_type" else s_val
            continue
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise ValidationError(f"Field '{f}' must be a number.")
        if math.isnan(v) or math.isinf(v):
            raise ValidationError(f"Field '{f}' cannot be NaN or Infinite.")
        if v < 0:
            raise ValidationError(f"Field '{f}' cannot be negative.")
        if f.endswith("_rate") and v > 1:
            raise ValidationError(f"Field '{f}' is a rate and must be between 0 and 1.")
        clean[f] = v
    if clean["protocol_type"] not in VALID_PROTOCOLS:
        raise ValidationError("protocol_type must be one of tcp, udp, icmp.")
    return clean


def tier_for(score: float, suspicious_t: float, malicious_t: float, anomaly_flag: bool = False) -> str:
    if score >= malicious_t:
        return "Malicious"
    if score >= suspicious_t or anomaly_flag:
        return "Suspicious"
    return "Normal"


def _sigmoid_anomaly(decision_value: float) -> float:
    """IsolationForest.decision_function: >0 inlier, <0 outlier -> 0-1, 1 = most anomalous."""
    import math
    return 1 / (1 + math.exp(max(-50, min(50, decision_value * 10))))


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Detector:
    def __init__(self):
        self._lock = threading.Lock()
        self.team = None  # the imported ml.predict module
        self.team_dir = None
        self.preprocessor = self.iforest = self.rf = None
        self._importances = None
        self.load_error = None
        self.load()

    # ---- model loading -------------------------------------------------
    def _load_team_module(self):
        """Import the team's ml.predict (reloading it so 'Reload models' picks up new .pkl files)."""
        import importlib
        import sys
        for d in (BASE_DIR, os.path.dirname(BASE_DIR)):
            if os.path.exists(os.path.join(d, "ml", "predict.py")):
                if d not in sys.path:
                    sys.path.append(d)
                for name in [m for m in list(sys.modules) if m == "ml" or m.startswith("ml.")]:
                    del sys.modules[name]
                mod = importlib.import_module("ml.predict")
                # one row at a time: worker threads only add overhead (predictions are identical)
                for pipe in (mod._RF, mod._ISO):
                    est = pipe.steps[-1][1] if hasattr(pipe, "steps") else pipe
                    if hasattr(est, "n_jobs"):
                        est.n_jobs = 1
                self.team, self.team_dir = mod, os.path.join(d, "ml")
                self._importances = self._rf_importances(mod._RF)
                log.info("Using team ML module from %s", self.team_dir)
                return True
        return False

    @staticmethod
    def _rf_importances(pipe):
        """Top global feature importances of an sklearn Pipeline(prep, clf), mapped back to raw column names."""
        try:
            clf = pipe.steps[-1][1] if hasattr(pipe, "steps") else pipe
            imp = clf.feature_importances_
            names = list(pipe.steps[0][1].get_feature_names_out()) if hasattr(pipe, "steps") else NSL_KDD_FEATURES
            agg = {}
            for n, v in zip(names, imp):
                raw = n.split("__", 1)[-1]
                for c in CATEGORICAL:  # one-hot columns like protocol_type_tcp -> protocol_type
                    if raw.startswith(c + "_"):
                        raw = c
                agg[raw] = agg.get(raw, 0) + float(v)
            return sorted(agg.items(), key=lambda kv: kv[1], reverse=True)
        except Exception:
            return None

    def load(self):
        with self._lock:
            self.team = self.team_dir = None
            self.preprocessor = self.iforest = self.rf = None
            self.load_error = None
            try:
                if self._load_team_module():
                    return self.status()
            except Exception as e:
                self.load_error = f"Could not load team ML module: {e}"
                log.exception(self.load_error)
            try:
                import joblib
            except ImportError:
                return self.status()
            for attr, fname in [("preprocessor", "preprocessor.joblib"),
                                ("iforest", "isolation_forest.joblib"),
                                ("rf", "random_forest.joblib")]:
                path = os.path.join(MODEL_DIR, fname)
                if os.path.exists(path):
                    try:
                        setattr(self, attr, joblib.load(path))
                    except Exception as e:
                        log.error("Failed to load %s: %s", fname, e)
        return self.status()

    @property
    def using_real_models(self):
        return self.team is not None or self.iforest is not None or self.rf is not None

    def status(self):
        if self.team is not None:
            mode = "team ML (RF + IF)"
        elif self.iforest is not None or self.rf is not None:
            mode = "trained models"
        else:
            mode = "demo heuristic"
        return {
            "mode": mode,
            "real": self.using_real_models,
            "team_module": self.team_dir,
            "isolation_forest": self.team is not None or self.iforest is not None,
            "random_forest": self.team is not None or self.rf is not None,
            "preprocessor": self.team is not None or self.preprocessor is not None,
            "error": self.load_error,
        }

    # ---- scoring -------------------------------------------------------
    def score(self, features: dict) -> dict:
        if self.team is not None:
            try:
                return self._score_team(features)
            except Exception as e:
                log.exception("Team model scoring failed, falling back to heuristic: %s", e)
        elif self.using_real_models:
            try:
                return self._score_with_models(features)
            except Exception as e:
                log.exception("Model scoring failed, falling back to heuristic: %s", e)
        out = self._score_heuristic(features)
        out["threat_score"] = combine(out["anomaly_score"], out["rf_probability"])
        out["anomaly_flag"] = False
        return out

    def score_batch(self, rows: list) -> list:
        """Score many validated records at once (used to backfill a whole dataset).
        Team module: one vectorised predict over a DataFrame, same models and inputs as predict()."""
        if self.team is None:
            return [self.score(r) for r in rows]
        import pandas as pd
        m = self.team
        df = pd.DataFrame(rows).reindex(columns=m.FEATURES)
        for c in m.FEATURES:
            df[c] = df[c].fillna("other" if c in m.CATEGORICAL else 0)
        rf = m._RF.predict_proba(df)[:, 1]
        dec = m._ISO.decision_function(df)
        top = (self._importances or [])[:5]
        out = []
        for i, r in enumerate(rows):
            p, d = float(rf[i]), float(dec[i])
            expl = [{"feature": "random_forest", "value": f"{p:.3f}", "note": "P(attack) from the Random Forest"},
                    {"feature": "isolation_forest", "value": "outlier" if d < 0 else "inlier",
                     "note": f"decision value {d:+.3f} (negative = anomalous)"}]
            expl += [{"feature": n, "value": r.get(n, "—"), "note": f"top RF feature (importance {imp:.3f})"} for n, imp in top]
            out.append({"threat_score": p, "rf_probability": p, "anomaly_score": round(_sigmoid_anomaly(d), 4),
                        "anomaly_flag": d < 0, "attack_category": None, "explanation": expl,
                        "model_version": "team-ml RF+IF"})
        return out

    def _score_team(self, features: dict) -> dict:
        m = self.team
        df = m._to_frame(features)
        rf = float(m._RF.predict_proba(df)[0][1])
        d = float(m._ISO.decision_function(df)[0])
        flag = d < 0  # identical to IsolationForest.predict(df) == -1, without scoring twice
        expl = []
        if self._importances:
            for name, imp in self._importances[:5]:
                expl.append({"feature": name, "value": features.get(name, "—"),
                             "note": f"top RF feature (importance {imp:.3f})"})
        expl.insert(0, {"feature": "isolation_forest", "value": "outlier" if flag else "inlier",
                        "note": f"decision value {d:+.3f} (negative = anomalous)"})
        expl.insert(0, {"feature": "random_forest", "value": f"{rf:.3f}",
                        "note": "P(attack) from the Random Forest"})
        return {
            "threat_score": rf,
            "rf_probability": rf,
            "anomaly_score": round(_sigmoid_anomaly(d), 4),
            "anomaly_flag": flag,
            "attack_category": None,  # filled in by the app from the tier (binary model has no families)
            "explanation": expl,
            "model_version": "team-ml RF+IF",
        }

    def _score_with_models(self, features: dict) -> dict:
        import numpy as np
        import pandas as pd

        df = pd.DataFrame([{k: features.get(k, 0) for k in NSL_KDD_FEATURES}])
        X = self.preprocessor.transform(df) if self.preprocessor is not None else df
        anomaly, flag = None, False
        if self.iforest is not None:
            d = float(self.iforest.decision_function(X)[0])
            anomaly, flag = _sigmoid_anomaly(d), d < 0
        rf_prob, category = None, None
        if self.rf is not None:
            proba = self.rf.predict_proba(X)[0]
            classes = [str(c) for c in self.rf.classes_]
            normal_idx = next((i for i, c in enumerate(classes) if c.lower() in ("normal", "0")), None)
            rf_prob = float(1 - proba[normal_idx]) if normal_idx is not None else float(max(proba))
            top = int(np.argmax(proba))
            if top != normal_idx:
                c = classes[top]
                category = c if c in ("DoS", "Probe", "R2L", "U2R") else ATTACK_MAP.get(c.lower())
        return {
            "threat_score": combine(anomaly, rf_prob),
            "anomaly_score": anomaly if anomaly is not None else rf_prob,
            "anomaly_flag": flag,
            "rf_probability": rf_prob,
            "attack_category": category,
            "explanation": [],
            "model_version": "joblib models",
        }

    def _score_heuristic(self, f: dict) -> dict:
        """Stand-in so the dashboard is demoable before real models exist.
        Rough rules of thumb from the NSL-KDD attack families — NOT a real detector."""
        reasons, s = [], 0.05
        cat = None
        if f["serror_rate"] > 0.5 or f["flag"] in ("S0", "REJ"):
            s += 0.45; cat = "DoS"; reasons.append(("serror_rate", f["serror_rate"], "high SYN-error rate (flood pattern)"))
        if f["count"] > 150:
            s += 0.25; cat = cat or "DoS"; reasons.append(("count", f["count"], "many connections to same host in 2s"))
        if f["protocol_type"] == "icmp" and f["src_bytes"] > 1000:
            s += 0.45; cat = "DoS"; reasons.append(("src_bytes", f["src_bytes"], "oversized ICMP payload (smurf-like)"))
        if f["diff_srv_rate"] > 0.5 or f["dst_host_diff_srv_rate"] > 0.5:
            s += 0.4; cat = cat or "Probe"; reasons.append(("diff_srv_rate", f["diff_srv_rate"], "touching many services (scan)"))
        if f["rerror_rate"] > 0.5:
            s += 0.2; cat = cat or "Probe"; reasons.append(("rerror_rate", f["rerror_rate"], "many rejected connections"))
        if f["num_failed_logins"] > 0:
            s += 0.3 * min(f["num_failed_logins"], 3); cat = "R2L"; reasons.append(("num_failed_logins", f["num_failed_logins"], "failed logins"))
        if f["root_shell"] > 0 or f["su_attempted"] > 0 or f["num_shells"] > 0:
            s += 0.6; cat = "U2R"; reasons.append(("root_shell", f["root_shell"], "root shell / privilege escalation"))
        if f["hot"] > 3:
            s += 0.15; reasons.append(("hot", f["hot"], "many 'hot' indicators"))
        s = max(0.0, min(1.0, s + random.uniform(-0.08, 0.08)))
        anomaly = max(0.0, min(1.0, s + random.uniform(-0.1, 0.1)))
        if s < 0.4:
            cat = None
        if not reasons:
            reasons.append(("same_srv_rate", f["same_srv_rate"], "traffic profile looks typical"))
        return {
            "anomaly_score": round(anomaly, 4),
            "rf_probability": round(s, 4),
            "attack_category": cat,
            "explanation": [{"feature": a, "value": b, "note": c} for a, b, c in reasons],
            "model_version": "demo-heuristic",
        }


detector = Detector()


def combine(anomaly, rf_prob):
    """Used by the demo heuristic and generic joblib backends."""
    if rf_prob is not None and anomaly is not None:
        return max(rf_prob, anomaly * 0.9)
    return rf_prob if rf_prob is not None else (anomaly or 0.0)
