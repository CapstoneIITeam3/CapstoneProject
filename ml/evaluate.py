import joblib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, confusion_matrix, ConfusionMatrixDisplay)
from ml.data import load_nsl_kdd, add_target, split_xy

def report(name, y_true, y_pred):
    print(f"--- {name} ---")
    print("Accuracy :", round(accuracy_score(y_true, y_pred), 4))
    print("Precision:", round(precision_score(y_true, y_pred), 4))
    print("Recall   :", round(recall_score(y_true, y_pred), 4))
    print("F1       :", round(f1_score(y_true, y_pred), 4))
    ConfusionMatrixDisplay(confusion_matrix(y_true, y_pred),
                           display_labels=["Normal", "Attack"]).plot()
    plt.title(name)
    plt.savefig(f"results/cm_{name}.png")
    plt.close()

if __name__ == "__main__":
    X, y = split_xy(add_target(load_nsl_kdd("data/KDDTest+.txt")))
    rf = joblib.load("ml/rf_model.pkl")
    iso = joblib.load("ml/iso_model.pkl")

    rf_p = rf.predict_proba(X)[:, 1]
    anom = iso.predict(X) == -1

    report("random_forest", y, rf.predict(X))
    report("isolation_forest", y, anom.astype(int))

    label = np.where(rf_p >= 0.5, "Malicious",
             np.where((rf_p >= 0.2) | anom, "Suspicious", "Normal"))
    report("hybrid_3level", y, (label != "Normal").astype(int))

    print("RF ROC-AUC :", round(roc_auc_score(y, rf_p), 4))
    print("ISO ROC-AUC:", round(roc_auc_score(y, -iso.score_samples(X)), 4))