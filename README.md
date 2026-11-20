# ML Module

Hybrid threat detection on NSL-KDD: Random Forest + Isolation Forest.

## Usage
    from ml.predict import predict
    predict(row)  # row: dict of 41 NSL-KDD features
    # -> {"label": "Normal" | "Suspicious" | "Malicious", "score": 0.0-1.0}

## Setup
    pip install -r ml/requirements-ml.txt
    python -m pytest

Models (`ml/rf_model.pkl`, `ml/iso_model.pkl`) were trained on KDDTrain+ in Colab
(scikit-learn 1.6.1). To retrain, place KDDTrain+.txt / KDDTest+.txt in `data/`
and run `python -m ml.train`, `python -m ml.evaluate`.

## Results (KDDTest+)
See results/metrics.md for the full table. Hybrid 3-level: accuracy 0.856,
precision 0.923, recall 0.816. RF ROC-AUC 0.96, Isolation Forest ROC-AUC 0.94.