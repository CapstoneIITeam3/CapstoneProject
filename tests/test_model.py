import pandas as pd
from ml.predict import predict

ROWS = pd.read_csv("tests/sample_rows.csv")

def _row():
    return ROWS.iloc[0].to_dict()

def test_output_format():
    assert set(predict(_row()).keys()) == {"label", "score"}

def test_score_range_and_labels():
    for i in range(len(ROWS)):
        out = predict(ROWS.iloc[i].to_dict())
        assert 0.0 <= out["score"] <= 1.0
        assert out["label"] in {"Normal", "Suspicious", "Malicious"}

def test_unseen_category_does_not_crash():
    row = _row()
    row["service"] = "totally_new_service"
    assert "label" in predict(row)

def test_missing_fields_do_not_crash():
    row = _row()
    for k in ["src_bytes", "count", "flag"]:
        row.pop(k)
    assert "label" in predict(row)