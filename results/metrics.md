# ML Results (NSL-KDD, test set: KDDTest+)

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Random Forest (threshold 0.5) | 0.7787 | 0.9689 | 0.6314 | 0.7646 |
| Isolation Forest | 0.8022 | 0.9274 | 0.7079 | 0.8029 |
| Hybrid 3-level (RF + Isolation Forest) | 0.8563 | 0.9230 | 0.8156 | 0.8660 |

ROC-AUC: Random Forest 0.9598, Isolation Forest 0.9365

Random Forest threshold analysis (test set):

| Threshold | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| 0.5 | 0.7796 | 0.9690 | 0.6331 | 0.7659 |
| 0.4 | 0.8045 | 0.9695 | 0.6779 | 0.7979 |
| 0.3 | 0.8283 | 0.9678 | 0.7224 | 0.8273 |
| 0.2 | 0.8447 | 0.9352 | 0.7813 | 0.8514 |
| 0.1 | 0.8890 | 0.9225 | 0.8788 | 0.9002 |

Label purity (hybrid): Malicious 8125/8385 actual attacks, Suspicious 2341/2954.

Note: on a random train/validation split recall is ~99.9%, but on KDDTest+
(which has attack types unseen in training) it drops. Thresholds were chosen
with recall priority, after looking at test results, so these numbers are
somewhat optimistic.