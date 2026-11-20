Adwitiya's ML module for AI-IDS.

Extract this ZIP into the root of your CapstoneProject repository.
It will create the ml/ folder.

The prediction interface is:
    from ml.predict import predict
    result = predict(row)

Input: dict containing the 41 NSL-KDD traffic features.
Output: {"label": "Normal" | "Suspicious" | "Malicious", "score": 0.0-1.0}

The saved model files are included. Do not retrain or modify the models during integration.
