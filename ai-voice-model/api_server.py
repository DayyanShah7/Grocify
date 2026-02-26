from flask import Flask, request, jsonify
import joblib
import librosa
import numpy as np
import tempfile
import os

app = Flask(__name__)

# Load trained model once
model = joblib.load("intent_model.pkl")

@app.route("/predict", methods=["POST"])
def predict():

    if "file" not in request.files:
        return jsonify({"error": "No audio file provided"}), 400

    audio_file = request.files["file"]

    # Save temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp:
        audio_file.save(tmp.name)
        temp_path = tmp.name

    try:
        # Extract MFCC
        y, sr = librosa.load(temp_path, sr=16000)
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)

        mfcc_mean = mfcc.mean(axis=1)
        mfcc_std = mfcc.std(axis=1)

        features = np.concatenate([mfcc_mean, mfcc_std]).reshape(1, -1)

        # Predict
        prediction = model.predict(features)[0]

    except Exception as e:
        os.remove(temp_path)
        return jsonify({"error": str(e)}), 500

    os.remove(temp_path)

    return jsonify({"intent": prediction})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)