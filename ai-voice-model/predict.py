import joblib
import numpy as np

# Load trained model
model = joblib.load("intent_model.pkl")

# Example fake MFCC vector (replace with real MFCC later)
sample = np.random.rand(1, 13)

prediction = model.predict(sample)
print("Predicted intent:", prediction[0])
