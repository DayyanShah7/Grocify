import os
import pandas as pd
from tqdm import tqdm
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
import joblib

DATA_FOLDER = "csv_features"

all_data = []
all_labels = []

print("Loading CSV files...")

for root, _, files in os.walk(DATA_FOLDER):
    for file in files:
        if file.endswith(".csv"):

            label = os.path.basename(root).lower()
            path = os.path.join(root, file)

            try:
                df = pd.read_csv(path)

                # MFCC mean + std
                mfcc_mean = df.mean().values
                mfcc_std = df.std().values
                features = list(mfcc_mean) + list(mfcc_std)

                all_data.append(features)
                all_labels.append(label)

            except Exception as e:
                print(f"Error reading {file}: {e}")

features_df = pd.DataFrame(all_data)
features_df["label"] = all_labels

print("\nTotal samples in dataset:", len(features_df))
print("\nClass distribution:")
print(features_df["label"].value_counts())

X = features_df.drop(columns="label")
y = features_df["label"]

# ---------------- SVM WITH SCALING (LINEAR) ----------------
svm_model = make_pipeline(
    StandardScaler(),
    SVC(kernel="linear", C=1)
)

# ---------------- CROSS VALIDATION ----------------
print("\n=== 5-Fold Cross Validation ===")
cv_scores = cross_val_score(svm_model, X, y, cv=5)
print("CV accuracy scores:", cv_scores)
print("Mean CV accuracy:", cv_scores.mean())

# ---------------- TRAIN / TEST SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

print("\n=== SVM Test Evaluation ===")
svm_model.fit(X_train, y_train)
svm_pred = svm_model.predict(X_test)

print(classification_report(y_test, svm_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, svm_pred))

# Save model
joblib.dump(svm_model, "intent_model.pkl")
print("\nModel saved as intent_model.pkl")
