import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os

# Charger dataset
df = pd.read_csv("training/dataset.csv")

# Features et label
X = df[["total_requests", "error_count", "unique_paths", "error_ratio", "ftp_ratio", "weblogin_ratio"]]
y = df["label"]

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Modèle petit et rapide
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X_train, y_train)

# Test
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Sauvegarde du modèle
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/model.pkl")
print("✅ Modèle sauvegardé : model/model.pkl")

# 🔹 Fonction pour prédire le risque pour une IP
def predict_risk(ip_features: dict) -> float:
    features = [[
        ip_features["total_requests"],
        ip_features["error_count"],
        ip_features["unique_paths"],
        ip_features["error_ratio"],
        ip_features["ftp_ratio"],
        ip_features["weblogin_ratio"]
    ]]
    score = model.predict_proba(features)[0][1]
    return score
