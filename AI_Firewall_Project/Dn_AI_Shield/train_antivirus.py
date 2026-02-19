import numpy as np
import pandas as pd
import math
import os
import joblib

# HACK: Agar TensorFlow fail ho, toh hum Scikit-Learn (RandomForest) use karenge
# Kyunki Antivirus ke liye Machine Learning (RandomForest) best kaam karta hai!
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

print("⚙️ Step 1: Asli jesa File Data (Safe vs Malware) generate kar rahe hain...")
# Features: [File Size (KB), Entropy (0-8), Suspicious API Calls, File Hidden Status]

# Safe Files: Badi size, low entropy (normal text/code), kam suspicious calls
safe_files = np.random.normal(loc=[5000, 4.2, 5, 0], scale=[1000, 0.5, 2, 0.1], size=(1000, 4))
safe_labels = np.zeros(1000)

# Malware (Virus): Chhoti size, High entropy (encrypted), bohot suspicious calls
malware_files = np.random.normal(loc=[800, 7.6, 25, 1], scale=[200, 0.3, 5, 0.1], size=(500, 4))
malware_labels = np.ones(500)

X = np.vstack((safe_files, malware_files))
y = np.concatenate((safe_labels, malware_labels))

# Values ko clean karna (Negative size nahi ho sakti, Entropy max 8)
X = np.abs(X)
X[:, 1] = np.clip(X[:, 1], 0, 8.0) 
X[:, 3] = np.clip(np.round(X[:, 3]), 0, 1) # Hidden status sirf 0 ya 1 hoga

print("⚙️ Step 2: AI ko sikha rahe hain (Training)...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, 'av_scaler.pkl') 

# Antivirus me RandomForest bohot fast aur accurate hota hai
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_scaled, y)

print("✅ Step 3: Model Save ho raha hai...")
joblib.dump(model, 'av_model.pkl')
print("🎉 Badhai ho! Dn Antivirus AI Model ('av_model.pkl') ready hai!")