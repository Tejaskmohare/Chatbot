import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

# Sample dataset with URL-based features
data = {
    "url_length": [10, 70, 25, 90, 15],
    "dot_count": [1, 4, 2, 5, 1],
    "dash_count": [0, 2, 1, 3, 0],
    "https": [1, 0, 1, 0, 1],
    "at_symbol": [0, 1, 0, 1, 0],
    "label": [0, 1, 0, 1, 0]  # 1 = Phishing, 0 = Safe
}

df = pd.DataFrame(data)
X = df.drop("label", axis=1)
y = df["label"]

# Train a simple Random Forest model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save the model
with open("phishing_model.pkl", "wb") as model_file:
    pickle.dump(model, model_file)

print("Model trained and saved as phishing_model.pkl")
