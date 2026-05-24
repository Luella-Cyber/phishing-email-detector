"""
ml_classifier.py
----------------
Layer 2: Machine Learning phishing classifier.

Uses a combination of:
  - TF-IDF features from email subject + body text
  - Engineered numerical features (URL count, urgency word count, etc.)

Model: Voting ensemble of Logistic Regression + Random Forest
Trained on: Labeled phishing and legitimate email samples
"""

import os
import re
import pickle
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

URGENCY_WORDS = [
    "urgent", "immediately", "expires", "suspended", "verify", "confirm",
    "unusual", "suspicious", "unauthorized", "locked", "compromised",
    "limited", "action required", "act now", "last chance"
]

PHISHING_WORDS = [
    "password", "click here", "login", "bank account", "credit card",
    "social security", "winner", "prize", "lottery", "inheritance",
    "gift card", "bitcoin", "wire transfer", "refund", "invoice",
    "paypal", "amazon", "apple", "microsoft", "update your account"
]


class NumericalFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts numerical features from parsed email dicts.
    Works alongside TF-IDF on the text content.
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.array([self._extract(row) for row in X])

    def _extract(self, row):
        text = str(row.get("subject", "")) + " " + str(row.get("body_text", ""))
        text_lower = text.lower()
        sender = str(row.get("sender", "")).lower()
        urls = row.get("urls", [])

        return [
            # URL features
            len(urls),
            sum(1 for u in urls if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)),  # IP URLs
            sum(1 for u in urls if any(s in u for s in ["bit.ly", "tinyurl", "goo.gl"])),  # shorteners

            # Text length features
            len(text),
            len(text.split()),

            # Keyword counts
            sum(1 for w in URGENCY_WORDS if w in text_lower),
            sum(1 for w in PHISHING_WORDS if w in text_lower),

            # Punctuation/formatting
            text.count("!"),
            text.count("?"),
            len(re.findall(r'[A-Z]{3,}', text)),  # sequences of caps

            # Sender features
            1 if re.search(r'@(gmail|yahoo|hotmail|outlook)\.com', sender) else 0,
            1 if row.get("reply_to") and row.get("reply_to") != row.get("sender") else 0,
            1 if row.get("has_attachments") else 0,
        ]


class TextFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts combined text string from parsed email for TF-IDF."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return [
            str(row.get("subject", "")) + " " + str(row.get("body_text", ""))
            for row in X
        ]


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------

def build_model():
    """Build the sklearn pipeline."""
    tfidf = Pipeline([
        ("text_extractor", TextFeatureExtractor()),
        ("tfidf", TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 2),
            stop_words="english",
            sublinear_tf=True
        ))
    ])

    numeric = Pipeline([
        ("num_extractor", NumericalFeatureExtractor()),
        ("scaler", StandardScaler())
    ])

    # Combine TF-IDF + numerical features
    combined = FeatureUnion([
        ("tfidf_features", tfidf),
        ("numeric_features", numeric)
    ])

    lr = LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced")
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)

    ensemble = VotingClassifier(
        estimators=[("lr", lr), ("rf", rf)],
        voting="soft"
    )

    pipeline = Pipeline([
        ("features", combined),
        ("classifier", ensemble)
    ])

    return pipeline


def train(data_path: str = None, verbose: bool = True) -> dict:
    """
    Train the model on labeled email data.
    Returns accuracy metrics.
    """
    if data_path is None:
        data_path = os.path.join(os.path.dirname(__file__), "..", "data", "training_data.csv")

    df = pd.read_csv(data_path)

    # Build parsed dicts from CSV rows (simulating parsed email structure)
    X = df.apply(lambda row: {
        "subject": row.get("subject", ""),
        "body_text": row.get("body_text", ""),
        "sender": row.get("sender", ""),
        "reply_to": row.get("reply_to", ""),
        "urls": str(row.get("urls", "")).split("|") if row.get("urls") else [],
        "has_attachments": bool(row.get("has_attachments", 0))
    }, axis=1).tolist()

    y = df["label"].tolist()  # 1 = phishing, 0 = legitimate

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = build_model()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])

    if verbose:
        print("=== ML Model Training Complete ===")
        print(report)

    # Save model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    if verbose:
        print(f"Model saved to {MODEL_PATH}")

    return {"report": report, "model": model}


def load_model():
    """Load the trained model from disk."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"No trained model found at {MODEL_PATH}. "
            "Run `python -m detector.ml_classifier` to train first."
        )
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def predict(parsed: dict, model=None) -> dict:
    """
    Run the ML classifier on a parsed email.

    Returns:
        {
            "ml_score": float (0.0 - 1.0, probability of phishing),
            "ml_label": "Phishing" | "Legitimate",
            "ml_confidence": float
        }
    """
    if model is None:
        model = load_model()

    proba = model.predict_proba([parsed])[0]
    phishing_prob = proba[1]

    return {
        "ml_score": round(float(phishing_prob), 3),
        "ml_label": "Phishing" if phishing_prob >= 0.5 else "Legitimate",
        "ml_confidence": round(float(max(proba)), 3)
    }


if __name__ == "__main__":
    train(verbose=True)
