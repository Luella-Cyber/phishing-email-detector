# 🎣 Phishing Email Detector

A **hybrid phishing detection tool** combining rule-based analysis and machine learning to identify malicious emails. Built as part of a cybersecurity portfolio to demonstrate threat detection, Python development, and security analysis skills.

---

## Architecture: 3-Layer Detection System

```
Email Input
    │
    ├──► Layer 1: Rule Engine      (55% weight)
    │         Sender spoofing, URL analysis,
    │         urgency language, credential harvesting,
    │         suspicious attachments, header anomalies
    │
    ├──► Layer 2: ML Classifier    (45% weight)
    │         TF-IDF text features + engineered
    │         numerical features → Voting Ensemble
    │         (Logistic Regression + Random Forest)
    │
    └──► Layer 3: Hybrid Scorer
              Weighted combination → Risk Score (0–100%)
              SAFE | LOW | MEDIUM | HIGH | CRITICAL
```

---

## Features

**Rule-Based Engine (Layer 1)**
- Sender display name spoofing detection (e.g. `PayPal <noreply@paypa1.xyz>`)
- Reply-To mismatch analysis
- URL analysis: IP addresses, suspicious TLDs, URL shorteners, brand impersonation
- Urgency/pressure language detection
- Credential harvesting phrase detection
- Financial scam language (gift cards, wire transfers, lottery)
- Threat language (legal action, arrest, IRS)
- Dangerous attachment extension detection
- Subject line anomaly detection

**ML Classifier (Layer 2)**
- TF-IDF vectorization with bigrams on email subject + body
- Engineered numerical features: URL count, urgency word count, punctuation patterns
- Voting ensemble of Logistic Regression + Random Forest
- Trained on labeled phishing and legitimate email samples
- Probability output feeds the hybrid scorer

**Hybrid Scorer (Layer 3)**
- Weighted combination of rule and ML scores
- 5-tier risk verdict: SAFE / LOW / MEDIUM / HIGH / CRITICAL
- Human-readable explanation of every triggered rule
- Graceful degradation to rule-only if ML model unavailable

---

## Installation

```bash
git clone https://github.com/Luella-Cyber/phishing-email-detector.git
cd phishing-email-detector
pip install -r requirements.txt
```

---

## Usage

### 1. Train the ML Model (first time only)
```bash
python -m detector.ml_classifier
```

### 2. Command Line — Quick Demo
```bash
python cli.py --demo
```

### 3. Command Line — Analyze an Email
```bash
# Analyze a .eml file
python cli.py --file path/to/email.eml

# Analyze by pasting components
python cli.py --subject "URGENT: Verify your account" \
              --sender "support@paypa1.xyz" \
              --body "Your account has been suspended. Click here immediately."

# Output as JSON
python cli.py --demo --json
```

### 4. Web Interface
```bash
python app.py
# Open http://localhost:5000
```

---

## Example Output

```
============================================================
  PHISHING ANALYSIS REPORT
============================================================
  Verdict:    🔴  CRITICAL
  Risk Score: 100.0%
  Advice:     Highly likely phishing. Do not click any links or reply.
------------------------------------------------------------
  EMAIL DETAILS
  Subject:    URGENT: Your PayPal account has been suspended - Verify Now
  From:       support@paypa1-billing.xyz
  Reply-To:   recovery@gmail.com
  URLs found: 2
------------------------------------------------------------
  SCORE BREAKDOWN
  Rule-based score: 100.0%
  ML score:         88.4%
  Final score:      94.8%
------------------------------------------------------------
  TRIGGERED RULES (4 found)
  [95%] Sender Spoofing: Sender display name 'paypal' impersonates 'paypal' but email comes from 'paypa1-billing.xyz'
  [75%] Reply-To Mismatch: Reply-To domain 'gmail.com' differs from sender domain 'paypa1-billing.xyz'
  [85%] Suspicious URLs: Brand 'paypal' in URL but domain is 'paypal-secure-update.xyz'
  [80%] Credential Harvesting: password, social security, credit card
============================================================
```

---

## Project Structure

```
phishing-email-detector/
├── detector/
│   ├── email_parser.py      # Parse .eml files and raw email text
│   ├── rule_engine.py       # Layer 1: 10 rule-based checks
│   ├── ml_classifier.py     # Layer 2: ML training and inference
│   └── hybrid_analyzer.py   # Layer 3: Score combination and reporting
├── data/
│   └── training_data.csv    # Labeled phishing/legitimate email samples
├── models/                  # Saved ML model (generated after training)
├── cli.py                   # Command-line interface
├── app.py                   # Flask web interface
└── requirements.txt
```

---

## Skills Demonstrated

- Python OOP and modular design
- NLP and text feature engineering (TF-IDF, n-grams)
- Machine learning (scikit-learn pipelines, ensemble methods)
- Email security concepts (header analysis, spoofing, phishing IOCs)
- Web application development (Flask)
- Security tool development and documentation

---

## Detection Rules Reference

| Rule | What It Catches | Max Score |
|------|----------------|-----------|
| Sender Spoofing | Display name impersonates trusted brand but wrong domain | 95% |
| Reply-To Mismatch | Reply-To and From domains differ | 75% |
| Free Email Provider | Corporate claims but Gmail/Yahoo sender | 80% |
| Suspicious URLs | IP addresses, bad TLDs, shorteners, brand misuse | 90% |
| Urgency Language | Pressure tactics and time limits | 75% |
| Credential Harvesting | Requests for passwords, SSN, card numbers | 80% |
| Financial Scam | Gift cards, wire transfers, prize claims | 85% |
| Threat Language | Legal action, arrest, criminal charges | 75% |
| Suspicious Attachments | .exe, .vbs, .js, macro-enabled files | 90% |
| Subject Anomalies | ALL CAPS, excessive punctuation | 45% |

---

*Part of the Cybersecurity Portfolio — Security Analyst in Training*  
*[github.com/Luella-Cyber](https://github.com/Luella-Cyber)*
