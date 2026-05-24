"""
app.py
------
Flask web application for the Phishing Email Detector.
Provides a simple web UI to paste email content and get analysis results.

Run with: python app.py
Then open: http://localhost:5000
"""

import os
import sys
from flask import Flask, render_template_string, request, jsonify

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector.hybrid_analyzer import analyze_text

app = Flask(__name__)

# ---------------------------------------------------------------------------
# HTML Template (single-file, no external dependencies)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Email Detector</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f1117;
            color: #e1e4e8;
            min-height: 100vh;
        }

        header {
            background: linear-gradient(135deg, #1a1f2e, #16213e);
            border-bottom: 1px solid #30363d;
            padding: 20px 40px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        header h1 { font-size: 1.4rem; font-weight: 600; color: #58a6ff; }
        header span { font-size: 1.6rem; }

        .subtitle {
            font-size: 0.8rem;
            color: #8b949e;
            margin-top: 2px;
        }

        .container {
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }

        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 24px;
        }

        .card h2 {
            font-size: 1rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 18px;
            font-weight: 500;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 16px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        label {
            font-size: 0.85rem;
            color: #8b949e;
            font-weight: 500;
        }

        input, textarea {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 8px;
            color: #e1e4e8;
            font-size: 0.9rem;
            padding: 10px 14px;
            outline: none;
            transition: border-color 0.2s;
            font-family: inherit;
            width: 100%;
        }

        input:focus, textarea:focus {
            border-color: #58a6ff;
        }

        textarea { resize: vertical; min-height: 150px; }

        .analyze-btn {
            background: linear-gradient(135deg, #238636, #2ea043);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 12px 32px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
            width: 100%;
            margin-top: 8px;
        }

        .analyze-btn:hover { opacity: 0.85; }
        .analyze-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .result-card { display: none; }

        .verdict-banner {
            border-radius: 10px;
            padding: 20px 24px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .verdict-icon { font-size: 2.5rem; }
        .verdict-label { font-size: 1.5rem; font-weight: 700; }
        .verdict-score { font-size: 0.9rem; opacity: 0.85; margin-top: 2px; }
        .verdict-advice { font-size: 0.9rem; margin-top: 4px; }

        .verdict-CRITICAL { background: rgba(248,81,73,0.15); border: 1px solid rgba(248,81,73,0.5); }
        .verdict-HIGH     { background: rgba(210,153,34,0.15); border: 1px solid rgba(210,153,34,0.5); }
        .verdict-MEDIUM   { background: rgba(210,153,34,0.10); border: 1px solid rgba(210,153,34,0.3); }
        .verdict-LOW      { background: rgba(63,185,80,0.10); border: 1px solid rgba(63,185,80,0.3); }
        .verdict-SAFE     { background: rgba(63,185,80,0.15); border: 1px solid rgba(63,185,80,0.5); }

        .score-bar-container { margin: 16px 0; }
        .score-bar-label { display: flex; justify-content: space-between; font-size: 0.8rem; color: #8b949e; margin-bottom: 6px; }
        .score-bar { height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; }
        .score-bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; }

        .meta-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 16px;
        }

        .meta-item {
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 8px;
            padding: 12px 14px;
        }

        .meta-key { font-size: 0.75rem; color: #8b949e; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
        .meta-val { font-size: 0.9rem; word-break: break-all; }

        .rules-list { display: flex; flex-direction: column; gap: 10px; }

        .rule-item {
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 8px;
            padding: 12px 14px;
            display: flex;
            gap: 12px;
            align-items: flex-start;
        }

        .rule-badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 20px;
            white-space: nowrap;
            min-width: 50px;
            text-align: center;
        }

        .badge-high   { background: rgba(248,81,73,0.2); color: #f85149; }
        .badge-medium { background: rgba(210,153,34,0.2); color: #e3b341; }
        .badge-low    { background: rgba(63,185,80,0.2); color: #3fb950; }

        .rule-text { font-size: 0.85rem; }
        .rule-name { font-weight: 600; color: #c9d1d9; margin-bottom: 3px; }
        .rule-explanation { color: #8b949e; }

        .loading { text-align: center; padding: 20px; color: #8b949e; display: none; }

        .demo-btns {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .demo-btn {
            background: #21262d;
            color: #8b949e;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 7px 14px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .demo-btn:hover { background: #30363d; color: #e1e4e8; }

        @media (max-width: 600px) {
            .form-row, .meta-grid { grid-template-columns: 1fr; }
            header { padding: 16px 20px; }
            .container { padding: 0 12px; }
        }
    </style>
</head>
<body>

<header>
    <span>🎣</span>
    <div>
        <h1>Phishing Email Detector</h1>
        <div class="subtitle">Hybrid Rule-Based + ML Analysis · Built for Constellis Security Portfolio</div>
    </div>
</header>

<div class="container">

    <div class="demo-btns">
        <button class="demo-btn" onclick="loadDemo('phishing')">🎣 Load Phishing Demo</button>
        <button class="demo-btn" onclick="loadDemo('legitimate')">✅ Load Legitimate Demo</button>
    </div>

    <div class="card">
        <h2>Email Input</h2>
        <div class="form-row">
            <div class="form-group">
                <label>From (Sender)</label>
                <input type="text" id="sender" placeholder="e.g. support@paypa1.xyz">
            </div>
            <div class="form-group">
                <label>Reply-To (optional)</label>
                <input type="text" id="reply_to" placeholder="e.g. recovery@gmail.com">
            </div>
        </div>
        <div class="form-group" style="margin-bottom:16px">
            <label>Subject</label>
            <input type="text" id="subject" placeholder="e.g. URGENT: Your account has been suspended">
        </div>
        <div class="form-group">
            <label>Body</label>
            <textarea id="body" placeholder="Paste the email body text here..."></textarea>
        </div>
        <button class="analyze-btn" onclick="analyzeEmail()">🔍 Analyze Email</button>
    </div>

    <div class="loading" id="loading">Analyzing email... ⏳</div>

    <div class="card result-card" id="resultCard">
        <h2>Analysis Result</h2>

        <div id="verdictBanner" class="verdict-banner">
            <div class="verdict-icon" id="verdictIcon"></div>
            <div>
                <div class="verdict-label" id="verdictLabel"></div>
                <div class="verdict-score" id="verdictScore"></div>
                <div class="verdict-advice" id="verdictAdvice"></div>
            </div>
        </div>

        <div class="score-bar-container">
            <div class="score-bar-label">
                <span>Risk Score</span>
                <span id="scorePercent"></span>
            </div>
            <div class="score-bar">
                <div class="score-bar-fill" id="scoreBarFill" style="width:0%"></div>
            </div>
        </div>

        <div class="meta-grid" id="metaGrid"></div>

        <h2 style="margin-top:8px; margin-bottom:14px">Triggered Rules</h2>
        <div class="rules-list" id="rulesList"></div>
    </div>

</div>

<script>
const DEMO_PHISHING = {
    sender: "support@paypa1-billing.xyz",
    reply_to: "recovery@gmail.com",
    subject: "URGENT: Your PayPal account has been suspended - Verify Now",
    body: `Dear Customer,\n\nWe have detected UNUSUAL ACTIVITY on your PayPal account. Your account has been temporarily SUSPENDED due to suspicious signin attempts from an unauthorized location.\n\nYou must verify your identity IMMEDIATELY within 24 hours or your account will be PERMANENTLY CLOSED and your funds will be frozen.\n\nClick here to confirm your account details: http://paypal-secure-update.xyz/verify\n\nYou will need to provide:\n- Your email address and password\n- Your credit card number and billing address\n- Your Social Security Number for identity verification\n\nThis is your FINAL NOTICE. Do not ignore this urgent security alert.\n\nPayPal Security Team`
};

const DEMO_LEGIT = {
    sender: "shipment-tracking@amazon.com",
    reply_to: "",
    subject: "Your Amazon order has shipped",
    body: `Hello,\n\nGreat news! Your order #112-3456789 has shipped and is on its way.\n\nYour estimated delivery date is Thursday, May 22.\n\nTrack your package at:\nhttps://www.amazon.com/progress-tracker/package/ref=pe_2640190\n\nOrder details:\n- Anker USB-C Cable (2-pack) x1\n\nThank you for shopping with Amazon.\nAmazon Customer Service\nhttps://www.amazon.com`
};

function loadDemo(type) {
    const d = type === 'phishing' ? DEMO_PHISHING : DEMO_LEGIT;
    document.getElementById('sender').value = d.sender;
    document.getElementById('reply_to').value = d.reply_to;
    document.getElementById('subject').value = d.subject;
    document.getElementById('body').value = d.body;
}

function getScoreColor(score) {
    if (score >= 0.8) return '#f85149';
    if (score >= 0.6) return '#e3b341';
    if (score >= 0.4) return '#e3b341';
    if (score >= 0.2) return '#3fb950';
    return '#3fb950';
}

function getRuleBadgeClass(score) {
    if (score >= 0.7) return 'badge-high';
    if (score >= 0.4) return 'badge-medium';
    return 'badge-low';
}

async function analyzeEmail() {
    const btn = document.querySelector('.analyze-btn');
    const loading = document.getElementById('loading');
    const resultCard = document.getElementById('resultCard');

    btn.disabled = true;
    loading.style.display = 'block';
    resultCard.style.display = 'none';

    const payload = {
        subject: document.getElementById('subject').value,
        sender: document.getElementById('sender').value,
        reply_to: document.getElementById('reply_to').value,
        body: document.getElementById('body').value
    };

    try {
        const res = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        renderResult(data);
    } catch (err) {
        alert('Analysis failed: ' + err.message);
    } finally {
        btn.disabled = false;
        loading.style.display = 'none';
    }
}

function renderResult(data) {
    const resultCard = document.getElementById('resultCard');
    resultCard.style.display = 'block';

    // Verdict banner
    const banner = document.getElementById('verdictBanner');
    banner.className = 'verdict-banner verdict-' + data.verdict;
    document.getElementById('verdictIcon').textContent = data.verdict_icon;
    document.getElementById('verdictLabel').textContent = data.verdict;
    document.getElementById('verdictScore').textContent = `Risk Score: ${(data.risk_score * 100).toFixed(1)}%`;
    document.getElementById('verdictAdvice').textContent = data.advice;

    // Score bar
    const pct = (data.risk_score * 100).toFixed(1) + '%';
    document.getElementById('scorePercent').textContent = pct;
    const fill = document.getElementById('scoreBarFill');
    fill.style.width = pct;
    fill.style.background = getScoreColor(data.risk_score);

    // Metadata
    const meta = data.email_metadata;
    const sb = data.score_breakdown;
    const metaItems = [
        { key: 'Subject', val: meta.subject || '(none)' },
        { key: 'From', val: meta.sender || '(unknown)' },
        { key: 'Reply-To', val: meta.reply_to || '(same as sender)' },
        { key: 'URLs Found', val: meta.url_count },
        { key: 'Rule Score', val: (sb.rule_based * 100).toFixed(1) + '%' },
        { key: 'ML Score', val: typeof sb.ml_classifier === 'number' ? (sb.ml_classifier * 100).toFixed(1) + '%' : 'N/A' },
        { key: 'Attachments', val: meta.has_attachments ? 'Yes — ' + meta.attachment_names.join(', ') : 'None' },
        { key: 'Triggered Rules', val: data.rule_analysis.triggered_count }
    ];

    document.getElementById('metaGrid').innerHTML = metaItems.map(i =>
        `<div class="meta-item"><div class="meta-key">${i.key}</div><div class="meta-val">${i.val}</div></div>`
    ).join('');

    // Rules
    const rules = data.rule_analysis.triggered_rules;
    const rulesList = document.getElementById('rulesList');

    if (rules.length === 0) {
        rulesList.innerHTML = '<div style="color:#3fb950; padding:12px">✅ No rule violations detected.</div>';
    } else {
        rulesList.innerHTML = rules.map(r => `
            <div class="rule-item">
                <span class="rule-badge ${getRuleBadgeClass(r.score)}">${(r.score * 100).toFixed(0)}%</span>
                <div class="rule-text">
                    <div class="rule-name">${r.rule}</div>
                    <div class="rule-explanation">${r.explanation}</div>
                </div>
            </div>
        `).join('');
    }

    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
</script>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/analyze", methods=["POST"])
def analyze_route():
    data = request.get_json()
    result = analyze_text(
        subject=data.get("subject", ""),
        body=data.get("body", ""),
        sender=data.get("sender", ""),
        reply_to=data.get("reply_to", "")
    )
    return jsonify(result)


if __name__ == "__main__":
    print("\n🎣 Phishing Email Detector — Web UI")
    print("   Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)
