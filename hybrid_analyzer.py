"""
hybrid_analyzer.py
------------------
Layer 3: Hybrid phishing analyzer.

Combines rule-based scores and ML probability into a single
weighted risk score, with a human-readable verdict and
detailed breakdown.

Score weights:
  - Rule engine: 55% (interpretable, catches known patterns)
  - ML classifier: 45% (catches novel/unknown patterns)
"""

from detector.email_parser import parse_email
from detector.rule_engine import run_rules

# Try to load ML — gracefully degrade if model not yet trained
_ml_available = False
_model = None

try:
    from detector.ml_classifier import load_model, predict as ml_predict
    _model = load_model()
    _ml_available = True
except Exception:
    pass


# ---------------------------------------------------------------------------
# Risk thresholds
# ---------------------------------------------------------------------------

RISK_LEVELS = [
    (0.80, "CRITICAL",  "🔴", "Highly likely phishing. Do not click any links or reply."),
    (0.60, "HIGH",      "🟠", "Strong phishing indicators. Treat with extreme caution."),
    (0.40, "MEDIUM",    "🟡", "Suspicious. Verify sender identity before taking any action."),
    (0.20, "LOW",       "🟢", "Some minor indicators. Likely legitimate but stay cautious."),
    (0.00, "SAFE",      "✅", "No significant phishing indicators detected."),
]


def get_risk_level(score: float) -> dict:
    for threshold, level, icon, advice in RISK_LEVELS:
        if score >= threshold:
            return {"level": level, "icon": icon, "advice": advice}
    return {"level": "SAFE", "icon": "✅", "advice": "No significant phishing indicators detected."}


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze(source: str | bytes, model=None) -> dict:
    """
    Full phishing analysis pipeline.

    Args:
        source: Raw email text, .eml file path, or bytes
        model: Optional pre-loaded ML model (for performance)

    Returns:
        Complete analysis result dict
    """
    # Step 1: Parse email
    parsed = parse_email(source)

    # Step 2: Rule engine
    rule_results = run_rules(parsed)
    rule_score = rule_results["rule_score"]

    # Step 3: ML classifier (if available)
    ml_results = None
    ml_score = None

    if _ml_available or model is not None:
        try:
            _m = model or _model
            ml_results = ml_predict(parsed, model=_m)
            ml_score = ml_results["ml_score"]
        except Exception as e:
            ml_results = {"error": str(e)}

    # Step 4: Combine scores
    if ml_score is not None:
        final_score = round((rule_score * 0.55) + (ml_score * 0.45), 3)
        score_breakdown = {
            "rule_based": rule_score,
            "ml_classifier": ml_score,
            "final_hybrid": final_score,
            "weights": {"rules": "55%", "ml": "45%"}
        }
    else:
        # Fall back to rule-only if ML not available
        final_score = rule_score
        score_breakdown = {
            "rule_based": rule_score,
            "ml_classifier": "N/A (model not trained yet — run python -m detector.ml_classifier)",
            "final_hybrid": final_score,
            "weights": {"rules": "100% (ML unavailable)", "ml": "0%"}
        }

    # Step 5: Risk level
    risk = get_risk_level(final_score)

    return {
        # Summary
        "verdict": risk["level"],
        "verdict_icon": risk["icon"],
        "risk_score": final_score,
        "advice": risk["advice"],

        # Email metadata
        "email_metadata": {
            "subject": parsed.get("subject", "(no subject)"),
            "sender": parsed.get("sender", "(unknown)"),
            "reply_to": parsed.get("reply_to", ""),
            "url_count": len(parsed.get("urls", [])),
            "has_attachments": parsed.get("has_attachments", False),
            "attachment_names": parsed.get("attachment_names", [])
        },

        # Score breakdown
        "score_breakdown": score_breakdown,

        # Rule results
        "rule_analysis": {
            "triggered_count": len(rule_results["triggered_rules"]),
            "triggered_rules": rule_results["triggered_rules"],
            "clean_rules": rule_results["clean_rules"]
        },

        # ML results
        "ml_analysis": ml_results,

        # URLs found
        "urls_found": parsed.get("urls", [])[:10]
    }


def analyze_text(subject: str = "", body: str = "", sender: str = "",
                 reply_to: str = "", urls: list = None) -> dict:
    """
    Convenience wrapper for analyzing email components without a full .eml file.
    Useful for web UI and API usage.
    """
    # Build a minimal RFC 2822-style email string
    raw = f"From: {sender}\n"
    if reply_to:
        raw += f"Reply-To: {reply_to}\n"
    raw += f"Subject: {subject}\n\n{body}"

    result = analyze(raw)

    # Inject any additional URLs provided
    if urls:
        result["urls_found"] = list(set(result["urls_found"] + urls))[:10]

    return result


def format_report(result: dict) -> str:
    """Format analysis result as a readable console report."""
    lines = [
        "=" * 60,
        f"  PHISHING ANALYSIS REPORT",
        "=" * 60,
        f"  Verdict:    {result['verdict_icon']}  {result['verdict']}",
        f"  Risk Score: {result['risk_score']:.1%}",
        f"  Advice:     {result['advice']}",
        "-" * 60,
        "  EMAIL DETAILS",
        f"  Subject:    {result['email_metadata']['subject']}",
        f"  From:       {result['email_metadata']['sender']}",
        f"  Reply-To:   {result['email_metadata']['reply_to'] or '(same as sender)'}",
        f"  URLs found: {result['email_metadata']['url_count']}",
        f"  Attachments: {'Yes — ' + ', '.join(result['email_metadata']['attachment_names']) if result['email_metadata']['has_attachments'] else 'None'}",
        "-" * 60,
        "  SCORE BREAKDOWN",
        f"  Rule-based score: {result['score_breakdown']['rule_based']:.1%}",
        "  ML score:         " + (result['score_breakdown']['ml_classifier'] if isinstance(result['score_breakdown']['ml_classifier'], str) else f"{result['score_breakdown']['ml_classifier']:.1%}"),
        f"  Final score:      {result['score_breakdown']['final_hybrid']:.1%}",
    ]

    triggered = result["rule_analysis"]["triggered_rules"]
    if triggered:
        lines += ["-" * 60, f"  TRIGGERED RULES ({len(triggered)} found)"]
        for r in triggered:
            lines.append(f"  [{r['score']:.0%}] {r['rule']}: {r['explanation']}")
    else:
        lines += ["-" * 60, "  ✅ No rule violations detected"]

    if result.get("urls_found"):
        lines += ["-" * 60, "  URLS EXTRACTED (first 5)"]
        for url in result["urls_found"][:5]:
            lines.append(f"  • {url[:80]}")

    lines.append("=" * 60)
    return "\n".join(lines)
