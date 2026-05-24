#!/usr/bin/env python3
"""
cli.py
------
Command-line interface for the Phishing Email Detector.

Usage:
    # Analyze a .eml file
    python cli.py --file path/to/email.eml

    # Analyze by pasting components
    python cli.py --subject "Urgent: Verify your account" \
                  --sender "support@paypa1.xyz" \
                  --body "Your account has been suspended. Click here."

    # Train the ML model
    python cli.py --train

    # Run on a test sample
    python cli.py --demo
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector.hybrid_analyzer import analyze, analyze_text, format_report


# ---------------------------------------------------------------------------
# Demo emails for quick testing
# ---------------------------------------------------------------------------

DEMO_PHISHING = {
    "subject": "URGENT: Your PayPal account has been suspended - Verify Now",
    "sender": "support@paypa1-billing.xyz",
    "reply_to": "recovery@gmail.com",
    "body": """Dear Customer,

We have detected UNUSUAL ACTIVITY on your PayPal account. Your account has been 
temporarily SUSPENDED due to suspicious signin attempts from an unauthorized location.

You must verify your identity IMMEDIATELY within 24 hours or your account will be 
PERMANENTLY CLOSED and your funds will be frozen.

Click here to confirm your account details: http://paypal-secure-update.xyz/verify

You will need to provide:
- Your email address and password
- Your credit card number and billing address
- Your Social Security Number for identity verification

This is your FINAL NOTICE. Do not ignore this urgent security alert.

PayPal Security Team""",
    "urls": ["http://paypal-secure-update.xyz/verify", "http://bit.ly/pp-verify"]
}

DEMO_LEGITIMATE = {
    "subject": "Your Amazon order has shipped",
    "sender": "shipment-tracking@amazon.com",
    "reply_to": "",
    "body": """Hello Luella,

Great news! Your order #112-3456789-1234567 has shipped.

Your package is on its way and your estimated delivery date is Thursday, May 22.

You can track your package at:
https://www.amazon.com/progress-tracker/package/ref=pe_2640190_261538020

Order details:
- Anker USB-C Cable (2-pack) x1

Thank you for shopping with Amazon.

Amazon Customer Service
https://www.amazon.com""",
    "urls": ["https://www.amazon.com/progress-tracker/package/ref=pe_2640190_261538020"]
}


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Detector — Hybrid Rule-Based + ML Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --demo                          # Run on built-in demo emails
  python cli.py --file email.eml                # Analyze an .eml file
  python cli.py --subject "..." --body "..."    # Analyze by components
  python cli.py --train                         # Train the ML model
        """
    )

    parser.add_argument("--file", help="Path to .eml file to analyze")
    parser.add_argument("--subject", help="Email subject line")
    parser.add_argument("--sender", help="Sender email address")
    parser.add_argument("--reply-to", dest="reply_to", help="Reply-To address", default="")
    parser.add_argument("--body", help="Email body text")
    parser.add_argument("--train", action="store_true", help="Train the ML model")
    parser.add_argument("--demo", action="store_true", help="Run analysis on demo emails")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Train mode
    # -----------------------------------------------------------------------
    if args.train:
        print("Training ML classifier...")
        from detector.ml_classifier import train
        train(verbose=True)
        return

    # -----------------------------------------------------------------------
    # Demo mode
    # -----------------------------------------------------------------------
    if args.demo:
        print("\n" + "🎣 " * 20)
        print("DEMO: Analyzing a PHISHING email")
        print("🎣 " * 20)
        result = analyze_text(**DEMO_PHISHING)
        print(format_report(result))

        print("\n" + "✅ " * 20)
        print("DEMO: Analyzing a LEGITIMATE email")
        print("✅ " * 20)
        result = analyze_text(**DEMO_LEGITIMATE)
        print(format_report(result))
        return

    # -----------------------------------------------------------------------
    # File mode
    # -----------------------------------------------------------------------
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
        result = analyze(args.file)

    # -----------------------------------------------------------------------
    # Component mode
    # -----------------------------------------------------------------------
    elif args.subject or args.body or args.sender:
        result = analyze_text(
            subject=args.subject or "",
            body=args.body or "",
            sender=args.sender or "",
            reply_to=args.reply_to or ""
        )

    else:
        # Interactive mode — read from stdin
        print("Phishing Email Detector — Interactive Mode")
        print("Paste your email below. Press Ctrl+D (Linux/Mac) or Ctrl+Z (Windows) when done:\n")
        try:
            raw = sys.stdin.read()
            result = analyze(raw)
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    if args.json:
        import json
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_report(result))


if __name__ == "__main__":
    main()
