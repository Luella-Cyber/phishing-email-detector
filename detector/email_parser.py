from __future__ import annotations
"""
email_parser.py
---------------
Parses raw email text or .eml files into a structured dictionary
for analysis by the rule engine and ML classifier.
"""

import email
import re
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse


def parse_email(source):
    if isinstance(source, str) and source.endswith(".eml"):
        with open(source, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    elif isinstance(source, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(source)
    else:
        msg = Parser(policy=policy.default).parsestr(source)

    parsed = {
        "subject": _get_header(msg, "subject"),
        "sender": _get_header(msg, "from"),
        "reply_to": _get_header(msg, "reply-to"),
        "recipients": _get_header(msg, "to"),
        "body_text": "",
        "body_html": "",
        "headers": dict(msg.items()),
        "urls": [],
        "has_attachments": False,
        "attachment_names": [],
    }

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition:
            parsed["has_attachments"] = True
            filename = part.get_filename()
            if filename:
                parsed["attachment_names"].append(filename)

        elif content_type == "text/plain":
            try:
                parsed["body_text"] += part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                pass

        elif content_type == "text/html":
            try:
                parsed["body_html"] += part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                pass

    import re

    # No plain-text part? Fall back to the HTML with the tags removed.
    if not parsed["body_text"] and parsed["body_html"]:
        parsed["body_text"] = re.sub(r"<[^>]+>", " ", parsed["body_html"])

    # Collect URLs from the text and HTML parts, without duplicates.
    combined = parsed["body_text"] + " " + parsed["body_html"]
    found = re.findall(r"https?://[^\s<>\x22\x27)]+", combined)
    parsed["urls"] = list(dict.fromkeys(found))

    return parsed


def get_display_name(sender):
    """Return the display name from a From header, e.g. 'PayPal' from 'PayPal <a@b.com>'."""
    from email.utils import parseaddr
    name, _ = parseaddr(str(sender or ""))
    return name.strip().strip('"')


def get_sender_domain(sender):
    """Return the lowercase domain from a From header, or '' if there is none."""
    from email.utils import parseaddr
    _, address = parseaddr(str(sender or ""))
    if "@" in address:
        return address.rsplit("@", 1)[1].strip().lower()
    return ""


def _get_header(msg, name):
    """Return a header value as plain text, or '' if the header is missing."""
    value = msg.get(name, "")
    return str(value).strip() if value else ""
