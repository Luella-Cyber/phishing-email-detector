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
                    part.get_content_cha
