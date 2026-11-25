
import sys
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

def analyze_email(file_path):
    path = Path(file_path)

    if not path.exists():
        print("Error: Email file not found.")
        return

    with open(path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    sender = message.get("From", "")
    subject = message.get("Subject", "")

    body = ""

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = message.get_content()

    text = subject + " " + body

    score = 0
    findings = []

    suspicious_words = [
        "urgent",
        "verify your account",
        "suspended",
        "immediately",
        "password",
        "bank details",
        "click here",
        "kyc"
    ]

    for word in suspicious_words:
        if word in text.lower():
            score += 10
            findings.append(f"Suspicious keyword found: {word}")

    urls = re.findall(r'https?://[^\s<>"]+', body)

    if urls:
        score += 20
        findings.append("Email contains a URL")

    if sender and not re.search(r'@[^@\s]+', sender):
        score += 20
        findings.append("Invalid sender email format")

    if "example.com" in sender.lower() or "example.org" in sender.lower():
        findings.append("Sender uses a sample domain")

    score = min(score, 100)

    print("\n========== PhishScan ==========")
    print("Sender:", sender)
    print("Subject:", subject)
    print("Score:", score, "/100")

    if score >= 50:
        print("Result: LIKELY PHISHING")
    else:
        print("Result: LIKELY LEGITIMATE")

    print("\nFindings:")

    if findings:
        for finding in findings:
            print("-", finding)
    else:
        print("No suspicious findings detected.")

    print("===============================\n")


if len(sys.argv) != 2:
    print("Usage: python phishscan_simple.py <email_file>")
else:
    analyze_email(sys.argv[1])
