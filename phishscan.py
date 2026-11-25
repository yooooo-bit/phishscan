
import sys
import re
import ipaddress
from pathlib import Path
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

def analyze_email(file_path):
    path = Path(file_path)

    if not path.exists():
        print("Error: Email file not found.")
        return

    with open(path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    sender = message.get("From", "")
    subject = message.get("Subject", "")
    reply_to = message.get("Reply-To", "")
    return_path = message.get("Return-Path", "")
    authentication = message.get("Authentication-Results", "")

    body = ""

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                content = part.get_content()
                if isinstance(content, str):
                    body += content
    else:
        content = message.get_content()
        if isinstance(content, str):
            body = content

    score = 0
    findings = []

    def add_finding(points, description):
        nonlocal score
        score += points
        findings.append(description)

    sender_match = re.search(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', sender)
    sender_email = sender_match.group(0) if sender_match else ""

    if not sender_email:
        add_finding(20, "Invalid or missing sender email address")

    if reply_to:
        reply_match = re.search(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', reply_to)

        if reply_match and sender_email:
            sender_domain = sender_email.split("@")[-1].lower()
            reply_domain = reply_match.group(0).split("@")[-1].lower()

            if sender_domain != reply_domain:
                add_finding(20, "Reply-To domain differs from sender domain")

    if return_path and sender_email:
        return_match = re.search(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', return_path)

        if return_match:
            return_domain = return_match.group(0).split("@")[-1].lower()
            sender_domain = sender_email.split("@")[-1].lower()

            if return_domain != sender_domain:
                add_finding(15, "Return-Path domain differs from sender domain")

    if authentication:
        auth_lower = authentication.lower()

        if "spf=fail" in auth_lower or "dkim=fail" in auth_lower or "dmarc=fail" in auth_lower:
            add_finding(25, "Email authentication failure detected")

    suspicious_words = [
        "urgent",
        "verify your account",
        "suspended",
        "immediately",
        "password",
        "bank details",
        "click here",
        "kyc",
        "account blocked",
        "confirm your identity",
        "limited time"
    ]

    text = (subject + " " + body).lower()

    for word in suspicious_words:
        if word in text:
            add_finding(8, f"Suspicious keyword detected: {word}")

    urls = re.findall(r'https?://[^\s<>"\']+', body)

    for url in urls:
        add_finding(10, f"URL found: {url}")

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or ""

        if hostname.startswith("xn--") or ".xn--" in hostname:
            add_finding(20, "Internationalized domain name detected")
        is_ip = False

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            add_finding(25, "URL uses an IP address instead of a domain")
        except ValueError:
            pass

        if not is_ip and hostname.count(".") >= 3:
            add_finding(10, "URL contains multiple subdomains")

        if "@" in parsed_url.netloc:
            add_finding(20, "URL contains an unusual @ symbol")

    if sender_email:
        domain = sender_email.split("@")[-1].lower()

        if domain in ["example.com", "example.org"]:
            findings.append("Sender uses a reserved sample domain")

        if any(char.isdigit() for char in domain.split(".")[0]):
            add_finding(5, "Sender domain contains numbers")

    score = min(score, 100)

    print("\n========== PhishScan Advanced ==========")
    print("Sender:", sender)
    print("Subject:", subject)
    print("Reply-To:", reply_to if reply_to else "Not provided")
    print("Return-Path:", return_path if return_path else "Not provided")
    print("Risk Score:", score, "/100")

    if score >= 50:
        print("Result: LIKELY PHISHING")
    elif score >= 25:
        print("Result: SUSPICIOUS")
    else:
        print("Result: NO MAJOR PHISHING INDICATORS")

    print("\nAnalysis Findings:")

    if findings:
        for finding in findings:
            print("-", finding)
    else:
        print("No suspicious indicators detected.")

    print("========================================\n")


if len(sys.argv) != 2:
    print("Usage: python phishscan.py <email_file>")
else:
    analyze_email(sys.argv[1])
