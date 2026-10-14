#!/usr/bin/env python3
"""
Purpose
  Reads a saved .eml file and flags common phishing indicators. Run
  "python phishing_analyzer.py message.eml" and every check prints with a
  label, so you can see WHY an email looks sketchy instead of just a yes/no.

Key Terms and Definitions
  registrable domain - the part of a hostname someone actually owns.
  mail.paypal.com and login.paypal.com both come back as paypal.com.

  display name - the friendly name in From, like "PayPal Support". It's free
  text, so attackers can put whatever they want there.

  SPF / DKIM / DMARC - checks the receiving mail server runs to see if the
  sender is allowed to send for that domain. This script reads the results
  the server wrote into the headers. It does not re-run them.

  defang - rewriting a URL so it can't be clicked (http -> hxxp, . -> [.]).

  read-only - never fetches a URL or sends anything, so it's safe to run on
  live phishing samples.

Inputs
  - one .eml file path from the command line
  - standard library only, nothing to install

Output
  - Labeled findings printed to the terminal, grouped by check
    (headers, authentication, links), each marked ok / WARN / FLAG
  - A summary with a verdict at the end
  - Exit code: 0 = nothing flagged, 1 = couldn't read the file,
    2 = at least one flag (so it can be used in scripts)
"""

import argparse
import ipaddress
import re
import sys
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlparse


# One line of output. level is OK / WARN / FLAG and picks the marker we print.
@dataclass
class Finding:
    level: str
    title: str
    detail: str


def registrable_domain(host):
    # Just the last two labels: mail.paypal.com -> paypal.com.
    # Good for this, wrong for things like example.co.uk (-> co.uk).
    host = (host or "").lower().strip().strip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    labels = host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


# Brand -> domains it actually owns. Short illustrative list,
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com",
                  "outlook.com", "live.com"},
    "office365": {"office.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
    "coinbase": {"coinbase.com"},
    "docusign": {"docusign.com", "docusign.net"},
}


def spoofed_brand(text, real_domain):
    # Brand shows up as its own word (paypal.evil.com, paypal-secure.com,
    # "PayPal Support") but the real domain isn't one the brand owns.
    # Whole word match so "chase" doesn't hit "purchase". 
    # misses mashed-together names like securepaypal.com.
    words = set(re.split(r"[^a-z0-9]+", text.lower()))
    reg = registrable_domain(real_domain)
    for brand, legit in BRANDS.items():
        if brand in words and reg not in legit:
            return brand
    return None


def addresses_in_header(msg, header_name):
    # getaddresses splits the display name from the real address for us,
    # even when there are several.
    values = msg.get_all(header_name, [])
    return getaddresses([str(v) for v in values])


def domains_in_header(msg, header_name):
    domains = []
    for _name, addr in addresses_in_header(msg, header_name):
        addr = addr.strip().strip("<>").strip()
        if "@" in addr:
            domains.append(addr.rsplit("@", 1)[1].lower())
    return domains


EMAIL_IN_TEXT_RE = re.compile(r"[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)",
                              re.IGNORECASE)


# Check 1: From / Reply To / Return-Path consistency

# The visible From is easy to fake. Reply To shows where a reply really goes and
# Return Path where bounces go, so a mismatch with From is a common tell.
def check_headers(msg):
    findings = []
    from_domains = domains_in_header(msg, "From")
    reply_domains = domains_in_header(msg, "Reply-To")
    return_domains = domains_in_header(msg, "Return-Path")

    from_reg = {registrable_domain(d) for d in from_domains}

    if not from_domains:
        findings.append(Finding("WARN", "From", "No parseable From address found."))
    else:
        findings.append(Finding("OK", "From", ", ".join(from_domains)))

    # Display name is what most mail clients show, and it's free text.
    # Look for a fake address or a brand name that the real domain doesn't back up.
    for name, addr in addresses_in_header(msg, "From"):
        if not name or "@" not in addr:
            continue
        real = addr.rsplit("@", 1)[1].lower()

        # Grab the first fake address in the name that doesn't match the real one.
        fake = None
        for domain in EMAIL_IN_TEXT_RE.findall(name):
            if registrable_domain(domain) != registrable_domain(real):
                fake = domain
                break

        if fake:
            findings.append(Finding("FLAG", "Display name spoof",
                f'Display name "{name}" shows an address at {fake.lower()}, '
                f"but it was really sent from {real}."))
        else:
            brand = spoofed_brand(name, real)
            if brand:
                findings.append(Finding("FLAG", "Display name spoof",
                    f'Display name "{name}" claims "{brand}", '
                    f"but it was really sent from {real}."))

    # Reply-To leaving the sender's domain is a strong indicator.
    if reply_domains:
        reply_reg = {registrable_domain(d) for d in reply_domains}
        if from_reg and reply_reg.isdisjoint(from_reg):
            findings.append(Finding("FLAG", "Reply-To mismatch",
                f"Reply-To ({', '.join(reply_domains)}) is a different domain than "
                f"From ({', '.join(from_domains)})."))
        else:
            findings.append(Finding("OK", "Reply-To", ", ".join(reply_domains)))

    # Return-Path mismatch is softer — bulk senders do this legitimately.
    if return_domains:
        ret_reg = {registrable_domain(d) for d in return_domains}
        if from_reg and ret_reg.isdisjoint(from_reg):
            findings.append(Finding("WARN", "Return-Path mismatch",
                f"Return-Path ({', '.join(return_domains)}) is a different domain than "
                f"From ({', '.join(from_domains)}). Common for bulk senders, but also spoofing."))
        else:
            findings.append(Finding("OK", "Return-Path", ", ".join(return_domains)))

    return findings


# Check 2: SPF / DKIM / DMARC
# We read the verdict the receiving server wrote into Authentication-Results.
# an attacker can forge that header in the raw file — only the one your
# own gateway stamped is trustworthy. This reads it, it does not re verify.
AUTH_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)\b",
    re.IGNORECASE,
)

def check_auth(msg):
    findings = []
    auth_headers = msg.get_all("Authentication-Results", [])
    received_spf = msg.get_all("Received-SPF", [])

    # First hit for each method wins
    results = {}
    for header in auth_headers:
        for method, value in AUTH_RE.findall(str(header)):
            results.setdefault(method.lower(), value.lower())

    # Fall back to Received-SPF if SPF wasn't in Authentication-Results.
    if "spf" not in results and received_spf:
        m = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
                     str(received_spf[0]), re.IGNORECASE)
        if m:
            results["spf"] = m.group(1).lower()

    if not results:
        findings.append(Finding("WARN", "Authentication-Results",
            "No SPF/DKIM/DMARC results in the headers — can't confirm authentication."))
        return findings

    failing = {"fail", "softfail", "permerror", "temperror"}
    weak = {"none", "neutral"}
    for method in ("spf", "dkim", "dmarc"):
        if method not in results:
            findings.append(Finding("WARN", method.upper(), "Not reported in headers."))
            continue
        value = results[method]
        if value in failing:
            findings.append(Finding("FLAG", method.upper(), f"{method.upper()}={value} — failed."))
        elif value in weak:
            findings.append(Finding("WARN", method.upper(), f"{method.upper()}={value} — not enforced."))
        else:
            findings.append(Finding("OK", method.upper(), f"{method.upper()}={value}."))

    return findings


# Check 3: links
# Pull every <a> plus bare URLs from the plain part,
# then look for text-vs-destination mismatches and suspicious destinations.
class AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = []   # list of (href, visible_text)
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []


def get_body(msg, subtype):
    # get_body skips attachments, so a .html attachment won't get read as the body.
    part = msg.get_body(preferencelist=(subtype,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        # Bogus charset (phishers do this). Decode it ourselves and move on.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
DOMAIN_IN_TEXT_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
              "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
# So "Download invoice.pdf" doesn't count as a domain in the link text.
# Heads up: .zip and .mov are real TLDs too, so this can miss those.
FILE_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
                   "csv", "zip", "rar", "jpg", "jpeg", "png", "gif", "htm",
                   "html", "eml", "exe", "mov", "mp4"}


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(href, display):
    problems = []
    try:
        parsed = urlparse(href)
        host = (parsed.hostname or "").lower()
    except ValueError:
        # Hostile input, e.g. http://[broken — don't crash on it.
        return ["couldn't be parsed (malformed URL)"]
    if not host:
        return ["has no host, so there's no telling where it goes"]
    reg = registrable_domain(host)

    if parsed.username:  # http://paypal.com@evil.ru actually goes to evil.ru
        problems.append(f'has "@" before the host, so it really goes to "{host}"')
    if is_ip(host):
        problems.append(f"points at a raw IP ({host}) instead of a domain")
    if "xn--" in host:
        problems.append(f"uses punycode/IDN ({host}) — possible look-alike")
    if reg in SHORTENERS:
        problems.append(f"is a shortener ({reg}) — real destination is hidden")
    brand = spoofed_brand(host, host)
    if brand:
        problems.append(f'uses "{brand}" in the hostname but the real domain is "{reg}"')

    # Does the visible text claim a different domain than where it goes?
    if display:
        for text_domain in DOMAIN_IN_TEXT_RE.findall(display):
            if text_domain.rsplit(".", 1)[1].lower() in FILE_EXTENSIONS:
                continue
            if registrable_domain(text_domain) != reg:
                problems.append(f'text shows "{text_domain}" but goes to "{reg}"')
                break

    return problems


def defang(url):
    # Make URLs non-clickable in the output. Bracketing the dots stops
    # terminals and chat apps from auto-linking the bare domain.
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def check_links(msg):
    findings = []
    anchors = []

    html_body = get_body(msg, "html")
    if html_body:
        parser = AnchorParser()
        parser.feed(html_body)
        anchors.extend(parser.anchors)

    # Bare URLs in the text part have no display text to compare.
    # Strip sentence punctuation so "see https://x.com." matches the HTML version.
    for url in URL_RE.findall(get_body(msg, "plain")):
        anchors.append((url.rstrip(".,;:!?"), ""))

    if not anchors:
        findings.append(Finding("OK", "Links", "No URLs found in the body."))
        return findings

    seen = set()
    for href, display in anchors:
        href = (href or "").strip()
        lowered = href.lower()
        if not href or lowered.startswith(("mailto:", "tel:", "#")):
            continue
        if href in seen:
            continue
        seen.add(href)

        if lowered.startswith("javascript:"):
            findings.append(Finding("FLAG", "Suspicious link",
                "javascript: link — runs script instead of opening a page"))
            continue
        # www.evil.com with no scheme, data:, ftp:, etc. Not proof of anything,
        # but we can't analyze it like a normal web link.
        if not lowered.startswith(("http://", "https://")):
            findings.append(Finding("WARN", "Odd link",
                f"{defang(href)} — not an http(s) link, can't tell where it goes"))
            continue

        problems = analyze_url(href, display)
        if problems:
            findings.append(Finding("FLAG", "Suspicious link",
                defang(href) + "\n           - " + "\n           - ".join(problems)))
        else:
            findings.append(Finding("OK", "Link", defang(href)))

    return findings


def print_report(path, sections):
    print("=" * 72)
    print("  Phishing Email Analysis")
    print(f"  File: {path}")
    print("=" * 72)

    flags = warns = 0
    marker = {"OK": "[ ok ]", "WARN": "[WARN]", "FLAG": "[FLAG]"}
    for name, findings in sections:
        print(f"\n{name}")
        print("-" * 72)
        for f in findings:
            print(f"  {marker.get(f.level, '[    ]')} {f.title}: {f.detail}")
            if f.level == "FLAG":
                flags += 1
            elif f.level == "WARN":
                warns += 1

    print("\n" + "=" * 72)
    print(f"  Summary: {flags} flag(s), {warns} warning(s)")
    if flags >= 2:
        print("  Verdict: HIGH — multiple strong phishing indicators.")
    elif flags == 1:
        print("  Verdict: ELEVATED — a strong phishing indicator is present.")
    elif warns:
        print("  Verdict: REVIEW — soft indicators only; use judgment.")
    else:
        print("  Verdict: No indicators flagged by these three checks.")
    print("=" * 72)

    return flags


def main():
    parser = argparse.ArgumentParser(
        description="Flag phishing indicators in a .eml file (read-only, local).")
    parser.add_argument("eml_path", help="Path to the .eml file")
    args = parser.parse_args()

    try:
        with open(args.eml_path, "rb") as fh:
            msg = BytesParser(policy=policy.default).parse(fh)
    except FileNotFoundError:
        print(f"Error: file not found: {args.eml_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error parsing email: {exc}", file=sys.stderr)
        sys.exit(1)

    sections = [
        ("1. Header consistency (From / Reply-To / Return-Path)", check_headers(msg)),
        ("2. Authentication results (SPF / DKIM / DMARC)", check_auth(msg)),
        ("3. Link analysis", check_links(msg)),
    ]
    flags = print_report(args.eml_path, sections)

    # 2 = flagged, so you can do things like: analyzer.py x.eml || move_to_review
    sys.exit(2 if flags else 0)


if __name__ == "__main__":
    main()
