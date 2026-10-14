# phishing-analyzer

Flags phishing indicators in `.eml` files: spoofed senders, failed SPF/DKIM/DMARC, and deceptive links.

It's a small triage tool. Point it at a saved email and it prints a labeled report showing *why* the message looks suspicious, not just a yes/no. It's read-only (never fetches a URL or sends anything), so it's safe to run on live samples, and it uses the Python standard library only.

## What it checks

** Header consistency**
- Display name spoofing, like `"PayPal Support <service@paypal.com>"` sent from a totally different domain
- Reply-To pointing to a different domain than From (classic BEC move)
- Return-Path mismatches (softer signal, bulk senders do this legitimately)

** Authentication results**
- Reads the SPF, DKIM, and DMARC verdicts the receiving server wrote into `Authentication-Results` (falls back to `Received-SPF`)

** Links**
- Link text that shows one domain but goes to another
- Brand names used in hostnames the brand doesn't own (`paypal-secure.example`)
- URL shorteners, raw IP addresses, punycode/IDN look-alikes, and `user@host` tricks
- `javascript:` links and links with no http(s) scheme
- All URLs in the output are defanged (`hxxps://evil[.]com`) so they can't be clicked

## Usage

```bash
python phishing_analyzer.py message.eml
```

Try it with the included samples:

```bash
python phishing_analyzer.py samples/phishing_example.eml
python phishing_analyzer.py samples/clean_example.eml
```

To get a `.eml` file: in Outlook or Gmail, open the message and use "Save as" / "Download message". In Gmail it's under the three-dot menu → **Download message**.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Nothing flagged |
| 1 | Couldn't read or parse the file |
| 2 | At least one indicator flagged |

So it can be used in scripts, e.g. `python phishing_analyzer.py x.eml || echo "needs review"`.

## Sample output

```
========================================================================
  Phishing Email Analysis
  File: samples/phishing_example.eml
========================================================================

1. Header consistency (From / Reply-To / Return-Path)
------------------------------------------------------------------------
  [ ok ] From: mailer-x.example
  [FLAG] Display name spoof: Display name "PayPal Support <service@paypal.com>" shows an address at paypal.com, but it was really sent from mailer-x.example.
  [FLAG] Reply-To mismatch: Reply-To (freemail.example) is a different domain than From (mailer-x.example).
  [ ok ] Return-Path: mailer-x.example

2. Authentication results (SPF / DKIM / DMARC)
------------------------------------------------------------------------
  [FLAG] SPF: SPF=softfail — failed.
  [WARN] DKIM: DKIM=none — not enforced.
  [FLAG] DMARC: DMARC=fail — failed.

3. Link analysis
------------------------------------------------------------------------
  [FLAG] Suspicious link: hxxps://paypal-secure[.]example/login
           - uses "paypal" in the hostname but the real domain is "paypal-secure.example"
           - text shows "www.paypal.com" but goes to "paypal-secure.example"
  [FLAG] Suspicious link: hxxps://bit[.]ly/3fakeLink
           - is a shortener (bit.ly) — real destination is hidden
  [FLAG] Suspicious link: hxxp://203[.]0[.]113[.]45/update
           - points at a raw IP (203.0.113.45) instead of a domain

========================================================================
  Summary: 7 flag(s), 1 warning(s)
  Verdict: HIGH — multiple strong phishing indicators.
========================================================================
```

## Limitations

Being upfront about what this doesn't do:

- **Auth results are read, not re-verified.** An attacker can forge an `Authentication-Results` header in the raw file. Only the one your own mail gateway stamped is trustworthy.
- **Domain matching is simplified.** It treats the last two labels as the registrable domain, so `example.co.uk` comes out as `co.uk`. A production tool would use the Public Suffix List (e.g. `tldextract`).
- **Brand list is small.** It's illustrative, and brand matching uses whole words, so mashed-together names like `securepaypal.com` slip through.
- **Attachments aren't checked yet.** A lot of real phishing comes through attachments rather than links.
- **No reputation lookups.** It doesn't check domains or URLs against threat intel feeds, on purpose, to stay offline and read-only.

## Roadmap

- [ ] Attachment checks (risky types, double extensions, macro-enabled Office files)
- [ ] `--json` output for feeding results into a SIEM or ticketing system
- [ ] Analyze a whole folder of `.eml` files
- [ ] Look-alike domain detection (`paypa1.com`, `rnicrosoft.com`)
- [ ] Unit tests

## Notes

The sample emails in `samples/` are fake and use reserved example domains and IPs.
