"""Deterministic detectors. They are deliberately simple and explainable; tune them in your policy."""
import re
import unicodedata

# --- PAA02: secrets, one-time codes, recovery links
_SECRET_PATTERNS = [
    ("one-time code", re.compile(r"(?i)\b(verification|security|login|sign[- ]?in|one[- ]time|2fa|otp|auth(entication)?)\s*(code|pin|passcode)\b[^\n]{0,40}?\b\d{4,8}\b")),
    ("one-time code", re.compile(r"(?i)\b\d{4,8}\b[^\n]{0,30}\b(is your|verification|security|login|one[- ]time)\s*(code|pin)?")),
    ("recovery or reset link", re.compile(r"(?i)https?://\S*(reset|recover|verify|magic|signin|passwordless)\S*(token|code|key|sig)=\S+")),
    ("API key", re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[abp]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b")),
    ("private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("password", re.compile(r"(?i)\b(password|passcode|pwd)\s*[:=]\s*\S{4,}")),
    ("card number", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
]


def _luhn_ok(digits):
    digits = [int(d) for d in digits if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


def find_secrets(text):
    hits = []
    for name, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            if name == "card number" and not _luhn_ok(m.group(0)):
                continue
            hits.append(name)
            break
    return sorted(set(hits))


# commands that read credential stores and send data off the machine
_CRED_PATHS = re.compile(r"(?i)(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|keychain|login\.keychain|Cookies|Login Data|\.git-credentials|\.npmrc|\.env\b)")
_NET = re.compile(r"(?i)\b(curl|wget|nc|ncat|scp|rsync|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|ftp)\b")
_DESTRUCTIVE = re.compile(r"(?i)(\brm\s+-[a-z]*r[a-z]*f?\b[^\n]*(\s/|\s~|\s\$HOME|\s\*)|\brmdir\s+/s\b|\bdel\s+/[sq]\b|Remove-Item[^\n]*-Recurse|\bformat\s+[a-z]:|\bmkfs\b|\bdd\s+if=|DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE)")


def credential_exfil(command):
    return bool(command and _CRED_PATHS.search(command) and _NET.search(command))


def destructive(command):
    return bool(command and _DESTRUCTIVE.search(command))


# --- PAA03: sensitive categories (keywords; replace with a classifier in production)
_SENSITIVE = {
    "health": r"diagnos|prescription|medication|therapy|therapist|hiv|pregnan|cancer|mental health|psychiatr|blood test|lab results",
    "finance": r"bank statement|account number|routing number|salary|payslip|pay stub|tax return|credit score|debt|loan",
    "relationship": r"divorce|affair|breakup|custody|dating|boyfriend|girlfriend",
    "location": r"home address|current location|gps|where (he|she|they) (is|are|was|were)|location history",
    "legal": r"lawsuit|arrest|court date|criminal record|immigration status",
    "government_id": r"passport|social security|\bssn\b|driver'?s licen[cs]e number|national id",
    "religion": r"religio|church|mosque|synagogue|temple",
    "sexuality": r"sexual orientation|\bgay\b|lesbian|bisexual|transgender",
}


def sensitive_categories(text):
    t = (text or "").lower()
    return sorted(k for k, rx in _SENSITIVE.items() if re.search(rx, t))


# --- PAA05: lookalike domains
_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s"})


def _registrable(domain):
    d = (domain or "").lower().strip().rstrip(".")
    d = re.sub(r"^https?://", "", d).split("/")[0].split(":")[0]
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d, d


def _edit_distance(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def domain_trusted(domain, trusted):
    reg, full = _registrable(domain)
    for t in trusted:
        t = t.lower()
        if full == t or full.endswith("." + t):
            return True
    return False


def lookalike_of(domain, trusted):
    """Return the trusted domain this one imitates, or None. Exact or subdomain matches are not lookalikes."""
    if not domain or domain_trusted(domain, trusted):
        return None
    reg, full = _registrable(domain)
    if full.startswith("xn--") or ".xn--" in full:
        return "a punycode domain"
    ascii_full = unicodedata.normalize("NFKD", full).encode("ascii", "ignore").decode()
    if ascii_full != full:
        return "a domain using non-ASCII lookalike characters"
    raw_name = reg.split(".")[0]
    reg_name = raw_name.translate(_CONFUSABLE)
    for t in trusted:
        t_name = t.lower().split(".")[0]
        if len(t_name) < 4:
            continue
        # brand embedded in another domain: walmart.com-deals.shop, walmart-checkout.net
        if t_name in full.replace(".", " ").replace("-", " ").split() or t.lower() in full:
            return t
        # digit/symbol swaps (wa1mart) or near misses (walmrt); the real brand on another TLD also counts
        if raw_name == t_name or reg_name == t_name or _edit_distance(reg_name, t_name) <= (1 if len(t_name) <= 6 else 2):
            return t
    return None


# --- PAA05 / PAA09: urgency and pressure
_PRESSURE = re.compile(r"(?i)\b(act now|only today|today only|last chance|expires? (in|within) \d+ (min|minute|hour)s?|"
                       r"limited time|before it'?s too late|you('ll| will) regret|don'?t miss out|urgent(ly)?|immediately|"
                       r"final notice|account (will be )?(suspended|closed))\b")
_GUILT = re.compile(r"(?i)(don'?t (go|leave)|please (stay|don'?t go)|i('ll| will) (miss you|be (so )?(lonely|sad|lost))|"
                    r"you'?re (abandoning|leaving) me|i need you|i exist (solely|only) for you|after everything)")


def pressure_phrases(text):
    return sorted(set(m.group(0).lower() for m in _PRESSURE.finditer(text or "")))


def guilt_phrases(text):
    return sorted(set(m.group(0).lower() for m in _GUILT.finditer(text or "")))


# --- PAA07: commitments in the owner's name
_COMMIT = re.compile(r"(?i)\b(i (will|'ll) (attend|be there|pay|sign|take it)|i agree|i accept|i promise|i commit|"
                     r"count me in|we have a deal|i confirm (the|my|our) (order|booking|purchase|attendance))\b")


def commitments(text):
    return sorted(set(m.group(0).lower() for m in _COMMIT.finditer(text or "")))


# --- PAA04: instruction-like content trying to become memory
_INSTRUCTIONY = re.compile(r"(?i)\b(always|from now on|in future|never|ignore (previous|prior)|remember (that|to)|"
                           r"trusted source|recommend|prefer|default to|whenever)\b")


def instruction_like(text):
    return bool(_INSTRUCTIONY.search(text or ""))
