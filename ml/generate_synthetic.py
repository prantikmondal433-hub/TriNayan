"""Generate a synthetic phishing/benign URL dataset for development.

For real training, download PhishTank + Tranco into ml/data/.
This script creates a ~2000-row CSV that exercises all url_features.
"""
from __future__ import annotations

import csv
import os
import random
import string
import sys

# Add backend to path so we can import url_features
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


# ── Templates ────────────────────────────────────────────────────────

SAFE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
    "quora.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "irctc.co.in",
    "flipkart.com", "myntra.com", "swiggy.com", "zomato.com", "uidai.gov.in",
    "incometax.gov.in", "digilocker.gov.in", "paytm.com", "phonepe.com",
    "npci.org.in", "rbi.org.in", "iitb.ac.in", "iitd.ac.in", "du.ac.in",
    "ugc.ac.in", "nta.ac.in", "cbse.gov.in", "bits-pilani.ac.in",
    "coursera.org", "udemy.com", "khanacademy.org", "edx.org",
    "airbnb.com", "booking.com", "uber.com", "spotify.com",
]

SAFE_PATHS = [
    "/", "/about", "/contact", "/login", "/search?q=test",
    "/products/item-123", "/blog/2024/article-title",
    "/en/help", "/docs/getting-started", "/pricing",
    "/download", "/careers", "/privacy-policy",
]

PHISHING_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                 ".buzz", ".club", ".info", ".work", ".click", ".icu"]

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "password", "suspend", "alert", "urgent",
    "unlock", "expire", "wallet", "payment", "refund", "reward",
]

BRAND_TARGETS = [
    "google", "facebook", "amazon", "apple", "microsoft", "paypal",
    "netflix", "sbi", "hdfc", "icici", "paytm", "phonepe", "aadhaar",
    "irctc", "linkedin", "instagram", "whatsapp",
]

SHORTENERS = ["bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd"]


def _random_string(length: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _make_safe_url() -> str:
    """Generate a plausible benign URL."""
    domain = random.choice(SAFE_DOMAINS)
    path = random.choice(SAFE_PATHS)
    scheme = "https" if random.random() > 0.1 else "http"
    www = "www." if random.random() > 0.5 else ""
    return f"{scheme}://{www}{domain}{path}"


def _make_phishing_url() -> str:
    """Generate a realistic-looking phishing URL."""
    strategy = random.choice([
        "typo", "keyword_stuff", "ip_host", "deep_subdomain",
        "shortener", "punycode_sim", "random_domain", "brand_keyword",
        "at_sign", "long_path",
    ])

    if strategy == "typo":
        brand = random.choice(BRAND_TARGETS)
        # Introduce a typo
        typos = [
            brand + random.choice("0123"),
            brand[:-1] + random.choice("xyz"),
            brand[:len(brand)//2] + "-" + brand[len(brand)//2:],
        ]
        typo = random.choice(typos)
        tld = random.choice(PHISHING_TLDS)
        kw = random.choice(PHISHING_KEYWORDS)
        return f"http://{typo}{tld}/{kw}"

    elif strategy == "keyword_stuff":
        kws = random.sample(PHISHING_KEYWORDS, k=random.randint(2, 4))
        domain = "-".join(kws) + random.choice(PHISHING_TLDS)
        return f"http://{domain}/index.html"

    elif strategy == "ip_host":
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        kw = random.choice(PHISHING_KEYWORDS)
        return f"http://{ip}/{kw}"

    elif strategy == "deep_subdomain":
        brand = random.choice(BRAND_TARGETS)
        subs = ".".join(_random_string(random.randint(3, 6))
                        for _ in range(random.randint(3, 5)))
        tld = random.choice(PHISHING_TLDS)
        return f"http://{subs}.{brand}-{random.choice(PHISHING_KEYWORDS)}{tld}/login"

    elif strategy == "shortener":
        shortener = random.choice(SHORTENERS)
        return f"https://{shortener}/{_random_string(6)}"

    elif strategy == "punycode_sim":
        brand = random.choice(BRAND_TARGETS)
        return f"http://xn--{brand[:3]}{_random_string(4)}.com/{random.choice(PHISHING_KEYWORDS)}"

    elif strategy == "random_domain":
        domain = _random_string(random.randint(12, 25))
        tld = random.choice(PHISHING_TLDS)
        return f"http://{domain}{tld}/{_random_string(8)}"

    elif strategy == "brand_keyword":
        brand = random.choice(BRAND_TARGETS)
        kw = random.choice(PHISHING_KEYWORDS)
        tld = random.choice(PHISHING_TLDS)
        return f"http://{brand}-{kw}{tld}/{kw}.html"

    elif strategy == "at_sign":
        brand = random.choice(BRAND_TARGETS)
        return f"http://{brand}.com@evil{_random_string(4)}{random.choice(PHISHING_TLDS)}/login"

    else:  # long_path
        brand = random.choice(BRAND_TARGETS)
        tld = random.choice(PHISHING_TLDS)
        long_path = "/".join(_random_string(random.randint(5, 10))
                             for _ in range(random.randint(4, 8)))
        return f"http://{brand}-{random.choice(PHISHING_KEYWORDS)}{tld}/{long_path}"


def generate_dataset(n_safe: int = 1000, n_phish: int = 1000, seed: int = 42) -> list[dict]:
    """Return a list of dicts with 'url' and 'label' (0=safe, 1=phishing)."""
    random.seed(seed)
    rows = []
    for _ in range(n_safe):
        rows.append({"url": _make_safe_url(), "label": 0})
    for _ in range(n_phish):
        rows.append({"url": _make_phishing_url(), "label": 1})
    random.shuffle(rows)
    return rows


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "synthetic_dataset.csv")

    rows = generate_dataset(n_safe=1000, n_phish=1000)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} URLs → {out_path}")
    print(f"  Safe:     {sum(1 for r in rows if r['label'] == 0)}")
    print(f"  Phishing: {sum(1 for r in rows if r['label'] == 1)}")


if __name__ == "__main__":
    main()

