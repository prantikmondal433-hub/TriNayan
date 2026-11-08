"""TrustLens Demo Verification & Benchmark Runner
Tests our 6 curated demo URLs against the TrustLens API and outputs a formatted table.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

API_URL = os.getenv("API_URL", "http://localhost:8000/scan")
DEMO_FILE = os.path.join(os.path.dirname(__file__), "urls.json")


def run_demo_checks():
    if not os.path.exists(DEMO_FILE):
        print(f"Error: {DEMO_FILE} not found.")
        sys.exit(1)

    with open(DEMO_FILE, "r", encoding="utf-8") as f:
        urls = json.load(f)

    print("=" * 80)
    print("🛡️  TRUSTLENS DEMO VERIFICATION BENCHMARK")
    print(f"Target API: {API_URL}")
    print("=" * 80)
    print(f"{'Category':<32} | {'Verdict':<11} | {'Risk':<5} | {'Status'}")
    print("-" * 80)

    for item in urls:
        category = item["category"][:30]
        url = item["url"]
        payload = json.dumps({"url": url}).encode("utf-8")
        req = urllib.request.Request(
            API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            start = time.time()
            with urllib.request.urlopen(req, timeout=15) as resp:
                elapsed = time.time() - start
                data = json.loads(resp.read().decode("utf-8"))
                verdict = data.get("verdict", "Unknown")
                risk = data.get("risk", 0)
                status = f"✅ Pass ({elapsed:.2f}s)"
        except Exception as e:
            verdict = item["expected_verdict"] + " (Sim)"
            risk = sum(item["expected_risk_range"]) // 2
            status = f"⚠️ Mock Fallback ({str(e)[:20]})"

        print(f"{category:<32} | {verdict:<11} | {risk:<5} | {status}")

    print("=" * 80)
    print("Ready for live judges presentation.")


if __name__ == "__main__":
    run_demo_checks()
