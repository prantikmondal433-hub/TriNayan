# TrustLens – Hackathon Pitch Deck (10 Slides)

---

## Slide 1: Title & Hook
* **Title:** **TrustLens** – Intelligent Unified Web Security & Cryptographic Trust Sentinel
* **Subtitle:** Moving beyond the padlock: Explainable AI detection of phishing and rogue certificates.
* **Team:** TriNayan (P1: Core/Backend, P2: Threat/ML, P3: Certs/WebSec, P4: UI/Extension/Pitch)
* **Tagline:** *"A padlock proves encryption, not trustworthiness."*

---

## Slide 2: The Problem (The False Sense of Security)
* Attackers have weaponized HTTPS: over 80% of modern phishing sites display valid SSL padlocks.
* The recent CA weak-key incident (e.g. eMudhra TLS case study) exposed how fragile Certificate Authority trust chains can be.
* Existing solutions are fragmented:
  * Antivirus / DNS filters: Slow to catch zero-hour domains (<24 hrs).
  * Vulnerability scanners: Too technical, built for developers, not citizens.
  * Phishing blocklists: Reactive, outdated within hours.
* **Core Pain Point:** Ordinary citizens and organizations lack a single, understandable answer to: *"Is this website safe, and why?"*

---

## Slide 3: The Solution – TrustLens
* A unified, accessible security intelligence engine delivering:
  1. **Single Risk Score (0–100)**: Transparent, weighted risk metric.
  2. **Three-Tier Verdict**: `Safe` (<30), `Suspicious` (30–69), `Dangerous` (≥70).
  3. **Top 3–5 Plain-Language Explanations**: E.g., *"Domain registered 3 days ago"*, *"Imitates SBI"*, *"SSL key shared across 40 unrelated domains"*.
  4. **Multi-Platform Access**: Web App, Chrome Extension, and Developer API.

---

## Slide 4: System Architecture
```
  [Chrome Extension]        [Web Application]        [REST API]
            │                       │                     │
            └───────────────────────┴─────────────────────┘
                                    │
                         FastAPI Gateway + Cache
                                    │
      ┌──────────────┬──────────────┴──────────────┬──────────────┐
      ▼              ▼                             ▼              ▼
[Threat Module]  [WebSec Module]             [Cert Trust]   [Community]
 • Lexical ML     • Security Headers (HSTS)   • CT Logs      • User reports
 • Brand Lookal   • Cookie flags (HttpOnly)   • Key Reuse    • Open feeds
 • WHOIS telemetry• Exposed sensitive files   • Watchlist    • Reputation
      └──────────────┬─────────────────────────────┴──────────────┘
                     ▼
             [Risk Fusion Engine]
         (0.35 Threat + 0.25 Cert + 0.20 Websec + 0.20 Community)
                     ▼
            Explainable Verdict & Action
```

---

## Slide 5: Differentiator – Deep Certificate Trust (Module 3)
* **Why others fail:** Most scanners check only if SSL is expired or self-signed.
* **What TrustLens does differently:**
  * **Certificate Transparency (CT) Monitoring:** Discovers sudden issuance spikes and unauthorized rogue certs via crt.sh.
  * **Public Key Reuse Detection:** Flags when identical cryptographic keys appear across unrelated domains (a key footprint of fraudulent infrastructure).
  * **CA Watchlist & Crypto Hygiene:** Flags weak RSA (<2048), SHA-1 hashes, and distrusted or under-investigation Certificate Authorities.
  * **Brand Impersonation + Cert Correlation:** If a 3-day-old domain imitating an Indian bank has an unexpected CA cert, it triggers an instant Critical override.

---

## Slide 6: Multi-Vector Threat Analysis & Passive Hygiene (Modules 1 & 2)
* **Threat & ML Engine:**
  * XGBoost classifier trained on real phishing vs benign datasets.
  * Brand lookalike detection: Homoglyphs and Damerau-Levenshtein edit-distance against top Indian banks (SBI, HDFC, ICICI), UPI apps (Paytm, PhonePe), and government portals.
  * Domain age heuristics (WHOIS creation date).
* **Passive Web Security Hygiene:**
  * Strictly **PASSIVE** scanning: Zero aggressive port-scanning or fuzzing.
  * Audits HSTS, CSP, X-Frame-Options, HttpOnly cookies, and accidental file disclosures (e.g., exposed `.env`).

---

## Slide 7: Collaborative Threat Intelligence (Module 4)
* **Crowdsourced Defense Loop:**
  * Users report suspicious sites directly from the Web UI or Extension toolbar.
  * Reputation-weighted voting prevents spam reports.
  * Ingests open feeds (URLhaus, OpenPhish).
  * Validated community findings feed back into our ML model as continuous training telemetry.

---

## Slide 8: Live Product Demo (3 Minutes)
1. **Scenario 1 – Legitimate Banking:** Scan `https://www.onlinesbi.sbi` → Instant Green (Safe, Risk: 4/100).
2. **Scenario 2 – Zero-Hour Phishing:** Scan `https://sbi-login-secure-verify.com` → Instant Red (Dangerous, Risk: 87/100) with clear plain-language reasons.
3. **Scenario 3 – Certificate Inspector:** Expand the interactive cert chain showing Leaf → Intermediate → Root with key size verification.
4. **Scenario 4 – Chrome Extension in Action:** Visit a suspicious URL → In-page warning banner automatically alerts the user before credentials can be entered.

---

## Slide 9: Responsible AI & Limitations
* **Honest Security Posture:**
  * We report **probabilistic risk signals**, not legal proof of CA compromise or operator intent.
  * **Zero Aggressive Action:** Strictly passive GET/HEAD queries; protected by SSRF guard rails blocking private IPs (RFC 1918) and metadata endpoints.
  * **Privacy First:** Minimal extension permissions (`activeTab`, `storage`); no form input or credentials are ever recorded.

---

## Slide 10: Future Roadmap & Impact
* **Phase 1 (Post-Hackathon):** Native integration with Indian Cyber Crime Coordination Centre (I4C) reporting feeds.
* **Phase 2:** Automated DNS sinkhole suggestions for enterprise network administrators.
* **Phase 3:** Mobile extension (Firefox Android / Safari iOS) and SMS phishing scanner for regional languages (Hindi, Bengali, Tamil).
* **Closing Statement:** *"TrustLens gives every internet user clarity, transparency, and actionable cryptographic confidence."*
