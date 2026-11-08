# TrustLens Chrome Extension (Manifest V3)

Real-time browser sentinel protecting users against credential harvesting, fraudulent certificates, and phishing links.

## How to Install in Chrome / Edge / Brave

1. Open your browser and navigate to `chrome://extensions/` (or `edge://extensions/`).
2. Toggle on **"Developer mode"** in the top right corner.
3. Click the **"Load unpacked"** button in the top left.
4. Select the `extension/` folder inside this repository:
   ```
   C:\Users\User\TriNayan\extension
   ```
5. The **TrustLens** icon will appear in your toolbar!

## Features

- **Passive In-Page Warning Banner**: When visiting a dangerous or lookalike site, a non-blocking banner warns the user and provides a one-click link to the full TrustLens explanation.
- **Toolbar Popup Verdict**: Click the TrustLens badge anytime to view the active tab's risk score (0–100), verdict badge (Safe / Suspicious / Dangerous), and top reasons.
- **Seamless Web App Integration**: One-click jumps directly to `http://localhost:3000/result` for deep cryptographic chain inspection or `http://localhost:3000/report` to submit threat telemetry.

## Privacy & Security Disclosures

- **Passive Only**: Does NOT modify forms, steal input, or alter traffic.
- **Minimal Permissions**: Requests only `activeTab` and `storage`.
- **SSRF & Privacy Guards**: All backend verification adheres to RFC 1918 private IP blocking and rate limiting.
