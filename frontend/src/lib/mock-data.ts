import { ScanResponse } from "./types";

export const MOCK_SCAN_RESPONSE: ScanResponse = {
  url: "https://sbi-login-secure-verify.com",
  risk: 87,
  verdict: "Dangerous",
  reasons: [
    "Domain registered only 3 days ago",
    "Imitates sbi.co.in (State Bank of India)",
    "Certificate key reused across 40 unrelated domains",
    "Password form posts data to a foreign domain",
    "No HSTS or CSP security headers found",
  ],
  recommended_action:
    "Do not enter any credentials. Close this site immediately and report it.",
  scanned_at: new Date().toISOString(),
  scan_id: "mock-001",
  modules: {
    threat: {
      module: "threat",
      score: 91,
      confidence: 0.95,
      error: null,
      findings: [
        {
          id: "THREAT_BRAND_IMPERSONATION",
          severity: "critical",
          title: "Imitates sbi.co.in (State Bank of India)",
          detail:
            "The domain 'sbi-login-secure-verify.com' uses keywords and structure nearly identical to sbi.co.in. Edit distance: 2.",
          evidence: { brand: "sbi.co.in", edit_distance: 2 },
        },
        {
          id: "THREAT_YOUNG_DOMAIN",
          severity: "high",
          title: "Domain registered 3 days ago",
          detail:
            "Very new domains are a strong phishing indicator. Legitimate banks use long-established domains.",
          evidence: { domain_age_days: 3 },
        },
        {
          id: "THREAT_SUSPICIOUS_KEYWORDS",
          severity: "medium",
          title: "URL contains suspicious keywords: login, secure, verify",
          detail:
            "These words are commonly used in phishing URLs to appear legitimate.",
          evidence: { keywords: ["login", "secure", "verify"] },
        },
        {
          id: "THREAT_PASSWORD_FORM_FOREIGN",
          severity: "critical",
          title: "Login form submits credentials to a different domain",
          detail:
            "The password input field posts data to 'data-harvester.ru', not to sbi.co.in.",
          evidence: { form_action: "https://data-harvester.ru/collect" },
        },
      ],
    },
    websec: {
      module: "websec",
      score: 72,
      confidence: 0.88,
      error: null,
      findings: [
        {
          id: "WEBSEC_MISSING_HSTS",
          severity: "high",
          title: "HSTS header missing",
          detail:
            "Without Strict-Transport-Security, the browser can be downgraded to HTTP.",
          evidence: {},
        },
        {
          id: "WEBSEC_MISSING_CSP",
          severity: "medium",
          title: "Content-Security-Policy header missing",
          detail: "No CSP means scripts from any source can run on this page.",
          evidence: {},
        },
        {
          id: "WEBSEC_COOKIE_NO_SECURE",
          severity: "medium",
          title: "Session cookie missing Secure flag",
          detail: "Cookie can be sent over plain HTTP connections.",
          evidence: { cookie: "SESSID" },
        },
        {
          id: "WEBSEC_EXPOSED_ENV",
          severity: "critical",
          title: "/.env file is publicly accessible",
          detail:
            "The server's environment variables file is exposed, potentially leaking API keys and passwords.",
          evidence: { path: "/.env", status: 200 },
        },
      ],
    },
    cert: {
      module: "cert",
      score: 78,
      confidence: 0.92,
      error: null,
      findings: [
        {
          id: "CERT_KEY_REUSE",
          severity: "critical",
          title: "Certificate key reused across 40 unrelated domains",
          detail:
            "The public key in this certificate appears on 40 other domains with no apparent relationship — a strong signal of poor key generation practices or a shared fraudulent infrastructure.",
          evidence: { reuse_count: 40 },
        },
        {
          id: "CERT_RECENT_ISSUANCE",
          severity: "high",
          title: "Certificate issued 3 days ago",
          detail:
            "Attackers obtain new certificates quickly. Very recent issuance combined with other signals is suspicious.",
          evidence: { issued_days_ago: 3 },
        },
        {
          id: "CERT_MISSING_SCT",
          severity: "medium",
          title: "No Certificate Transparency (SCT) extension found",
          detail:
            "SCTs prove the certificate was logged publicly. Missing SCTs may indicate the cert bypasses normal logging.",
          evidence: {},
        },
      ],
    },
    community: {
      module: "community",
      score: 95,
      confidence: 0.99,
      error: null,
      findings: [
        {
          id: "COMMUNITY_CONFIRMED_PHISHING",
          severity: "critical",
          title: "Confirmed phishing by 24 community reports",
          detail:
            "24 users reported this URL as phishing within the last 48 hours. It also appears in the OpenPhish and URLhaus blocklists.",
          evidence: { report_count: 24, blocklists: ["OpenPhish", "URLhaus"] },
        },
      ],
    },
  },
};

export const MOCK_SAFE_RESPONSE: ScanResponse = {
  url: "https://github.com",
  risk: 4,
  verdict: "Safe",
  reasons: [
    "Domain registered over 20 years ago",
    "Valid certificate with strong RSA-4096 key",
    "All security headers present (HSTS, CSP, X-Frame-Options)",
    "No community reports",
  ],
  recommended_action: "This site appears safe to use.",
  scanned_at: new Date().toISOString(),
  scan_id: "mock-002",
  modules: {
    threat: {
      module: "threat",
      score: 2,
      confidence: 0.99,
      error: null,
      findings: [],
    },
    websec: {
      module: "websec",
      score: 5,
      confidence: 0.95,
      error: null,
      findings: [],
    },
    cert: {
      module: "cert",
      score: 3,
      confidence: 0.98,
      error: null,
      findings: [],
    },
    community: {
      module: "community",
      score: 0,
      confidence: 1.0,
      error: null,
      findings: [],
    },
  },
};
