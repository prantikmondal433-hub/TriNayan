import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TrustLens – Website Trust Analysis",
  description:
    "AI-powered platform that scores websites for phishing, certificate issues, and security flaws with one explainable verdict.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">{children}</body>
    </html>
  );
}
