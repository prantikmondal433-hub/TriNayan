import type { Metadata } from "next";
import "./globals.css";
import { LanguageProvider } from "@/context/LanguageContext";

export const metadata: Metadata = {
  title: "TrustLens – AI Website Trust & Phishing Sentinel",
  description:
    "AI-powered platform that scores websites for phishing, certificate issues, and security flaws with one explainable verdict.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">
        <LanguageProvider>{children}</LanguageProvider>
      </body>
    </html>
  );
}
