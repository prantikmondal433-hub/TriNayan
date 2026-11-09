import type { Metadata } from "next";
import { Roboto, Noto_Sans_Devanagari, Noto_Sans_Bengali } from "next/font/google";
import "./globals.css";
import { LanguageProvider } from "@/context/LanguageContext";

const roboto = Roboto({
  weight: ["300", "400", "500", "700", "900"],
  subsets: ["latin"],
  variable: "--font-roboto",
  display: "swap",
});

const notoDevanagari = Noto_Sans_Devanagari({
  weight: ["400", "500", "600", "700"],
  subsets: ["devanagari"],
  variable: "--font-noto-hi",
  display: "swap",
});

const notoBengali = Noto_Sans_Bengali({
  weight: ["400", "500", "600", "700"],
  subsets: ["bengali"],
  variable: "--font-noto-bn",
  display: "swap",
});

export const metadata: Metadata = {
  title: "TriNayan – Explainable AI Website Trust & Phishing Sentinel",
  description:
    "Passive website security scanner evaluating SSL certificate chains, brand impersonation, security headers, and community threat intelligence.",
  icons: {
    icon: "/logo.png",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`dark ${roboto.variable} ${notoDevanagari.variable} ${notoBengali.variable}`}
    >
      <body className="antialiased min-h-screen bg-[var(--tn-bg)] text-[var(--tn-text)] selection:bg-blue-600 selection:text-white">
        <LanguageProvider>{children}</LanguageProvider>
      </body>
    </html>
  );
}
