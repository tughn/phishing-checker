import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Free Phishing URL Checker & Email Link Scanner | Sendmarc",
  description: "Check any URL or email for phishing threats instantly. Free phishing link checker with VirusTotal & Google Safe Browsing. Analyze suspicious links and protect your business from email phishing attacks.",
  keywords: [
    "phishing checker",
    "phishing url scanner",
    "check phishing link",
    "email link checker",
    "malware url scanner",
    "suspicious link checker",
    "url safety checker",
    "phishing detection tool",
    "free phishing scanner",
    "email security tool"
  ],
  authors: [{ name: "Sendmarc", url: "https://www.sendmarc.com" }],
  creator: "Sendmarc",
  publisher: "Sendmarc",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://tools.sendmarc.com/phishing-checker",
    title: "Free Phishing URL Checker & Email Link Scanner | Sendmarc",
    description: "Check any URL or email for phishing threats instantly. Free phishing link checker with VirusTotal & Google Safe Browsing.",
    siteName: "Sendmarc Security Tools",
    images: [
      {
        url: "https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg",
        width: 1200,
        height: 630,
        alt: "Sendmarc Phishing Checker Tool",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Free Phishing URL Checker | Sendmarc",
    description: "Check any URL or email for phishing threats instantly. Free tool with VirusTotal & Google Safe Browsing.",
    images: ["https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg"],
  },
  alternates: {
    canonical: "https://tools.sendmarc.com/phishing-checker",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    "name": "Sendmarc Phishing URL Checker",
    "description": "Free phishing URL checker and email link scanner. Check suspicious links for phishing threats using VirusTotal and Google Safe Browsing.",
    "url": "https://tools.sendmarc.com/phishing-checker",
    "applicationCategory": "SecurityApplication",
    "operatingSystem": "Any",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "provider": {
      "@type": "Organization",
      "name": "Sendmarc",
      "url": "https://www.sendmarc.com",
      "logo": "https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg"
    },
    "featureList": [
      "Check URLs for phishing threats",
      "Scan email content for malicious links",
      "VirusTotal integration",
      "Google Safe Browsing verification",
      "Batch URL checking",
      "Real-time threat detection"
    ]
  };

  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
