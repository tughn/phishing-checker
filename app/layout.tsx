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

  const faqSchema = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    "mainEntity": [
      {
        "@type": "Question",
        "name": "What is phishing and how does it work?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Phishing is a cyberattack where criminals impersonate legitimate organizations to steal sensitive information like passwords, credit card numbers, or personal data. Attackers send fraudulent emails, text messages, or create fake websites that appear authentic, tricking users into clicking malicious links or providing confidential information. Modern phishing attacks have become increasingly sophisticated, with threats like spear phishing targeting specific individuals."
        }
      },
      {
        "@type": "Question",
        "name": "How does this phishing URL checker work?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Our phishing checker analyzes URLs using multiple security layers: VirusTotal scans URLs against 70+ antivirus engines, Google Safe Browsing checks against continuously updated unsafe web resources, SSL Certificate Analysis verifies HTTPS encryption, and Domain Age & WHOIS identifies newly registered domains often used in phishing campaigns. You can paste individual URLs or entire email content for automatic link extraction and analysis."
        }
      },
      {
        "@type": "Question",
        "name": "How do I interpret the scan results?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "The tool provides clear verdicts: SUSPICIOUS means the URL has been flagged by security engines, has concerning characteristics, or matches known phishing patterns - do not click these links. CLEAN means no security engines detected threats, the domain has proper SSL encryption, and no suspicious characteristics were found. The VirusTotal results show how many security engines flagged the URL, with even a few detections indicating a potential threat."
        }
      },
      {
        "@type": "Question",
        "name": "What are the warning signs of a phishing URL?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Key warning signs include: misspelled domains (paypa1.com instead of paypal.com), suspicious subdomains, lack of HTTPS encryption on sites handling sensitive information, shortened URLs that hide the real destination, and unusual urgency in messaging. Learning to identify these signs helps protect against phishing attacks before clicking suspicious links."
        }
      },
      {
        "@type": "Question",
        "name": "How can email authentication prevent phishing attacks?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Email authentication protocols are critical defenses: DMARC tells email servers how to handle emails that fail authentication, SPF specifies which mail servers are authorized to send emails on behalf of your domain, and DKIM adds a digital signature to verify emails haven't been tampered with. Together, these protocols make it significantly harder for attackers to impersonate legitimate domains, with DMARC enforcement blocking up to 99% of email-based phishing attacks."
        }
      },
      {
        "@type": "Question",
        "name": "What should I do if I find a suspicious link?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "If a URL is identified as suspicious: do not click the link as even visiting a malicious site can compromise security, delete the email or message without forwarding it, report it to your IT security team or the impersonated organization, and verify directly by contacting the organization using official contact information (not from the suspicious email). These behavioral changes help prevent phishing attacks and protect your organization."
        }
      }
    ]
  };

  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(faqSchema) }}
        />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
