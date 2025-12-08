# Sendmarc Phishing URL Checker

**Live Demo:** [https://phishing-checker-5y86g148o-tughan-caydavuls-projects.vercel.app](https://phishing-checker-5y86g148o-tughan-caydavuls-projects.vercel.app)

A free, production-ready tool to check URLs and email content for phishing threats using VirusTotal and Google Safe Browsing.

---

## Features

- **Single URL Analysis** - Check individual URLs for security threats
- **Email Content Scanner** - Paste entire emails to automatically extract and analyze all links
- **Multi-Engine Detection** - Powered by VirusTotal (60+ security engines) and Google Safe Browsing
- **Risk Scoring** - 0-100 risk assessment with detailed threat breakdown
- **Real-time Analysis** - Instant results with comprehensive security reports
- **Rate Limited** - Built-in protection against abuse (10 requests/minute/IP)

---

## Technology Stack

**Frontend**
- Next.js 16 with App Router
- TypeScript
- Tailwind CSS
- React 19

**Backend**
- Next.js API Routes (Serverless)
- VirusTotal API v3
- Google Safe Browsing API v4
- Axios for HTTP requests

**Infrastructure**
- Vercel (Edge Functions)
- Server-side API key management
- In-memory rate limiting

---

## Prerequisites

- Node.js 18 or higher
- VirusTotal API key ([Get one here](https://www.virustotal.com/gui/my-apikey))
- Google Safe Browsing API key ([Get one here](https://console.cloud.google.com/apis/credentials))

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/tughn/sendmarc-phishing-checker.git
cd sendmarc-phishing-checker
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Create a `.env.local` file in the root directory:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
```

### 4. Run development server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### 5. Build for production

```bash
npm run build
npm start
```

---

## Deployment

### Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/tughn/sendmarc-phishing-checker)

1. Connect your GitHub repository to Vercel
2. Add environment variables in Vercel dashboard:
   - `VIRUSTOTAL_API_KEY`
   - `GOOGLE_SAFE_BROWSING_API_KEY`
3. Deploy

---

## API Reference

### POST `/api/check-url`

Check a URL for security threats.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "timestamp": "2025-12-08T10:00:00.000Z",
  "riskScore": 0,
  "riskLevel": "SAFE",
  "checks": {
    "virustotal": {
      "malicious": 0,
      "suspicious": 0,
      "undetected": 45,
      "harmless": 55,
      "total_engines": 100
    },
    "safeBrowsing": {
      "safe": true,
      "threats": []
    },
    "ssl": {
      "protocol": "https:",
      "secure": true
    },
    "domain": {
      "hostname": "example.com"
    }
  }
}
```

---

## Security

- All API keys are server-side only and never exposed to the client
- Rate limiting prevents abuse (10 requests/minute per IP)
- Input validation on all endpoints
- HTTPS enforced in production
- Environment variables excluded from version control

**Security Audit Score:** 9/10 - Production ready

See [SECURITY.md](SECURITY.md) for detailed security documentation.

---

## Project Structure

```
phishing-checker/
├── app/
│   ├── api/check-url/route.ts    # API endpoint with rate limiting
│   ├── page.tsx                   # Main UI with dual input modes
│   ├── layout.tsx                 # SEO metadata and structured data
│   └── globals.css                # Sendmarc brand styling
├── .env.local                     # Environment variables (not in Git)
├── .env.example                   # Template for required variables
├── DEPLOYMENT.md                  # Deployment guide
├── SECURITY.md                    # Security audit report
├── SEO_STRATEGY.md                # SEO optimization guide
└── README.md                      # This file
```

---

## Usage Limits

**Free Tier:**
- VirusTotal: 500 requests/day
- Google Safe Browsing: 10,000 requests/day
- Vercel: Unlimited hosting

---

## Contributing

This is a Sendmarc internal tool. For issues or suggestions, please contact the development team.

---

## License

Proprietary - Sendmarc

---

## Support

- **Documentation:** See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed setup instructions
- **Security:** See [SECURITY.md](SECURITY.md) for security best practices
- **SEO:** See [SEO_STRATEGY.md](SEO_STRATEGY.md) for ranking strategy

---

**Built by Sendmarc** - Email security made simple
