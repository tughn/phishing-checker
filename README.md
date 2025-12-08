# Sendmarc Phishing URL Checker

A free tool to check URLs for phishing, malware, and security threats using multiple security engines.

## Features

- ✅ **VirusTotal Integration** - Scans URLs against 60+ security engines
- ✅ **Google Safe Browsing** - Checks against Google's threat database
- ✅ **SSL/TLS Validation** - Verifies HTTPS security
- ✅ **Risk Scoring** - 0-100 risk score with threat level classification
- ✅ **Sendmarc Branding** - Clean, professional UI matching Sendmarc style
- ✅ **Free to Use** - 500 checks/day (VirusTotal limit)

## Tech Stack

- **Next.js 16** - React framework with App Router
- **TypeScript** - Type-safe code
- **Tailwind CSS** - Utility-first styling
- **VirusTotal API** - Malware/phishing detection
- **Google Safe Browsing API** - Threat database
- **Vercel** - Deployment platform

## Setup

### Prerequisites

- Node.js 18+ installed
- VirusTotal API key
- Google Safe Browsing API key

### Installation

1. Install dependencies:
```bash
npm install
```

2. Create `.env.local` file:
```bash
VIRUSTOTAL_API_KEY=your_virustotal_api_key
NEXT_PUBLIC_GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
```

3. Run development server:
```bash
npm run dev
```

4. Open [http://localhost:3000](http://localhost:3000)

## API Endpoints

### POST /api/check-url

Check a URL for security threats.

**Request:**
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

## Risk Scoring

| Risk Score | Level  | Color  |
|------------|--------|--------|
| 0-19       | SAFE   | Green  |
| 20-39      | LOW    | Yellow |
| 40-69      | MEDIUM | Orange |
| 70-100     | HIGH   | Red    |

**Scoring Breakdown:**
- VirusTotal malicious detections: up to 40 points
- Google Safe Browsing threats: 40 points
- No HTTPS: 20 points

## Deployment

### Deploy to Vercel

1. Push to GitHub:
```bash
git init
git add .
git commit -m "Initial commit: Phishing URL Checker"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

2. Import to Vercel:
   - Go to https://vercel.com/new
   - Import your GitHub repository
   - Add environment variables:
     - `VIRUSTOTAL_API_KEY`
     - `NEXT_PUBLIC_GOOGLE_SAFE_BROWSING_API_KEY`
   - Deploy!

## Usage Limits (Free Tier)

- **VirusTotal**: 500 requests/day, 4 requests/minute
- **Google Safe Browsing**: 10,000 requests/day
- **Vercel**: Unlimited hosting

## Project Structure

```
phishing-checker/
├── app/
│   ├── api/
│   │   └── check-url/
│   │       └── route.ts          # API endpoint
│   ├── globals.css               # Sendmarc branding
│   ├── layout.tsx                # Root layout
│   └── page.tsx                  # Main UI
├── public/                        # Static assets
├── .env.local                     # API keys (not in git)
├── .gitignore                     # Excludes .env files
├── next.config.ts                 # Next.js config
├── package.json                   # Dependencies
└── README.md                      # This file
```

## Security

- ✅ API keys stored in `.env.local` (excluded from Git)
- ✅ Server-side API calls (keys never exposed to client)
- ✅ Input validation on all requests
- ✅ CORS protection via Next.js
- ✅ Rate limiting via API providers

## Development

### Start development server:
```bash
npm run dev
```

### Build for production:
```bash
npm run build
```

### Run production build:
```bash
npm start
```

## Testing

Test with these URLs:

**Safe URLs:**
- `https://google.com`
- `https://sendmarc.com`

**Known Malicious (for testing):**
- `http://malware.wicar.org/data/eicar.com`
- Check VirusTotal's recent submissions

## Troubleshooting

### "URL not found" on VirusTotal
- The URL hasn't been scanned yet
- The tool will automatically submit it for scanning
- Check again in 2-3 minutes

### Image not loading
- Verify `help.sendmarc.com` is allowed in `next.config.ts`
- Check internet connection

### API errors
- Verify API keys in `.env.local`
- Check rate limits (500/day for VirusTotal)
- Ensure keys are valid

## License

Proprietary - Sendmarc Internal Tool

## Support

For issues or questions, contact the Sendmarc development team.

---

**Built with ❤️ by Sendmarc**
