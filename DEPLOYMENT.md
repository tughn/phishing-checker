# Deployment Guide - Sendmarc Phishing URL Checker

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ installed
- VirusTotal API key
- Google Safe Browsing API key
- GitHub account
- Vercel account (free)

---

## 📦 Local Development

### 1. Clone & Install
```bash
git clone <your-repo-url>
cd phishing-checker
npm install
```

### 2. Set Up Environment Variables
```bash
# Copy example file
cp .env.example .env.local

# Edit .env.local and add your API keys
```

### 3. Run Development Server
```bash
npm run dev
```

Open http://localhost:3000

### 4. Build for Production
```bash
npm run build
npm start
```

---

## 🔐 Security Checklist

✅ **API Keys** - Stored in `.env.local` (NOT committed to Git)
✅ **Server-Side Only** - All API calls happen on the server
✅ **Rate Limiting** - 10 requests/minute per IP
✅ **Input Validation** - URL format validation
✅ **Error Handling** - Graceful error messages

### Common Security Mistakes to Avoid:
- ❌ Never use `NEXT_PUBLIC_` prefix for API keys
- ❌ Never commit `.env.local` to Git
- ❌ Never expose API keys in client-side code
- ❌ Never skip input validation

---

## 🌐 Deploy to Vercel (Recommended)

### Step 1: Push to GitHub
```bash
cd phishing-checker
git init
git add .
git commit -m "Initial commit: Sendmarc Phishing URL Checker"
git branch -M main

# Create repo on GitHub first, then:
git remote add origin https://github.com/YOUR_USERNAME/sendmarc-phishing-checker.git
git push -u origin main
```

### Step 2: Deploy to Vercel
1. Go to https://vercel.com/new
2. Import your GitHub repository
3. Configure project:
   - **Framework Preset:** Next.js
   - **Root Directory:** `./`
   - **Build Command:** `npm run build`
   - **Output Directory:** `.next`

### Step 3: Add Environment Variables
In Vercel dashboard, go to **Settings → Environment Variables** and add:

```
VIRUSTOTAL_API_KEY=your_actual_virustotal_key
GOOGLE_SAFE_BROWSING_API_KEY=your_actual_google_key
```

### Step 4: Deploy!
Click "Deploy" - Vercel will build and deploy automatically.

---

## 🔄 Continuous Deployment

Once set up, every push to `main` branch will:
1. Trigger automatic build
2. Run tests (if configured)
3. Deploy to production

---

## 🐛 Troubleshooting

### API Keys Not Working
```bash
# Check if keys are set
vercel env ls

# Pull production env vars locally (for testing)
vercel env pull .env.local
```

### Build Fails
```bash
# Clear cache and rebuild
rm -rf .next
npm run build
```

### Rate Limit Issues
- Current limit: 10 requests/minute/IP
- For higher limits, upgrade to Redis-based rate limiting
- Or use Vercel Edge Config

---

## 📊 Monitoring

### Vercel Analytics (Free)
- Go to your project → Analytics tab
- View real-time traffic, errors, and performance

### Check Logs
```bash
vercel logs
```

---

## 🔧 Advanced Configuration

### Custom Domain
1. Vercel Dashboard → Domains
2. Add your domain
3. Update DNS records as instructed

### Edge Functions (Better Performance)
Already configured - API routes run on Vercel Edge Network globally.

### Redis Rate Limiting (Scalable)
For production with high traffic:
1. Sign up for Upstash Redis (free tier)
2. Replace in-memory rate limiting in `api/check-url/route.ts`

---

## 📈 Scaling

### Free Tier Limits
- **Vercel:** 100 GB bandwidth/month
- **VirusTotal:** 500 requests/day
- **Google Safe Browsing:** 10,000 requests/day

### When to Upgrade
- If you exceed 500 URL checks/day → Upgrade VirusTotal
- If you need custom domain SSL → Already included in Vercel free tier
- If you need team collaboration → Vercel Pro ($20/month)

---

## 🛡️ Production Checklist

Before going live:

- [ ] API keys added to Vercel
- [ ] Custom domain configured (optional)
- [ ] Test all features in production
- [ ] Set up monitoring/alerts
- [ ] Add Terms of Service link
- [ ] Add Privacy Policy link
- [ ] Test rate limiting
- [ ] Test with malicious URLs
- [ ] Test with safe URLs
- [ ] Mobile responsive check

---

## 📞 Support

- **Vercel Docs:** https://vercel.com/docs
- **Next.js Docs:** https://nextjs.org/docs
- **VirusTotal API:** https://developers.virustotal.com/
- **Google Safe Browsing:** https://developers.google.com/safe-browsing

---

**Built with ❤️ by Sendmarc**
