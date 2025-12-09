import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

// Simple in-memory rate limiting (for production, use Redis or database)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
// Track verified Turnstile tokens to allow reuse within a session
const verifiedTokens = new Map<string, { ip: string; verifiedAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const limit = rateLimitMap.get(ip);

  if (!limit || now > limit.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + 60000 }); // 1 minute window
    return true;
  }

  if (limit.count >= 10) {  // 10 requests per minute
    return false;
  }

  limit.count++;
  return true;
}

function cleanupExpiredTokens() {
  const now = Date.now();
  const fiveMinutes = 5 * 60 * 1000;
  for (const [token, data] of verifiedTokens.entries()) {
    if (now - data.verifiedAt > fiveMinutes) {
      verifiedTokens.delete(token);
    }
  }
}

interface VirusTotalResponse {
  data: {
    attributes: {
      last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
      };
      last_analysis_results: Record<string, any>;
    };
  };
}

interface SafeBrowsingResponse {
  matches?: Array<{
    threatType: string;
    platformType: string;
    threat: {
      url: string;
    };
  }>;
}

export async function POST(request: NextRequest) {
  try {
    // Cleanup expired tokens periodically
    cleanupExpiredTokens();

    // Rate limiting
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: 'Rate limit exceeded. Please try again later.' },
        { status: 429 }
      );
    }

    const { url, turnstileToken } = await request.json();

    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      );
    }

    // Verify Turnstile token
    if (!turnstileToken) {
      return NextResponse.json(
        { error: 'Security verification required' },
        { status: 400 }
      );
    }

    // Check if token was already verified for this IP
    const cachedToken = verifiedTokens.get(turnstileToken);
    if (cachedToken && cachedToken.ip === ip) {
      // Token already verified, allow reuse
      console.log('Reusing verified Turnstile token');
    } else {
      // New token, verify with Cloudflare
      const turnstileResponse = await fetch(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            secret: process.env.TURNSTILE_SECRET_KEY,
            response: turnstileToken,
            remoteip: ip,
          }),
        }
      );

      const turnstileData = await turnstileResponse.json();

      if (!turnstileData.success) {
        return NextResponse.json(
          { error: 'Security verification failed. Please try again.' },
          { status: 403 }
        );
      }

      // Cache the verified token
      verifiedTokens.set(turnstileToken, { ip, verifiedAt: Date.now() });
    }

    // Check API keys
    if (!VIRUSTOTAL_API_KEY || !GOOGLE_SAFE_BROWSING_API_KEY) {
      return NextResponse.json(
        { error: 'API keys not configured' },
        { status: 500 }
      );
    }

    // Validate URL format
    let validUrl: string;
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      validUrl = urlObj.href;
    } catch (e) {
      return NextResponse.json(
        { error: 'Invalid URL format' },
        { status: 400 }
      );
    }

    const results: any = {
      url: validUrl,
      timestamp: new Date().toISOString(),
      checks: {},
    };

    // 1. VirusTotal Check
    try {
      const vtUrlId = Buffer.from(validUrl).toString('base64').replace(/=/g, '');

      const vtResponse = await axios.get<VirusTotalResponse>(
        `https://www.virustotal.com/api/v3/urls/${vtUrlId}`,
        {
          headers: {
            'x-apikey': VIRUSTOTAL_API_KEY,
          },
          timeout: 10000,
        }
      );

      const stats = vtResponse.data.data.attributes.last_analysis_stats;
      const analysisResults = vtResponse.data.data.attributes.last_analysis_results;

      // Extract which engines flagged it
      const detections = Object.entries(analysisResults)
        .filter(([_, result]: [string, any]) => result.category === 'malicious' || result.category === 'suspicious')
        .map(([engine, result]: [string, any]) => ({
          engine,
          category: result.category,
          result: result.result
        }));

      results.checks.virustotal = {
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected,
        harmless: stats.harmless,
        total_engines: Object.keys(analysisResults).length,
        detections: detections
      };
    } catch (error: any) {
      if (error.response?.status === 404) {
        // URL not yet scanned, submit it
        try {
          const scanResponse = await axios.post(
            'https://www.virustotal.com/api/v3/urls',
            new URLSearchParams({ url: validUrl }),
            {
              headers: {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded',
              },
            }
          );
          results.checks.virustotal = {
            status: 'scanning',
            message: 'URL submitted for scanning. Please check again in a few minutes.',
          };
        } catch (submitError) {
          results.checks.virustotal = {
            error: 'Failed to submit URL for scanning',
          };
        }
      } else {
        results.checks.virustotal = {
          error: 'VirusTotal check failed',
        };
      }
    }

    // 2. Google Safe Browsing Check
    try {
      const safeBrowsingResponse = await axios.post<SafeBrowsingResponse>(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
        {
          client: {
            clientId: 'sendmarc-phishing-checker',
            clientVersion: '1.0.0',
          },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: validUrl }],
          },
        },
        { timeout: 10000 }
      );

      results.checks.safeBrowsing = {
        safe: !safeBrowsingResponse.data.matches || safeBrowsingResponse.data.matches.length === 0,
        threats: safeBrowsingResponse.data.matches || [],
      };
    } catch (error) {
      results.checks.safeBrowsing = {
        error: 'Safe Browsing check failed',
      };
    }

    // 3. SSL Check
    try {
      const urlObj = new URL(validUrl);
      results.checks.ssl = {
        protocol: urlObj.protocol,
        secure: urlObj.protocol === 'https:',
      };
    } catch (error) {
      results.checks.ssl = {
        error: 'SSL check failed',
      };
    }

    // 4. Domain Age Check (basic)
    try {
      const urlObj = new URL(validUrl);
      const domain = urlObj.hostname;

      // This is a simplified check - in production you'd use a proper WHOIS API
      results.checks.domain = {
        hostname: domain,
        note: 'Domain age check requires WHOIS API (not implemented in free version)',
      };
    } catch (error) {
      results.checks.domain = {
        error: 'Domain check failed',
      };
    }

    // Binary Classification (Suspicious/Clean)
    // If ANY reputable engine flags it, it's suspicious
    const premiumEngines = [
      'Kaspersky', 'Sophos', 'Fortinet', 'Avira', 'ESET',
      'BitDefender', 'G-Data', 'Webroot', 'Antiy-AVL', 'AlphaSOC',
      'Emsisoft', 'Trustwave', 'Lionic', 'Forcepoint ThreatSeeker'
    ];

    let isSuspicious = false;
    let suspicionReasons: string[] = [];

    // Check if Google Safe Browsing flagged it
    if (results.checks.safeBrowsing?.threats?.length > 0) {
      isSuspicious = true;
      suspicionReasons.push('Google Safe Browsing detected threats');
    }

    // Check if any premium engine flagged it as malicious
    if (results.checks.virustotal?.detections) {
      const premiumDetections = results.checks.virustotal.detections.filter(
        (d: any) => d.category === 'malicious' && premiumEngines.includes(d.engine)
      );
      if (premiumDetections.length > 0) {
        isSuspicious = true;
        suspicionReasons.push(`${premiumDetections.length} trusted security engine${premiumDetections.length > 1 ? 's' : ''} flagged this`);
      }
    }

    // Check if multiple engines flagged it (even if not premium)
    if (results.checks.virustotal?.malicious >= 3) {
      isSuspicious = true;
      if (!suspicionReasons.some(r => r.includes('security engine'))) {
        suspicionReasons.push(`${results.checks.virustotal.malicious} security engines flagged this`);
      }
    }

    results.isSuspicious = isSuspicious;
    results.suspicionReasons = suspicionReasons;
    results.verdict = isSuspicious ? 'SUSPICIOUS' : 'CLEAN';

    return NextResponse.json(results);

  } catch (error: any) {
    console.error('Error checking URL:', error);
    return NextResponse.json(
      { error: 'Failed to check URL', details: error.message },
      { status: 500 }
    );
  }
}
