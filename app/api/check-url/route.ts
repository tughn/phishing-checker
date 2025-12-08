import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

// Simple in-memory rate limiting (for production, use Redis or database)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

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
    // Rate limiting
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: 'Rate limit exceeded. Please try again later.' },
        { status: 429 }
      );
    }

    const { url } = await request.json();

    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      );
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
      results.checks.virustotal = {
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected,
        harmless: stats.harmless,
        total_engines: Object.keys(vtResponse.data.data.attributes.last_analysis_results).length,
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

    // Calculate Risk Score
    let riskScore = 0;
    let maxScore = 100;

    // VirusTotal scoring (40 points)
    if (results.checks.virustotal?.malicious) {
      riskScore += Math.min(results.checks.virustotal.malicious * 10, 40);
    }

    // Safe Browsing scoring (40 points)
    if (results.checks.safeBrowsing?.threats?.length > 0) {
      riskScore += 40;
    }

    // SSL scoring (20 points)
    if (!results.checks.ssl?.secure) {
      riskScore += 20;
    }

    results.riskScore = Math.min(riskScore, maxScore);
    results.riskLevel =
      riskScore >= 70 ? 'HIGH' :
      riskScore >= 40 ? 'MEDIUM' :
      riskScore >= 20 ? 'LOW' :
      'SAFE';

    return NextResponse.json(results);

  } catch (error: any) {
    console.error('Error checking URL:', error);
    return NextResponse.json(
      { error: 'Failed to check URL', details: error.message },
      { status: 500 }
    );
  }
}
