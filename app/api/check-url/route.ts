import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';
import * as tls from 'tls';
import * as net from 'net';
import { URL } from 'url';

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

  if (limit.count >= 5) {  // 5 requests per minute
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

// Helper: Check OpenPhish database
async function checkOpenPhish(url: string): Promise<any> {
  try {
    const response = await axios.get('https://openphish.com/feed.txt', { timeout: 10000 });
    const phishingUrls = response.data.split('\n').filter((line: string) => line.trim());
    const isListed = phishingUrls.some((phishUrl: string) => url.includes(phishUrl) || phishUrl.includes(url));

    return {
      listed: isListed,
      source: 'OpenPhish',
      checked: true
    };
  } catch (error) {
    return { error: 'OpenPhish check failed', checked: false };
  }
}

// Helper: Check URLhaus database
async function checkURLhaus(url: string): Promise<any> {
  try {
    const response = await axios.post(
      'https://urlhaus-api.abuse.ch/v1/url/',
      new URLSearchParams({ url }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 10000
      }
    );

    if (response.data.query_status === 'ok') {
      return {
        listed: true,
        threat: response.data.threat || 'malware',
        tags: response.data.tags || [],
        source: 'URLhaus',
        checked: true
      };
    }

    return { listed: false, source: 'URLhaus', checked: true };
  } catch (error) {
    return { error: 'URLhaus check failed', checked: false };
  }
}

// Helper: Get SSL certificate details
async function getSSLCertificate(hostname: string, port: number = 443): Promise<any> {
  return new Promise((resolve) => {
    const socket = net.connect(port, hostname, () => {
      const secureSocket = tls.connect({
        socket: socket,
        servername: hostname,
        rejectUnauthorized: false
      }, () => {
        const cert = secureSocket.getPeerCertificate();
        secureSocket.end();

        if (cert && Object.keys(cert).length > 0) {
          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const certAge = Math.floor((now.getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24));

          resolve({
            issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysUntilExpiry: Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)),
            certAge: certAge,
            subject: cert.subject?.CN || hostname,
            isLetsEncrypt: cert.issuer?.O?.includes("Let's Encrypt") || false
          });
        } else {
          resolve({ error: 'No certificate found' });
        }
      });

      secureSocket.on('error', () => {
        resolve({ error: 'Failed to retrieve certificate' });
      });
    });

    socket.on('error', () => {
      resolve({ error: 'Failed to connect' });
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({ error: 'Connection timeout' });
    });
  });
}

// Helper: Follow redirect chain
async function followRedirects(url: string): Promise<any> {
  const chain: Array<{url: string, status: number}> = [];
  let currentUrl = url;
  let redirectCount = 0;
  const maxRedirects = 10;

  try {
    while (redirectCount < maxRedirects) {
      const response = await axios.get(currentUrl, {
        maxRedirects: 0,
        validateStatus: (status) => status >= 200 && status < 400,
        timeout: 10000
      });

      chain.push({ url: currentUrl, status: response.status });

      if (response.status >= 300 && response.status < 400 && response.headers.location) {
        const nextUrl = new URL(response.headers.location, currentUrl).href;
        currentUrl = nextUrl;
        redirectCount++;
      } else {
        break;
      }
    }

    const domains = chain.map(c => new URL(c.url).hostname);
    const uniqueDomains = [...new Set(domains)];

    return {
      chain,
      redirectCount: chain.length - 1,
      finalUrl: chain[chain.length - 1]?.url || url,
      crossDomain: uniqueDomains.length > 1,
      domains: uniqueDomains
    };
  } catch (error: any) {
    if (error.response && error.response.status >= 300 && error.response.status < 400) {
      chain.push({ url: currentUrl, status: error.response.status });
      if (error.response.headers.location) {
        const nextUrl = new URL(error.response.headers.location, currentUrl).href;
        return followRedirects(nextUrl);
      }
    }

    return {
      chain: chain.length > 0 ? chain : [{ url, status: 0 }],
      error: 'Failed to follow redirects',
      redirectCount: chain.length - 1
    };
  }
}

// Helper: Perform WHOIS lookup (simplified - uses whois-json package)
async function performWHOIS(domain: string): Promise<any> {
  try {
    // For now, we'll use a public WHOIS API
    const response = await axios.get(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_free&domainName=${domain}&outputFormat=JSON`, {
      timeout: 10000
    });

    const data = response.data?.WhoisRecord;
    if (data) {
      const createdDate = data.createdDate ? new Date(data.createdDate) : null;
      const now = new Date();
      const domainAge = createdDate ? Math.floor((now.getTime() - createdDate.getTime()) / (1000 * 60 * 60 * 24)) : null;

      return {
        registrar: data.registrarName || 'Unknown',
        createdDate: data.createdDate,
        expiresDate: data.expiresDate,
        updatedDate: data.updatedDate,
        domainAge: domainAge,
        isNew: domainAge !== null && domainAge < 30,
        privacyProtected: data.registrant?.organization?.toLowerCase().includes('privacy') ||
                          data.registrant?.organization?.toLowerCase().includes('redacted') || false
      };
    }

    return { error: 'WHOIS data not available' };
  } catch (error) {
    // Fallback: just calculate basic info
    return {
      error: 'WHOIS lookup failed - using free tier limits',
      note: 'Domain age check requires premium WHOIS API for detailed info'
    };
  }
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

    // 3. OpenPhish Check
    try {
      results.checks.openphish = await checkOpenPhish(validUrl);
    } catch (error) {
      results.checks.openphish = { error: 'OpenPhish check failed' };
    }

    // 4. URLhaus Check
    try {
      results.checks.urlhaus = await checkURLhaus(validUrl);
    } catch (error) {
      results.checks.urlhaus = { error: 'URLhaus check failed' };
    }

    // 5. SSL Certificate Details
    try {
      const urlObj = new URL(validUrl);
      if (urlObj.protocol === 'https:') {
        const certDetails = await getSSLCertificate(urlObj.hostname);
        results.checks.ssl = {
          protocol: urlObj.protocol,
          secure: true,
          certificate: certDetails
        };
      } else {
        results.checks.ssl = {
          protocol: urlObj.protocol,
          secure: false,
        };
      }
    } catch (error) {
      results.checks.ssl = {
        error: 'SSL check failed',
      };
    }

    // 6. WHOIS & Domain Age
    try {
      const urlObj = new URL(validUrl);
      const domain = urlObj.hostname;
      const whoisData = await performWHOIS(domain);

      results.checks.whois = {
        hostname: domain,
        ...whoisData
      };
    } catch (error) {
      results.checks.whois = {
        error: 'WHOIS check failed',
      };
    }

    // 7. Redirect Chain Analysis
    try {
      const redirectData = await followRedirects(validUrl);
      results.checks.redirects = redirectData;
    } catch (error) {
      results.checks.redirects = {
        error: 'Redirect analysis failed',
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

    // Check OpenPhish
    if (results.checks.openphish?.listed) {
      isSuspicious = true;
      suspicionReasons.push('Listed in OpenPhish phishing database');
    }

    // Check URLhaus
    if (results.checks.urlhaus?.listed) {
      isSuspicious = true;
      suspicionReasons.push(`Listed in URLhaus as ${results.checks.urlhaus.threat}`);
    }

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

    // Check domain age
    if (results.checks.whois?.isNew) {
      suspicionReasons.push(`Domain registered within last 30 days (${results.checks.whois.domainAge} days old)`);
    }

    // Check Let's Encrypt + new domain combination
    if (results.checks.ssl?.certificate?.isLetsEncrypt && results.checks.whois?.isNew) {
      if (!suspicionReasons.some(r => r.includes('Domain registered'))) {
        suspicionReasons.push('New domain with free SSL certificate');
      }
    }

    // Check suspicious redirects
    if (results.checks.redirects?.crossDomain && results.checks.redirects?.redirectCount > 2) {
      suspicionReasons.push(`Multiple cross-domain redirects (${results.checks.redirects.redirectCount} hops)`);
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
