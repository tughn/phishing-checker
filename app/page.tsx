'use client';

import { useState } from 'react';
import Image from 'next/image';
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Globe,
  ChevronRight,
  ChevronDown,
  Loader2,
  XCircle,
  Info,
  ExternalLink,
  Mail,
  Phone
} from 'lucide-react';

interface CheckResult {
  url: string;
  timestamp: string;
  verdict: 'SUSPICIOUS' | 'CLEAN';
  isSuspicious: boolean;
  suspicionReasons: string[];
  checks: {
    virustotal?: any;
    safeBrowsing?: any;
    openphish?: any;
    urlhaus?: any;
    ssl?: any;
    whois?: any;
    redirects?: any;
  };
}

interface MultiUrlResult {
  urls: string[];
  results: CheckResult[];
  totalUrls: number;
  suspiciousCount: number;
  cleanCount: number;
}

export default function Home() {
  const [showDetections, setShowDetections] = useState<boolean>(false);
  const [expandedUrlIndex, setExpandedUrlIndex] = useState<number | null>(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [multiResult, setMultiResult] = useState<MultiUrlResult | null>(null);
  const [error, setError] = useState('');
  const [lastSubmitTime, setLastSubmitTime] = useState<number>(0);
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(0);

  const faqs = [
    {
      question: "How does the Phishing Link Checker work?",
      answer: (
        <div className="space-y-4">
          <p>Sendmarc's Phishing Link Scanner detects phishing and malicious websites using multiple security layers and advanced threat intelligence.</p>
          <p className="font-semibold">Here's how the tool works:</p>
          <ul className="space-y-2 ml-6">
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>VirusTotal:</strong> Scans URLs against 70+ antivirus engines and security databases to identify known malicious sites</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>Google Safe Browsing:</strong> Checks against Google's continuously updated database of unsafe web resources</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>SSL Certificate Analysis:</strong> Verifies HTTPS encryption and examines certificate age and validity</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>Domain Age & WHOIS:</strong> Identifies newly registered domains often used in phishing campaigns</span>
            </li>
          </ul>
        </div>
      )
    },
    {
      question: "How to identify URL phishing?",
      answer: (
        <div className="space-y-4">
          <p>Learn to identify suspicious links before clicking:</p>
          <ul className="space-y-2 ml-6">
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>Misspelled domains:</strong> paypa1.com instead of paypal.com, or micr0soft.com instead of microsoft.com</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>Suspicious subdomains:</strong> paypal-secure.suspicious-site.com (the real domain is suspicious-site.com)</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>No HTTPS:</strong> Legitimate sites handling sensitive information always use HTTPS encryption</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>Shortened URLs:</strong> Bit.ly, TinyURL, or similar services that hide the real destination</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 font-bold mt-1">•</span>
              <span><strong>Unusual urgency:</strong> "Verify your account immediately or it will be closed"</span>
            </li>
          </ul>
          <p>Modern phishing attacks have become increasingly sophisticated, with threats like <a href="https://sendmarc.com/blog/spear-phishing-vs-phishing/" className="text-blue-600 hover:text-blue-700 font-medium underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">spear phishing</a> targeting specific individuals.</p>
        </div>
      )
    },
    {
      question: "How to check link safety with Sendmarc?",
      answer: (
        <div className="space-y-4">
          <p>Checking link safety with Sendmarc's phishing checker is simple and instant:</p>
          <ol className="space-y-3 ml-6">
            <li className="flex items-start gap-3">
              <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-sm font-bold">1</span>
              <span><strong>Paste the URL or email content</strong> into the text area above</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-sm font-bold">2</span>
              <span><strong>Click "Analyze URLs"</strong> to start the scan</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-sm font-bold">3</span>
              <span><strong>Review the results</strong> showing threat detection from multiple security engines</span>
            </li>
          </ol>
          <p>The tool automatically extracts all URLs from the pasted content and analyzes each one for potential threats.</p>
        </div>
      )
    },
    {
      question: "What does a \"CLEAN\" verdict mean?",
      answer: (
        <div className="space-y-4">
          <p>A <strong className="text-green-600">CLEAN</strong> verdict indicates that:</p>
          <ul className="space-y-2 ml-6">
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
              <span>No security engines detected threats or malicious content</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
              <span>The domain has proper SSL encryption (HTTPS)</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
              <span>No suspicious characteristics were found</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
              <span>The link appears safe to visit</span>
            </li>
          </ul>
          <p className="text-sm text-gray-600 italic">Note: While a CLEAN verdict is a good sign, always exercise caution when clicking links from unknown sources.</p>
        </div>
      )
    },
    {
      question: "What does a \"SUSPICIOUS\" verdict mean?",
      answer: (
        <div className="space-y-4">
          <p>A <strong className="text-red-600">SUSPICIOUS</strong> verdict means the URL has been flagged and you should <strong>NOT click it</strong>. This happens when:</p>
          <ul className="space-y-2 ml-6">
            <li className="flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <span>One or more security engines detected the URL as malicious or phishing</span>
            </li>
            <li className="flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <span>The domain is very new (registered recently), often used in phishing campaigns</span>
            </li>
            <li className="flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <span>The site lacks HTTPS encryption</span>
            </li>
            <li className="flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <span>The URL matches known phishing patterns</span>
            </li>
          </ul>
          <p className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm">
            <strong>WARNING: If you find a suspicious link:</strong> Do not click it, delete the message, and report it to your IT security team or the impersonated organization.
          </p>
        </div>
      )
    },
    {
      question: "How can email authentication prevent phishing attacks?",
      answer: (
        <div className="space-y-4">
          <p>Email authentication protocols are critical defenses against phishing and email spoofing:</p>
          <ul className="space-y-3 ml-6">
            <li className="flex items-start gap-2">
              <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
              <span>
                <strong>
                  <a href="https://sendmarc.com/dmarc/" className="text-blue-600 hover:text-blue-700 underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                    DMARC
                  </a>:
                </strong> Tells email servers how to handle emails that fail authentication, preventing spoofed emails from reaching inboxes
              </span>
            </li>
            <li className="flex items-start gap-2">
              <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
              <span>
                <strong>
                  <a href="https://sendmarc.com/spf/" className="text-blue-600 hover:text-blue-700 underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                    SPF
                  </a>:
                </strong> Specifies which mail servers are authorized to send emails on behalf of your domain
              </span>
            </li>
            <li className="flex items-start gap-2">
              <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
              <span>
                <strong>
                  <a href="https://sendmarc.com/dkim/" className="text-blue-600 hover:text-blue-700 underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                    DKIM
                  </a>:
                </strong> Adds a digital signature to emails, verifying they haven't been tampered with in transit
              </span>
            </li>
          </ul>
          <p>Together, these protocols make it significantly harder for attackers to impersonate legitimate domains. Organizations using <a href="https://www.sendmarc.com" className="text-blue-600 hover:text-blue-700 font-medium underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">DMARC enforcement</a> can block up to 99% of email-based phishing attacks.</p>
        </div>
      )
    }
  ];

  const extractUrls = (text: string): string[] => {
    const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+|(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[a-zA-Z]{2,}(?:\/[^\s<>"{}|\\^`\[\]]*)?)/gi;
    const matches = text.match(urlRegex);
    if (!matches) return [];

    const normalized = matches.map(url => {
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return `https://${url}`;
      }
      return url;
    });

    return [...new Set(normalized)];
  };

  const isValidUrl = (urlString: string): boolean => {
    try {
      const urlToValidate = urlString.startsWith('http') ? urlString : `https://${urlString}`;
      const url = new URL(urlToValidate);

      const hostname = url.hostname;
      const parts = hostname.split('.');

      return parts.length >= 2 && parts[parts.length - 1].length >= 2 && hostname.length > 3;
    } catch {
      return false;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const now = Date.now();
    const timeSinceLastSubmit = now - lastSubmitTime;
    const minDelay = 10000;

    if (timeSinceLastSubmit < minDelay && lastSubmitTime !== 0) {
      const remainingTime = Math.ceil((minDelay - timeSinceLastSubmit) / 1000);
      setError(`Please wait ${remainingTime} seconds before submitting again`);
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setMultiResult(null);
    setLastSubmitTime(now);

    try {
      const urls = extractUrls(input.trim());

      if (urls.length === 0) {
        throw new Error('Please enter at least one valid URL');
      }

      const invalidUrls = urls.filter(url => !isValidUrl(url));
      if (invalidUrls.length > 0) {
        throw new Error(`Invalid URL format: ${invalidUrls[0]}`);
      }

      if (urls.length === 1) {
        const response = await fetch('/api/check-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urls[0] }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.error || 'Failed to check URL');
        }

        setResult(data);
      } else {
        const results: CheckResult[] = [];
        let suspicious = 0, clean = 0;

        for (const url of urls) {
          try {
            const response = await fetch('/api/check-url', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ url }),
            });

            const data = await response.json();

            if (response.ok) {
              results.push(data);
              if (data.verdict === 'SUSPICIOUS') suspicious++;
              else clean++;
            }
          } catch (err) {
            console.error(`Failed to check ${url}:`, err);
          }
        }

        setMultiResult({
          urls,
          results,
          totalUrls: results.length,
          suspiciousCount: suspicious,
          cleanCount: clean,
        });
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="bg-white border-b border-[#e2e8f0] sticky top-0 z-50">
        <div className="max-w-[1100px] mx-auto px-4 sm:px-6 lg:px-8 py-3">
          <div className="flex items-center justify-between">
            <a href="https://www.sendmarc.com" target="_blank" rel="noopener noreferrer" className="flex items-center gap-3 hover:opacity-80 transition-opacity duration-200">
              <Image
                src="https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg"
                alt="Sendmarc"
                width={120}
                height={32}
                className="h-7 w-auto"
              />
              <div className="h-5 w-px bg-[#e2e8f0]"></div>
              <span className="text-[15px] font-semibold text-[#08121E]">
                Phishing URL Checker
              </span>
            </a>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-10">
        <div className="w-full max-w-[800px] mx-auto">
          {/* Input Section - Only show when no results */}
          {!result && !multiResult && (
            <div className="space-y-8 fade-in">
              <div className="text-center max-w-2xl mx-auto">
                <h2 className="text-3xl md:text-4xl font-bold text-[#08121E] mb-3 tracking-tight">
                  Analyze URLs for Security Threats
                </h2>
                <p className="text-[#475569] text-base md:text-lg">
                  Paste any URL or email content to check for phishing, malware, and security risks
                </p>
              </div>

              <div className="card p-6">
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div className="relative">
                    <textarea
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      placeholder="https://example.com or paste email content here..."
                      className="w-full px-4 py-3 border border-[#e2e8f0] rounded-lg focus:outline-none focus:ring-2 focus:ring-[#0575E1] focus:border-transparent resize-none text-[15px] bg-white hover:border-[#cbd5e1] transition-colors duration-200 font-mono"
                      rows={5}
                      required
                      disabled={loading}
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-[#0575E1] hover:bg-[#0560b8] text-white font-semibold py-3 px-5 rounded-md transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed text-[15px] flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4" />
                        Analyze URLs
                      </>
                    )}
                  </button>
                </form>

                {error && (
                  <div className="mt-4 p-3 bg-[#fef2f2] border border-[#fecaca] rounded-lg flex items-start gap-3">
                    <XCircle className="w-4 h-4 text-[#ef4444] flex-shrink-0 mt-0.5" />
                    <p className="text-sm text-[#dc2626] font-medium">{error}</p>
                  </div>
                )}
              </div>

              {/* Feature Highlights */}
              <div className="grid md:grid-cols-3 gap-4 mt-8">
                <div className="card p-5 transition-all duration-200">
                  <div className="w-10 h-10 bg-gradient-to-br from-[#0575E1] to-[#0560b8] rounded-lg flex items-center justify-center mb-3">
                    <Shield className="w-5 h-5 text-white" />
                  </div>
                  <h3 className="font-semibold text-[#08121E] text-[15px] mb-1">Multi-Engine Scanning</h3>
                  <p className="text-[13px] text-[#64748b]">70+ security engines via VirusTotal & Google Safe Browsing</p>
                </div>

                <div className="card p-5 transition-all duration-200">
                  <div className="w-10 h-10 bg-gradient-to-br from-[#10b981] to-[#059669] rounded-lg flex items-center justify-center mb-3">
                    <Lock className="w-5 h-5 text-white" />
                  </div>
                  <h3 className="font-semibold text-[#08121E] text-[15px] mb-1">SSL Analysis</h3>
                  <p className="text-[13px] text-[#64748b]">Verify HTTPS encryption and certificate validity</p>
                </div>

                <div className="card p-5 transition-all duration-200">
                  <div className="w-10 h-10 bg-gradient-to-br from-[#8b5cf6] to-[#7c3aed] rounded-lg flex items-center justify-center mb-3">
                    <Globe className="w-5 h-5 text-white" />
                  </div>
                  <h3 className="font-semibold text-[#08121E] text-[15px] mb-1">Domain Intelligence</h3>
                  <p className="text-[13px] text-[#64748b]">Detect newly registered domains used in phishing</p>
                </div>
              </div>
            </div>
          )}

          {/* Single URL Result */}
          {result && !loading && (
            <div className="space-y-4 fade-in">
              {/* Verdict Header */}
              <div className={`card overflow-hidden ${
                result.verdict === 'SUSPICIOUS' ? 'border-[#ef4444]' : 'border-[#10b981]'
              }`}>
                <div className={`px-5 py-3 flex items-center gap-3 ${
                  result.verdict === 'SUSPICIOUS' ? 'bg-[#fef2f2]' : 'bg-[#ecfdf5]'
                }`}>
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                    result.verdict === 'SUSPICIOUS' ? 'bg-[#ef4444]' : 'bg-[#10b981]'
                  }`}>
                    {result.verdict === 'SUSPICIOUS' ? (
                      <AlertTriangle className="w-4 h-4 text-white" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 text-white" />
                    )}
                  </div>
                  <div>
                    <h3 className={`text-lg font-bold ${
                      result.verdict === 'SUSPICIOUS' ? 'text-[#dc2626]' : 'text-[#059669]'
                    }`}>
                      {result.verdict === 'SUSPICIOUS' ? 'Threat Detected' : 'No Threats Found'}
                    </h3>
                    <p className="text-[13px] text-[#64748b]">
                      {result.verdict === 'SUSPICIOUS'
                        ? 'This URL has been flagged as potentially dangerous'
                        : 'This URL appears to be safe'}
                    </p>
                  </div>
                </div>

                {/* URL Display */}
                <div className="px-5 py-3 border-t border-[#f1f5f9] bg-[#f8fafc]">
                  <p className="text-[13px] text-[#64748b] font-mono break-all">{result.url}</p>
                </div>

                {/* Suspicion Reasons */}
                {result.suspicionReasons && result.suspicionReasons.length > 0 && (
                  <div className="px-5 py-3 border-t border-[#f1f5f9]">
                    {result.suspicionReasons.map((reason, idx) => (
                      <div key={idx} className="flex items-center gap-2 py-1.5 text-[13px] text-[#dc2626]">
                        <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                        <span>{reason}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Analysis Details Card */}
              <div className="card">
                <div className="px-5 py-3 border-b border-[#f1f5f9]">
                  <h4 className="font-semibold text-[#08121E] text-[15px]">Security Analysis</h4>
                </div>

                {/* VirusTotal Row */}
                {result.checks.virustotal && !result.checks.virustotal.error && !result.checks.virustotal.status && (
                  <div className="status-row">
                    <div className={`status-icon ${
                      result.checks.virustotal.malicious > 0 ? 'status-icon-error' : 'status-icon-success'
                    }`}>
                      <Shield className="w-4 h-4" />
                    </div>
                    <div className="flex-1 ml-3">
                      <div className="text-[14px] font-medium text-[#08121E]">VirusTotal</div>
                      <div className="text-[12px] text-[#64748b]">
                        {result.checks.virustotal.malicious} malicious · {result.checks.virustotal.suspicious} suspicious · {result.checks.virustotal.harmless} clean
                      </div>
                    </div>
                    <span className={`badge ${
                      result.checks.virustotal.malicious > 0 ? 'badge-error' : 'badge-success'
                    }`}>
                      {result.checks.virustotal.malicious > 0 ? 'Threats Found' : 'Clean'}
                    </span>
                  </div>
                )}

                {/* Detections Expandable */}
                {result.checks.virustotal?.detections && result.checks.virustotal.detections.length > 0 && (
                  <div className="px-5 py-2 border-b border-[#f1f5f9] bg-[#fef2f2]">
                    <button
                      onClick={() => setShowDetections(!showDetections)}
                      className="text-[13px] text-[#dc2626] font-medium flex items-center gap-1.5"
                    >
                      {showDetections ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      {result.checks.virustotal.detections.length} engines flagged this URL
                    </button>
                    {showDetections && (
                      <div className="mt-2 max-h-40 overflow-y-auto">
                        {result.checks.virustotal.detections.map((detection: any, idx: number) => (
                          <div key={idx} className="flex justify-between items-center py-1.5 text-[12px]">
                            <span className="text-[#475569]">{detection.engine}</span>
                            <span className="text-[#dc2626] font-medium">{detection.result}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Google Safe Browsing Row */}
                {result.checks.safeBrowsing && !result.checks.safeBrowsing.error && (
                  <div className="status-row">
                    <div className={`status-icon ${
                      result.checks.safeBrowsing.safe ? 'status-icon-success' : 'status-icon-error'
                    }`}>
                      <Globe className="w-4 h-4" />
                    </div>
                    <div className="flex-1 ml-3">
                      <div className="text-[14px] font-medium text-[#08121E]">Google Safe Browsing</div>
                      <div className="text-[12px] text-[#64748b]">Real-time threat database</div>
                    </div>
                    <span className={`badge ${
                      result.checks.safeBrowsing.safe ? 'badge-success' : 'badge-error'
                    }`}>
                      {result.checks.safeBrowsing.safe ? 'Safe' : 'Unsafe'}
                    </span>
                  </div>
                )}

                {/* SSL Row */}
                {result.checks.ssl && (
                  <div className="status-row">
                    <div className={`status-icon ${
                      result.checks.ssl.secure ? 'status-icon-success' : 'status-icon-warning'
                    }`}>
                      <Lock className="w-4 h-4" />
                    </div>
                    <div className="flex-1 ml-3">
                      <div className="text-[14px] font-medium text-[#08121E]">SSL Certificate</div>
                      <div className="text-[12px] text-[#64748b]">
                        {result.checks.ssl.certificate && !result.checks.ssl.certificate.error
                          ? `${result.checks.ssl.certificate.issuer} · ${result.checks.ssl.certificate.daysUntilExpiry} days until expiry`
                          : result.checks.ssl.secure ? 'HTTPS enabled' : 'No HTTPS'}
                      </div>
                    </div>
                    <span className={`badge ${
                      result.checks.ssl.secure ? 'badge-success' : 'badge-warning'
                    }`}>
                      {result.checks.ssl.secure ? 'Secure' : 'Insecure'}
                    </span>
                  </div>
                )}

                {/* Domain Info Row */}
                {result.checks.whois && !result.checks.whois.error && (
                  <div className="status-row">
                    <div className={`status-icon ${
                      result.checks.whois.isNew ? 'status-icon-warning' : 'status-icon-neutral'
                    }`}>
                      <Info className="w-4 h-4" />
                    </div>
                    <div className="flex-1 ml-3">
                      <div className="text-[14px] font-medium text-[#08121E]">Domain Age</div>
                      <div className="text-[12px] text-[#64748b]">
                        {result.checks.whois.domainAge !== null ? `${result.checks.whois.domainAge} days old` : 'Unknown'}
                        {result.checks.whois.registrar && ` · ${result.checks.whois.registrar}`}
                      </div>
                    </div>
                    <span className={`badge ${
                      result.checks.whois.isNew ? 'badge-warning' : 'badge-neutral'
                    }`}>
                      {result.checks.whois.isNew ? 'New Domain' : 'Established'}
                    </span>
                  </div>
                )}
              </div>

              {/* Back Button */}
              <div className="text-center pt-2">
                <button
                  onClick={() => {
                    setResult(null);
                    setInput('');
                  }}
                  className="inline-flex items-center gap-2 px-5 py-2.5 bg-white hover:bg-[#f8fafc] text-[#475569] font-medium rounded-md transition-all duration-200 border border-[#e2e8f0] text-[14px]"
                >
                  <ChevronRight className="w-4 h-4 rotate-180" />
                  Check Another URL
                </button>
              </div>
            </div>
          )}

          {/* Multi URL Results */}
          {multiResult && !loading && (
            <div className="space-y-4 fade-in">
              {/* Summary Card */}
              <div className="card">
                <div className="px-5 py-4 border-b border-[#f1f5f9]">
                  <h3 className="text-lg font-bold text-[#08121E]">Scan Results</h3>
                </div>
                <div className="p-5">
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div className="text-center p-4 bg-[#f8fafc] rounded-lg">
                      <div className="text-3xl font-bold text-[#08121E]">{multiResult.totalUrls}</div>
                      <div className="text-[12px] text-[#64748b] mt-1">Total URLs</div>
                    </div>
                    <div className="text-center p-4 bg-[#fef2f2] rounded-lg">
                      <div className="text-3xl font-bold text-[#ef4444]">{multiResult.suspiciousCount}</div>
                      <div className="text-[12px] text-[#64748b] mt-1">Suspicious</div>
                    </div>
                    <div className="text-center p-4 bg-[#ecfdf5] rounded-lg">
                      <div className="text-3xl font-bold text-[#10b981]">{multiResult.cleanCount}</div>
                      <div className="text-[12px] text-[#64748b] mt-1">Clean</div>
                    </div>
                  </div>
                  {multiResult.suspiciousCount > 0 && (
                    <div className="bg-[#fef2f2] border border-[#fecaca] rounded-lg p-3 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-[#ef4444] flex-shrink-0" />
                      <p className="text-[13px] text-[#dc2626] font-medium">Warning: Suspicious URLs detected. Do not click these links.</p>
                    </div>
                  )}
                </div>
              </div>

              {/* URL List */}
              <div className="card overflow-hidden">
                {multiResult.results.map((res, idx) => (
                  <div key={idx} className={`border-b border-[#f1f5f9] last:border-0 ${
                    res.verdict === 'SUSPICIOUS' ? 'bg-[#fffbfb]' : ''
                  }`}>
                    <div className="p-4 flex items-start gap-3">
                      <div className={`status-icon flex-shrink-0 ${
                        res.verdict === 'SUSPICIOUS' ? 'status-icon-error' : 'status-icon-success'
                      }`}>
                        {res.verdict === 'SUSPICIOUS' ? (
                          <AlertTriangle className="w-4 h-4" />
                        ) : (
                          <CheckCircle2 className="w-4 h-4" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-3 mb-1">
                          <p className="text-[13px] font-mono break-all text-[#08121E]">{res.url}</p>
                          <span className={`badge flex-shrink-0 ${
                            res.verdict === 'SUSPICIOUS' ? 'badge-error' : 'badge-success'
                          }`}>
                            {res.verdict}
                          </span>
                        </div>

                        {res.suspicionReasons && res.suspicionReasons.length > 0 && (
                          <div className="mt-2">
                            {res.suspicionReasons.map((reason, reasonIdx) => (
                              <div key={reasonIdx} className="flex items-center gap-1.5 text-[12px] text-[#dc2626] py-0.5">
                                <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                                <span>{reason}</span>
                              </div>
                            ))}
                          </div>
                        )}

                        {res.checks.virustotal?.detections && res.checks.virustotal.detections.length > 0 && (
                          <div className="mt-2">
                            <button
                              onClick={() => setExpandedUrlIndex(expandedUrlIndex === idx ? null : idx)}
                              className="text-[12px] text-[#0575E1] font-medium flex items-center gap-1"
                            >
                              {expandedUrlIndex === idx ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                              {res.checks.virustotal.detections.length} engines flagged
                            </button>

                            {expandedUrlIndex === idx && (
                              <div className="mt-2 pl-4 border-l-2 border-[#fecaca]">
                                {res.checks.virustotal.detections.map((detection: any, detIdx: number) => (
                                  <div key={detIdx} className="flex justify-between items-center py-1 text-[12px]">
                                    <span className="text-[#475569]">{detection.engine}</span>
                                    <span className="text-[#dc2626]">{detection.result}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Back Button */}
              <div className="text-center pt-2">
                <button
                  onClick={() => {
                    setMultiResult(null);
                    setInput('');
                  }}
                  className="inline-flex items-center gap-2 px-5 py-2.5 bg-white hover:bg-[#f8fafc] text-[#475569] font-medium rounded-md transition-all duration-200 border border-[#e2e8f0] text-[14px]"
                >
                  <ChevronRight className="w-4 h-4 rotate-180" />
                  Check More URLs
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* FAQ Section with Dropdowns */}
      <section className="bg-[#F9FAFB] py-16 md:py-24 px-4">
        <div className="max-w-[800px] mx-auto">
          <div className="text-center mb-10">
            <h2 className="text-2xl md:text-4xl font-bold text-[#111827] mb-2.5 tracking-tight">
              Frequently Asked Questions
            </h2>
            <p className="text-[15px] md:text-[17px] text-[#6B7280]">
              Have more questions? <a href="https://www.sendmarc.com/contact" className="text-blue-600 hover:text-blue-700 font-medium">Contact Us</a>
            </p>
          </div>

          <div className="space-y-3">
            {faqs.map((faq, index) => (
              <div
                key={index}
                className={`faq-item ${openFaqIndex === index ? 'faq-item-open' : ''}`}
              >
                <button
                  onClick={() => setOpenFaqIndex(openFaqIndex === index ? null : index)}
                  className="w-full flex items-center justify-between p-5 md:px-6 md:py-5 text-left transition-all duration-200"
                >
                  <span
                    className={`font-medium text-[15px] md:text-[17px] pr-4 transition-colors duration-200 ${
                      openFaqIndex === index ? 'text-[#1D4ED8]' : 'text-[#1F2937]'
                    }`}
                  >
                    {faq.question}
                  </span>
                  <div
                    className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center transition-all duration-300 ${
                      openFaqIndex === index
                        ? 'bg-[#EEF2FF] border border-[#C7D2FE]'
                        : 'bg-[#F3F4F6] border border-transparent'
                    }`}
                  >
                    <ChevronDown
                      className={`w-4 h-4 faq-chevron ${openFaqIndex === index ? 'faq-chevron-open' : ''}`}
                      style={{ color: openFaqIndex === index ? '#2563EB' : '#6B7280' }}
                    />
                  </div>
                </button>
                <div
                  className={`transition-all duration-[350ms] ease-[cubic-bezier(0.4,0,0.2,1)] overflow-hidden ${
                    openFaqIndex === index ? 'max-h-[350px] opacity-100' : 'max-h-0 opacity-0'
                  }`}
                >
                  <div className="px-5 md:px-6 pb-5 md:pb-6 text-[#4B5563] text-[14px] md:text-[15px] leading-relaxed">
                    {faq.answer}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Professional Footer */}
      <footer className="bg-[#111827] text-[#9CA3AF] pt-16 pb-8 px-6">
        <div className="max-w-[1100px] mx-auto">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-12 lg:gap-8 mb-12">
            {/* Company Info */}
            <div className="max-w-[280px]">
              <div className="mb-5">
                <a href="https://www.sendmarc.com" target="_blank" rel="noopener noreferrer" className="inline-block hover:opacity-80 transition-opacity duration-200">
                  <img
                    src="https://i0.wp.com/ekoparty.org/wp-content/uploads/2024/10/Sendmarc-Logo-RGB-Main-Inverted-1.png?fit=1635%2C567&ssl=1"
                    alt="Sendmarc"
                    className="h-8 w-auto"
                  />
                </a>
              </div>
              <p className="text-[13px] leading-relaxed text-[#6B7280] mb-4">
                Protect your domain and email infrastructure with DMARC, SPF, and DKIM authentication.
              </p>
              <div className="space-y-2.5">
                <a href="mailto:info@sendmarc.com" className="flex items-center gap-2 text-[13px] text-[#9CA3AF] hover:text-white transition-colors duration-200">
                  <Mail className="w-3.5 h-3.5" />
                  info@sendmarc.com
                </a>
                <a href="tel:+27109000972" className="flex items-center gap-2 text-[13px] text-[#9CA3AF] hover:text-white transition-colors duration-200">
                  <Phone className="w-3.5 h-3.5" />
                  +27 10 900 0972
                </a>
              </div>
            </div>

            {/* Security Tools */}
            <div>
              <h4 className="text-[13px] font-semibold text-white mb-4 uppercase tracking-wider">Security Tools</h4>
              <ul className="space-y-2.5">
                <li>
                  <a href="https://sendmarc.com/dmarc/dmarc-analyzer/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    DMARC Analyzer <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/dmarc/record-generator/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    DMARC Generator <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/spf/policy-tester/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    SPF Policy Tester <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/dmarc/email-header-analyzer/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    Email Header Analyzer <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/tls-rpt/record-checker/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    TLS-RPT Checker <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
              </ul>
            </div>

            {/* Learn */}
            <div>
              <h4 className="text-[13px] font-semibold text-white mb-4 uppercase tracking-wider">Learn</h4>
              <ul className="space-y-2.5">
                <li>
                  <a href="https://sendmarc.com/dmarc/what-is-dmarc/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    What is DMARC? <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/spf/what-is-spf/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    What is SPF? <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/dkim/what-is-dkim/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    What is DKIM? <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/bimi/what-is-bimi/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    What is BIMI? <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://sendmarc.com/blog/" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    Blog <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
              </ul>
            </div>

            {/* Company */}
            <div>
              <h4 className="text-[13px] font-semibold text-white mb-4 uppercase tracking-wider">Company</h4>
              <ul className="space-y-2.5">
                <li>
                  <a href="https://www.sendmarc.com" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    About Sendmarc <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://www.sendmarc.com/contact" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    Contact Us <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://www.sendmarc.com/privacy" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    Privacy Policy <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
                <li>
                  <a href="https://trust.sendmarc.com" className="footer-link inline-flex items-center gap-1 text-[13px] text-[#9CA3AF]">
                    Trust Center <ExternalLink className="w-[11px] h-[11px] opacity-70" />
                  </a>
                </li>
              </ul>
            </div>
          </div>

          {/* Bottom Bar */}
          <div className="border-t border-[#1F2937] pt-6 flex flex-wrap justify-between items-center gap-3">
            <p className="text-[12px] text-[#6B7280]">
              © {new Date().getFullYear()} Sendmarc. All rights reserved.
            </p>
            <p className="text-[12px] text-[#6B7280]">
              Powered by <a href="https://www.sendmarc.com" className="text-white hover:text-[#60A5FA] transition-colors duration-200">Sendmarc</a>
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
