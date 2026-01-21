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
  Search,
  Loader2,
  XCircle,
  Info
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
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-gray-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-md border-b border-gray-200/50 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center gap-3">
            <Image
              src="https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg"
              alt="Sendmarc"
              width={140}
              height={36}
              className="h-8 w-auto"
            />
            <div className="h-6 w-px bg-gradient-to-b from-gray-300 to-transparent"></div>
            <h1 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-600" />
              Phishing URL Checker
            </h1>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-12">
        <div className="w-full max-w-5xl mx-auto">
          {/* Input Section - Only show when no results */}
          {!result && !multiResult && (
            <div className="space-y-8 fade-in">
              <div className="text-center max-w-3xl mx-auto">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-2xl mb-6">
                  <Search className="w-8 h-8 text-blue-600" />
                </div>
                <h2 className="text-4xl font-bold text-gray-900 mb-4">
                  Analyze URLs for Security Threats
                </h2>
                <p className="text-lg text-gray-600">
                  Paste any URL or entire email content to instantly check for phishing, malware, and security risks
                </p>
              </div>

              <div className="bg-white rounded-2xl border border-gray-200/60 shadow-xl shadow-gray-200/50 p-8 hover:shadow-2xl hover:shadow-gray-300/50 transition-all duration-300">
                <form onSubmit={handleSubmit} className="space-y-5">
                  <div className="relative">
                    <textarea
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      placeholder="https://example.com or paste email content here..."
                      className="w-full px-5 py-4 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none text-base bg-gray-50/50 hover:bg-gray-50 transition-colors duration-200"
                      rows={6}
                      required
                      disabled={loading}
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed text-base shadow-lg shadow-blue-600/30 hover:shadow-xl hover:shadow-blue-600/40 flex items-center justify-center gap-2 group"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5 group-hover:scale-110 transition-transform" />
                        Analyze URLs
                      </>
                    )}
                  </button>
                </form>

                {error && (
                  <div className="mt-5 p-4 bg-red-50 border border-red-200 rounded-xl flex items-start gap-3 animate-in fade-in slide-in-from-top-2 duration-300">
                    <XCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                    <p className="text-sm text-red-800 font-medium">{error}</p>
                  </div>
                )}
              </div>

              {/* Feature Highlights */}
              <div className="grid md:grid-cols-3 gap-6 mt-12">
                <div className="bg-white/60 backdrop-blur-sm rounded-xl p-6 border border-gray-200/50 hover:bg-white hover:shadow-lg hover:border-blue-200 transition-all duration-300 group">
                  <div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-blue-600 transition-colors duration-300">
                    <Shield className="w-6 h-6 text-blue-600 group-hover:text-white transition-colors duration-300" />
                  </div>
                  <h3 className="font-semibold text-gray-900 mb-2">Multi-Engine Scanning</h3>
                  <p className="text-sm text-gray-600">Powered by VirusTotal's 70+ security engines and Google Safe Browsing</p>
                </div>

                <div className="bg-white/60 backdrop-blur-sm rounded-xl p-6 border border-gray-200/50 hover:bg-white hover:shadow-lg hover:border-green-200 transition-all duration-300 group">
                  <div className="w-12 h-12 bg-green-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-green-600 transition-colors duration-300">
                    <Lock className="w-6 h-6 text-green-600 group-hover:text-white transition-colors duration-300" />
                  </div>
                  <h3 className="font-semibold text-gray-900 mb-2">SSL & Certificate Analysis</h3>
                  <p className="text-sm text-gray-600">Verify HTTPS encryption and examine certificate validity</p>
                </div>

                <div className="bg-white/60 backdrop-blur-sm rounded-xl p-6 border border-gray-200/50 hover:bg-white hover:shadow-lg hover:border-purple-200 transition-all duration-300 group">
                  <div className="w-12 h-12 bg-purple-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-purple-600 transition-colors duration-300">
                    <Globe className="w-6 h-6 text-purple-600 group-hover:text-white transition-colors duration-300" />
                  </div>
                  <h3 className="font-semibold text-gray-900 mb-2">Domain Intelligence</h3>
                  <p className="text-sm text-gray-600">Identify newly registered domains often used in phishing</p>
                </div>
              </div>
            </div>
          )}

          {/* Single URL Result */}
          {result && !loading && (
            <div className="space-y-6 fade-in">
              {/* Verdict Card */}
              <div className={`rounded-2xl border-2 shadow-xl p-8 ${
                result.verdict === 'SUSPICIOUS'
                  ? 'bg-gradient-to-br from-red-50 to-red-100/50 border-red-200'
                  : 'bg-gradient-to-br from-green-50 to-green-100/50 border-green-200'
              }`}>
                <div className="flex items-start gap-5">
                  <div className={`flex-shrink-0 w-20 h-20 rounded-2xl flex items-center justify-center shadow-lg ${
                    result.verdict === 'SUSPICIOUS' ? 'bg-red-500' : 'bg-green-500'
                  }`}>
                    {result.verdict === 'SUSPICIOUS' ? (
                      <AlertTriangle className="w-10 h-10 text-white" />
                    ) : (
                      <CheckCircle2 className="w-10 h-10 text-white" />
                    )}
                  </div>
                  <div className="flex-1">
                    <h3 className={`text-3xl font-bold mb-2 ${
                      result.verdict === 'SUSPICIOUS' ? 'text-red-900' : 'text-green-900'
                    }`}>
                      {result.verdict === 'SUSPICIOUS' ? 'Threat Detected' : 'No Threats Found'}
                    </h3>
                    <p className={`text-lg mb-4 ${
                      result.verdict === 'SUSPICIOUS' ? 'text-red-700' : 'text-green-700'
                    }`}>
                      {result.verdict === 'SUSPICIOUS'
                        ? 'This URL has been flagged as potentially dangerous'
                        : 'This URL appears to be safe'}
                    </p>
                    {result.suspicionReasons && result.suspicionReasons.length > 0 && (
                      <ul className="space-y-2">
                        {result.suspicionReasons.map((reason, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-sm text-red-800 bg-white/50 rounded-lg p-3">
                            <AlertTriangle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
                            <span className="font-medium">{reason}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>

              {/* Analysis Details */}
              <div className="grid md:grid-cols-2 gap-6">
                {/* VirusTotal */}
                {result.checks.virustotal && !result.checks.virustotal.error && !result.checks.virustotal.status && (
                  <div className="bg-white rounded-2xl border border-gray-200/60 shadow-lg p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center gap-3 mb-5">
                      <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center">
                        <Shield className="w-5 h-5 text-blue-600" />
                      </div>
                      <h4 className="font-semibold text-gray-900 text-lg">VirusTotal</h4>
                    </div>
                    <div className="grid grid-cols-4 gap-3">
                      <div className="text-center p-4 bg-gradient-to-br from-red-50 to-red-100 rounded-xl hover:scale-105 transition-transform duration-200">
                        <div className="text-2xl font-bold text-red-600">{result.checks.virustotal.malicious}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Malicious</div>
                      </div>
                      <div className="text-center p-4 bg-gradient-to-br from-orange-50 to-orange-100 rounded-xl hover:scale-105 transition-transform duration-200">
                        <div className="text-2xl font-bold text-orange-600">{result.checks.virustotal.suspicious}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Suspicious</div>
                      </div>
                      <div className="text-center p-4 bg-gradient-to-br from-green-50 to-green-100 rounded-xl hover:scale-105 transition-transform duration-200">
                        <div className="text-2xl font-bold text-green-600">{result.checks.virustotal.harmless}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Clean</div>
                      </div>
                      <div className="text-center p-4 bg-gradient-to-br from-gray-50 to-gray-100 rounded-xl hover:scale-105 transition-transform duration-200">
                        <div className="text-2xl font-bold text-gray-600">{result.checks.virustotal.undetected}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Undetected</div>
                      </div>
                    </div>

                    {result.checks.virustotal.detections && result.checks.virustotal.detections.length > 0 && (
                      <div className="mt-5">
                        <button
                          onClick={() => setShowDetections(!showDetections)}
                          className="text-sm text-blue-600 hover:text-blue-700 font-semibold flex items-center gap-2 hover:gap-3 transition-all duration-200"
                        >
                          {showDetections ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                          {showDetections ? 'Hide' : 'Show'} {result.checks.virustotal.detections.length} engine detections
                        </button>

                        {showDetections && (
                          <div className="mt-3 max-h-64 overflow-y-auto border border-gray-200 rounded-xl bg-gray-50">
                            {result.checks.virustotal.detections.map((detection: any, idx: number) => (
                              <div key={idx} className="flex justify-between items-center px-4 py-3 border-b border-gray-200 last:border-0 text-sm hover:bg-white transition-colors">
                                <span className="font-semibold text-gray-800">{detection.engine}</span>
                                <span className={`px-3 py-1 rounded-lg text-xs font-semibold ${
                                  detection.category === 'malicious' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
                                }`}>
                                  {detection.result}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Google Safe Browsing */}
                {result.checks.safeBrowsing && !result.checks.safeBrowsing.error && (
                  <div className="bg-white rounded-2xl border border-gray-200/60 shadow-lg p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center gap-3 mb-5">
                      <div className="w-10 h-10 bg-green-100 rounded-xl flex items-center justify-center">
                        <Globe className="w-5 h-5 text-green-600" />
                      </div>
                      <h4 className="font-semibold text-gray-900 text-lg">Google Safe Browsing</h4>
                    </div>
                    <div className={`flex items-center gap-3 p-4 rounded-xl ${result.checks.safeBrowsing.safe ? 'bg-green-50' : 'bg-red-50'}`}>
                      {result.checks.safeBrowsing.safe ? (
                        <CheckCircle2 className="w-6 h-6 text-green-600" />
                      ) : (
                        <AlertTriangle className="w-6 h-6 text-red-600" />
                      )}
                      <span className={`text-base font-semibold ${result.checks.safeBrowsing.safe ? 'text-green-700' : 'text-red-700'}`}>
                        {result.checks.safeBrowsing.safe ? 'No threats detected' : 'Threats detected'}
                      </span>
                    </div>
                  </div>
                )}

                {/* SSL Certificate */}
                {result.checks.ssl && (
                  <div className="bg-white rounded-2xl border border-gray-200/60 shadow-lg p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center gap-3 mb-5">
                      <div className="w-10 h-10 bg-purple-100 rounded-xl flex items-center justify-center">
                        <Lock className="w-5 h-5 text-purple-600" />
                      </div>
                      <h4 className="font-semibold text-gray-900 text-lg">SSL Certificate</h4>
                    </div>
                    <div className="space-y-3">
                      <div className={`flex items-center gap-3 p-3 rounded-xl ${result.checks.ssl.secure ? 'bg-green-50' : 'bg-orange-50'}`}>
                        <Lock className={`w-5 h-5 ${result.checks.ssl.secure ? 'text-green-600' : 'text-orange-600'}`} />
                        <span className={`text-sm font-semibold ${result.checks.ssl.secure ? 'text-green-700' : 'text-orange-700'}`}>
                          {result.checks.ssl.secure ? 'Secure HTTPS' : 'Insecure HTTP'}
                        </span>
                      </div>
                      {result.checks.ssl.certificate && !result.checks.ssl.certificate.error && (
                        <div className="space-y-2 text-sm bg-gray-50 rounded-xl p-4">
                          <div className="flex justify-between">
                            <span className="text-gray-600">Issuer:</span>
                            <span className="font-medium text-gray-900">{result.checks.ssl.certificate.issuer}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-600">Age:</span>
                            <span className="font-medium text-gray-900">{result.checks.ssl.certificate.certAge} days</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-600">Expires:</span>
                            <span className="font-medium text-gray-900">{result.checks.ssl.certificate.daysUntilExpiry} days</span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Domain Info */}
                {result.checks.whois && !result.checks.whois.error && (
                  <div className="bg-white rounded-2xl border border-gray-200/60 shadow-lg p-6 hover:shadow-xl transition-all duration-300">
                    <div className="flex items-center gap-3 mb-5">
                      <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center">
                        <Info className="w-5 h-5 text-indigo-600" />
                      </div>
                      <h4 className="font-semibold text-gray-900 text-lg">Domain Information</h4>
                    </div>
                    <div className="space-y-2 text-sm bg-gray-50 rounded-xl p-4">
                      {result.checks.whois.domainAge !== null && result.checks.whois.domainAge !== undefined && (
                        <div className={`flex justify-between ${result.checks.whois.isNew ? 'text-red-700 font-semibold' : ''}`}>
                          <span className="text-gray-600">Age:</span>
                          <span className="font-medium text-gray-900">
                            {result.checks.whois.domainAge} days
                            {result.checks.whois.isNew && ' (NEW)'}
                          </span>
                        </div>
                      )}
                      {result.checks.whois.registrar && (
                        <div className="flex justify-between">
                          <span className="text-gray-600">Registrar:</span>
                          <span className="font-medium text-gray-900">{result.checks.whois.registrar}</span>
                        </div>
                      )}
                      {result.checks.whois.createdDate && (
                        <div className="flex justify-between">
                          <span className="text-gray-600">Created:</span>
                          <span className="font-medium text-gray-900">{new Date(result.checks.whois.createdDate).toLocaleDateString()}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* URL Display */}
              <div className="bg-gradient-to-r from-gray-50 to-gray-100 rounded-2xl border border-gray-200 p-5">
                <p className="text-sm text-gray-600 font-mono break-all">{result.url}</p>
              </div>

              {/* Back Button */}
              <div className="text-center">
                <button
                  onClick={() => {
                    setResult(null);
                    setInput('');
                  }}
                  className="inline-flex items-center gap-2 px-8 py-3 bg-white hover:bg-gray-50 text-gray-700 font-semibold rounded-xl transition-all duration-200 border border-gray-200 shadow-lg hover:shadow-xl group"
                >
                  <ChevronRight className="w-4 h-4 rotate-180 group-hover:-translate-x-1 transition-transform" />
                  Check Another URL
                </button>
              </div>
            </div>
          )}

          {/* Multi URL Results */}
          {multiResult && !loading && (
            <div className="space-y-6 fade-in">
              {/* Summary */}
              <div className="bg-white rounded-2xl border border-gray-200/60 shadow-xl p-8">
                <h3 className="text-2xl font-bold text-gray-900 mb-6">Scan Results</h3>
                <div className="grid grid-cols-3 gap-6 mb-6">
                  <div className="text-center p-6 bg-gradient-to-br from-gray-50 to-gray-100 rounded-2xl hover:scale-105 transition-transform duration-200">
                    <div className="text-5xl font-bold text-gray-900">{multiResult.totalUrls}</div>
                    <div className="text-sm text-gray-600 mt-2 font-medium">Total URLs</div>
                  </div>
                  <div className="text-center p-6 bg-gradient-to-br from-red-50 to-red-100 rounded-2xl hover:scale-105 transition-transform duration-200">
                    <div className="text-5xl font-bold text-red-600">{multiResult.suspiciousCount}</div>
                    <div className="text-sm text-gray-600 mt-2 font-medium">Suspicious</div>
                  </div>
                  <div className="text-center p-6 bg-gradient-to-br from-green-50 to-green-100 rounded-2xl hover:scale-105 transition-transform duration-200">
                    <div className="text-5xl font-bold text-green-600">{multiResult.cleanCount}</div>
                    <div className="text-sm text-gray-600 mt-2 font-medium">Clean</div>
                  </div>
                </div>
                {multiResult.suspiciousCount > 0 && (
                  <div className="bg-gradient-to-r from-red-50 to-red-100 border border-red-200 rounded-2xl p-4 flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                    <p className="text-sm text-red-800 font-semibold">Warning: Suspicious URLs detected. Do not click these links.</p>
                  </div>
                )}
              </div>

              {/* URL List */}
              <div className="space-y-4">
                {multiResult.results.map((res, idx) => (
                  <div key={idx} className={`bg-white rounded-2xl border-2 shadow-lg p-6 hover:shadow-xl transition-all duration-300 ${
                    res.verdict === 'SUSPICIOUS' ? 'border-red-200' : 'border-green-200'
                  }`}>
                    <div className="flex items-start gap-4">
                      <div className={`flex-shrink-0 w-12 h-12 rounded-xl flex items-center justify-center shadow-md ${
                        res.verdict === 'SUSPICIOUS' ? 'bg-red-500' : 'bg-green-500'
                      }`}>
                        {res.verdict === 'SUSPICIOUS' ? (
                          <AlertTriangle className="w-6 h-6 text-white" />
                        ) : (
                          <CheckCircle2 className="w-6 h-6 text-white" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-mono break-all text-gray-900 mb-3 bg-gray-50 rounded-lg p-3">{res.url}</p>
                        <div className="flex items-center gap-2 mb-3">
                          <span className={`px-4 py-2 rounded-lg text-xs font-bold shadow-sm ${
                            res.verdict === 'SUSPICIOUS'
                              ? 'bg-red-100 text-red-700'
                              : 'bg-green-100 text-green-700'
                          }`}>
                            {res.verdict}
                          </span>
                        </div>
                        {res.suspicionReasons && res.suspicionReasons.length > 0 && (
                          <ul className="space-y-1.5 text-xs text-gray-600 mb-3">
                            {res.suspicionReasons.map((reason, reasonIdx) => (
                              <li key={reasonIdx} className="flex items-start gap-2 bg-red-50/50 rounded-lg p-2">
                                <AlertTriangle className="w-3 h-3 text-red-600 flex-shrink-0 mt-0.5" />
                                <span>{reason}</span>
                              </li>
                            ))}
                          </ul>
                        )}

                        {res.checks.virustotal?.detections && res.checks.virustotal.detections.length > 0 && (
                          <div className="mt-3">
                            <button
                              onClick={() => setExpandedUrlIndex(expandedUrlIndex === idx ? null : idx)}
                              className="text-sm text-blue-600 hover:text-blue-700 font-semibold flex items-center gap-2 hover:gap-3 transition-all duration-200"
                            >
                              {expandedUrlIndex === idx ? (
                                <ChevronDown className="w-4 h-4" />
                              ) : (
                                <ChevronRight className="w-4 h-4" />
                              )}
                              {expandedUrlIndex === idx ? 'Hide' : 'Show'} {res.checks.virustotal.detections.length} engine detections
                            </button>

                            {expandedUrlIndex === idx && (
                              <div className="mt-3 max-h-48 overflow-y-auto border border-gray-200 rounded-xl bg-gray-50">
                                {res.checks.virustotal.detections.map((detection: any, detIdx: number) => (
                                  <div key={detIdx} className="flex justify-between items-center px-4 py-3 border-b border-gray-200 last:border-0 text-sm hover:bg-white transition-colors">
                                    <span className="font-semibold text-gray-800">{detection.engine}</span>
                                    <span className="text-red-600 font-medium px-3 py-1 bg-red-50 rounded-lg">{detection.result}</span>
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
              <div className="text-center">
                <button
                  onClick={() => {
                    setMultiResult(null);
                    setInput('');
                  }}
                  className="inline-flex items-center gap-2 px-8 py-3 bg-white hover:bg-gray-50 text-gray-700 font-semibold rounded-xl transition-all duration-200 border border-gray-200 shadow-lg hover:shadow-xl group"
                >
                  <ChevronRight className="w-4 h-4 rotate-180 group-hover:-translate-x-1 transition-transform" />
                  Check More URLs
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Educational Content / FAQ Section */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="bg-white rounded-2xl border border-gray-200/60 shadow-xl p-8 md:p-12">
          <h2 className="text-3xl font-bold text-gray-900 mb-8 text-center">
            Frequently Asked Questions
          </h2>

          <div className="space-y-8">
            {/* FAQ 1 */}
            <div className="pb-8 border-b border-gray-100 last:border-0">
              <h3 className="text-xl font-semibold text-gray-900 mb-3 flex items-start gap-2">
                <div className="w-6 h-6 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-xs font-bold text-blue-600">1</span>
                </div>
                What is phishing and how does it work?
              </h3>
              <p className="text-gray-700 leading-relaxed mb-3 ml-8">
                Phishing is a cyberattack where criminals impersonate legitimate organizations to steal sensitive information like passwords, credit card numbers, or personal data. Attackers send fraudulent emails, text messages, or create fake websites that appear authentic, tricking users into clicking malicious links or providing confidential information.
              </p>
              <p className="text-gray-700 leading-relaxed ml-8">
                Modern phishing attacks have become increasingly sophisticated, with threats like{' '}
                <a href="https://sendmarc.com/blog/spear-phishing-vs-phishing/" className="text-blue-600 hover:text-blue-700 font-medium underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                  spear phishing
                </a>
                {' '}targeting specific individuals and{' '}
                <a href="https://sendmarc.com/blog/phishing-for-sale-the-telegram-threat-to-business-email-safety/" className="text-blue-600 hover:text-blue-700 font-medium underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                  phishing kits being sold on platforms like Telegram
                </a>
                , making these attacks more accessible to criminals.
              </p>
            </div>

            {/* FAQ 2 */}
            <div className="pb-8 border-b border-gray-100 last:border-0">
              <h3 className="text-xl font-semibold text-gray-900 mb-3 flex items-start gap-2">
                <div className="w-6 h-6 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-xs font-bold text-blue-600">2</span>
                </div>
                How does this phishing URL checker work?
              </h3>
              <p className="text-gray-700 leading-relaxed mb-3 ml-8">
                Our phishing checker analyzes URLs using multiple security layers to detect threats:
              </p>
              <ul className="space-y-2 text-gray-700 ml-14 mb-3">
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
              <p className="text-gray-700 leading-relaxed ml-8">
                You can paste individual URLs or entire email content, and our tool will automatically extract and analyze all links found.
              </p>
            </div>

            {/* FAQ 3 */}
            <div className="pb-8 border-b border-gray-100 last:border-0">
              <h3 className="text-xl font-semibold text-gray-900 mb-3 flex items-start gap-2">
                <div className="w-6 h-6 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-xs font-bold text-blue-600">3</span>
                </div>
                How do I interpret the scan results?
              </h3>
              <p className="text-gray-700 leading-relaxed mb-3 ml-8">
                The tool provides a clear verdict for each URL:
              </p>
              <ul className="space-y-3 text-gray-700 ml-14 mb-3">
                <li className="flex items-start gap-2">
                  <div className="w-5 h-5 bg-red-100 rounded flex items-center justify-center flex-shrink-0 mt-0.5">
                    <AlertTriangle className="w-3 h-3 text-red-600" />
                  </div>
                  <span><strong className="text-red-600">SUSPICIOUS:</strong> The URL has been flagged by one or more security engines, has concerning characteristics (like a very new domain or no HTTPS), or matches known phishing patterns. Do not click these links.</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="w-5 h-5 bg-green-100 rounded flex items-center justify-center flex-shrink-0 mt-0.5">
                    <CheckCircle2 className="w-3 h-3 text-green-600" />
                  </div>
                  <span><strong className="text-green-600">CLEAN:</strong> No security engines detected threats, the domain has proper SSL encryption, and no suspicious characteristics were found. The link appears safe.</span>
                </li>
              </ul>
              <p className="text-gray-700 leading-relaxed ml-8">
                The VirusTotal results show how many security engines flagged the URL as malicious, suspicious, harmless, or undetected. Even a few detections can indicate a threat.
              </p>
            </div>

            {/* FAQ 4 */}
            <div className="pb-8 border-b border-gray-100 last:border-0">
              <h3 className="text-xl font-semibold text-gray-900 mb-3 flex items-start gap-2">
                <div className="w-6 h-6 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-xs font-bold text-blue-600">4</span>
                </div>
                What are the warning signs of a phishing URL?
              </h3>
              <p className="text-gray-700 leading-relaxed mb-3 ml-8">
                Learn to identify suspicious links before clicking:
              </p>
              <ul className="space-y-2 text-gray-700 ml-14">
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
            </div>

            {/* FAQ 5 */}
            <div className="pb-8 border-b border-gray-100 last:border-0">
              <h3 className="text-xl font-semibold text-gray-900 mb-3 flex items-start gap-2">
                <div className="w-6 h-6 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-xs font-bold text-blue-600">5</span>
                </div>
                How can email authentication prevent phishing attacks?
              </h3>
              <p className="text-gray-700 leading-relaxed mb-3 ml-8">
                Email authentication protocols are critical defenses against phishing and email spoofing:
              </p>
              <ul className="space-y-2 text-gray-700 ml-14 mb-3">
                <li className="flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-1">•</span>
                  <span>
                    <strong>
                      <a href="https://sendmarc.com/dmarc/" className="text-blue-600 hover:text-blue-700 underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                        DMARC
                      </a>
                      :
                    </strong> Tells email servers how to handle emails that fail authentication, preventing spoofed emails from reaching inboxes
                  </span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-1">•</span>
                  <span>
                    <strong>
                      <a href="https://sendmarc.com/spf/" className="text-blue-600 hover:text-blue-700 underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                        SPF
                      </a>
                      :
                    </strong> Specifies which mail servers are authorized to send emails on behalf of your domain
                  </span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-1">•</span>
                  <span>
                    <strong>
                      <a href="https://sendmarc.com/dkim/" className="text-blue-600 hover:text-blue-700 underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                        DKIM
                      </a>
                      :
                    </strong> Adds a digital signature to emails, verifying they haven't been tampered with in transit
                  </span>
                </li>
              </ul>
              <p className="text-gray-700 leading-relaxed ml-8">
                Together, these protocols make it significantly harder for attackers to impersonate legitimate domains. Organizations using{' '}
                <a href="https://www.sendmarc.com" className="text-blue-600 hover:text-blue-700 font-medium underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                  DMARC enforcement
                </a>
                {' '}can block up to 99% of email-based phishing attacks.
              </p>
            </div>

            {/* FAQ 6 */}
            <div className="pb-8 border-b border-gray-100 last:border-0">
              <h3 className="text-xl font-semibold text-gray-900 mb-3 flex items-start gap-2">
                <div className="w-6 h-6 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-xs font-bold text-blue-600">6</span>
                </div>
                What should I do if I find a suspicious link?
              </h3>
              <p className="text-gray-700 leading-relaxed mb-3 ml-8">
                If our tool identifies a URL as suspicious, or if you have any doubts:
              </p>
              <ul className="space-y-2 text-gray-700 ml-14 mb-3">
                <li className="flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-1">•</span>
                  <span><strong>Do not click the link</strong> - Even visiting a malicious site can compromise your security</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-1">•</span>
                  <span><strong>Delete the email or message</strong> - Do not forward it to others</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-1">•</span>
                  <span><strong>Report it</strong> - Forward phishing emails to your IT security team or report it to the impersonated organization</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-1">•</span>
                  <span><strong>Verify directly</strong> - If the email claims to be from your bank or a service you use, contact them directly using official contact information (not from the suspicious email)</span>
                </li>
              </ul>
              <p className="text-gray-700 leading-relaxed ml-8">
                Learn more about{' '}
                <a href="https://sendmarc.com/blog/changing-user-behaviour-to-prevent-phishing-attacks/" className="text-blue-600 hover:text-blue-700 font-medium underline hover:no-underline transition-all" target="_blank" rel="noopener noreferrer">
                  behavioral changes that prevent phishing attacks
                </a>
                {' '}and protect your organization.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200/50 py-8 bg-white/50 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <p className="text-sm text-gray-600">
            Powered by{' '}
            <a
              href="https://www.sendmarc.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:text-blue-700 font-medium transition-colors"
            >
              Sendmarc
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}
