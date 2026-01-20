'use client';

import { useState, useEffect } from 'react';
import Image from 'next/image';

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
    // Match URLs with or without protocol
    const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+|(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[a-zA-Z]{2,}(?:\/[^\s<>"{}|\\^`\[\]]*)?)/gi;
    const matches = text.match(urlRegex);
    if (!matches) return [];

    // Normalize URLs and remove duplicates
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
      // Add protocol if missing
      const urlToValidate = urlString.startsWith('http') ? urlString : `https://${urlString}`;
      const url = new URL(urlToValidate);

      // Check if it has a proper domain (at least domain.tld format)
      const hostname = url.hostname;
      const parts = hostname.split('.');

      // Must have at least 2 parts (domain.tld) and the TLD should be at least 2 chars
      return parts.length >= 2 && parts[parts.length - 1].length >= 2 && hostname.length > 3;
    } catch {
      return false;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Rate limiting check
    const now = Date.now();
    const timeSinceLastSubmit = now - lastSubmitTime;
    const minDelay = 10000; // 10 seconds

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
          totalUrls: urls.length,
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
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center gap-3">
            <Image
              src="https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg"
              alt="Sendmarc"
              width={140}
              height={36}
              className="h-8 w-auto"
            />
            <div className="h-6 w-px bg-gray-300"></div>
            <h1 className="text-base font-semibold text-gray-900">Phishing URL Checker</h1>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12">
        <div className="w-full max-w-4xl">
          {/* Input Section - Only show when no results */}
          {!result && !multiResult && (
            <div className="fade-in">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-gray-900 mb-3">
                  Analyze URLs for Security Threats
                </h2>
                <p className="text-gray-600 text-lg">
                  Paste a URL or entire email content to check for phishing and malware
                </p>
              </div>

              <div className="bg-white rounded-xl border border-gray-200 shadow-lg p-8">
                <form onSubmit={handleSubmit} className="space-y-5">
                  <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="https://example.com or paste email content here..."
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none text-sm"
                    rows={6}
                    required
                    disabled={loading}
                  />

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3.5 px-6 rounded-lg transition-colors duration-200 disabled:opacity-50 disabled:cursor-not-allowed text-base"
                  >
                    {loading ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Analyzing...
                      </span>
                    ) : 'Analyze URLs'}
                  </button>
                </form>

                {error && (
                  <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
                    <svg className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                    </svg>
                    <p className="text-sm text-red-800">{error}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Single URL Result */}
          {result && !loading && (
            <div className="space-y-6 fade-in">
              {/* Verdict Card */}
              <div className={`rounded-xl border-2 shadow-lg p-8 ${
                result.verdict === 'SUSPICIOUS'
                  ? 'bg-red-50 border-red-200'
                  : 'bg-green-50 border-green-200'
              }`}>
                <div className="flex items-start gap-4">
                  <div className={`flex-shrink-0 w-16 h-16 rounded-full flex items-center justify-center ${
                    result.verdict === 'SUSPICIOUS' ? 'bg-red-100' : 'bg-green-100'
                  }`}>
                    {result.verdict === 'SUSPICIOUS' ? (
                      <svg className="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                    ) : (
                      <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    )}
                  </div>
                  <div className="flex-1">
                    <h3 className={`text-2xl font-bold mb-2 ${
                      result.verdict === 'SUSPICIOUS' ? 'text-red-900' : 'text-green-900'
                    }`}>
                      {result.verdict === 'SUSPICIOUS' ? 'Threat Detected' : 'No Threats Found'}
                    </h3>
                    <p className={`text-base mb-3 ${
                      result.verdict === 'SUSPICIOUS' ? 'text-red-700' : 'text-green-700'
                    }`}>
                      {result.verdict === 'SUSPICIOUS'
                        ? 'This URL has been flagged as potentially dangerous'
                        : 'This URL appears to be safe'}
                    </p>
                    {result.suspicionReasons && result.suspicionReasons.length > 0 && (
                      <ul className="space-y-2">
                        {result.suspicionReasons.map((reason, idx) => (
                          <li key={idx} className="flex items-start gap-2 text-sm text-red-800">
                            <svg className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                            </svg>
                            <span>{reason}</span>
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
                  <div className="bg-white rounded-xl border border-gray-200 shadow-md p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <svg className="w-5 h-5 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      <h4 className="font-semibold text-gray-900 text-base">VirusTotal</h4>
                    </div>
                    <div className="grid grid-cols-4 gap-3">
                      <div className="text-center p-4 bg-red-50 rounded-lg">
                        <div className="text-2xl font-bold text-red-600">{result.checks.virustotal.malicious}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Malicious</div>
                      </div>
                      <div className="text-center p-4 bg-orange-50 rounded-lg">
                        <div className="text-2xl font-bold text-orange-600">{result.checks.virustotal.suspicious}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Suspicious</div>
                      </div>
                      <div className="text-center p-4 bg-green-50 rounded-lg">
                        <div className="text-2xl font-bold text-green-600">{result.checks.virustotal.harmless}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Clean</div>
                      </div>
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <div className="text-2xl font-bold text-gray-600">{result.checks.virustotal.undetected}</div>
                        <div className="text-xs text-gray-600 mt-1 font-medium">Undetected</div>
                      </div>
                    </div>

                    {result.checks.virustotal.detections && result.checks.virustotal.detections.length > 0 && (
                      <div className="mt-4">
                        <button
                          onClick={() => setShowDetections(!showDetections)}
                          className="text-sm text-blue-600 hover:text-blue-700 font-semibold flex items-center gap-2"
                        >
                          <svg className={`w-4 h-4 transition-transform duration-200 ${showDetections ? 'rotate-90' : ''}`} fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                          </svg>
                          {showDetections ? 'Hide' : 'Show'} {result.checks.virustotal.detections.length} engine detections
                        </button>

                        {showDetections && (
                          <div className="mt-3 max-h-48 overflow-y-auto border border-gray-200 rounded-lg bg-gray-50">
                            {result.checks.virustotal.detections.map((detection: any, idx: number) => (
                              <div key={idx} className="flex justify-between items-center px-3 py-2 border-b border-gray-200 last:border-0 text-sm hover:bg-white transition-colors">
                                <span className="font-semibold text-gray-800">{detection.engine}</span>
                                <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${
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
                  <div className="bg-white rounded-xl border border-gray-200 shadow-md p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <svg className="w-5 h-5 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                      </svg>
                      <h4 className="font-semibold text-gray-900 text-base">Google Safe Browsing</h4>
                    </div>
                    <div className={`flex items-center gap-2 ${result.checks.safeBrowsing.safe ? 'text-green-700' : 'text-red-700'}`}>
                      <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                      <span className="text-sm font-semibold">
                        {result.checks.safeBrowsing.safe ? 'No threats detected' : 'Threats detected'}
                      </span>
                    </div>
                  </div>
                )}

                {/* SSL Certificate */}
                {result.checks.ssl && (
                  <div className="bg-white rounded-xl border border-gray-200 shadow-md p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <svg className="w-5 h-5 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                      <h4 className="font-semibold text-gray-900 text-base">SSL Certificate</h4>
                    </div>
                    <div className="space-y-2 text-sm">
                      <div className={`flex items-center gap-2 ${result.checks.ssl.secure ? 'text-green-700' : 'text-orange-700'}`}>
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                        </svg>
                        <span className="font-semibold">
                          {result.checks.ssl.secure ? 'Secure HTTPS' : 'Insecure HTTP'}
                        </span>
                      </div>
                      {result.checks.ssl.certificate && !result.checks.ssl.certificate.error && (
                        <div className="pl-6 space-y-1 text-gray-600">
                          <div><span className="font-semibold">Issuer:</span> {result.checks.ssl.certificate.issuer}</div>
                          <div><span className="font-semibold">Age:</span> {result.checks.ssl.certificate.certAge} days</div>
                          <div><span className="font-semibold">Expires:</span> {result.checks.ssl.certificate.daysUntilExpiry} days</div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Domain Info */}
                {result.checks.whois && !result.checks.whois.error && (
                  <div className="bg-white rounded-xl border border-gray-200 shadow-md p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <svg className="w-5 h-5 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                      </svg>
                      <h4 className="font-semibold text-gray-900 text-base">Domain Information</h4>
                    </div>
                    <div className="space-y-2 text-sm text-gray-600">
                      {result.checks.whois.domainAge !== null && result.checks.whois.domainAge !== undefined && (
                        <div className={result.checks.whois.isNew ? 'text-red-700 font-semibold' : ''}>
                          <span className="font-semibold">Age:</span> {result.checks.whois.domainAge} days
                          {result.checks.whois.isNew && ' (NEW)'}
                        </div>
                      )}
                      {result.checks.whois.registrar && (
                        <div><span className="font-semibold">Registrar:</span> {result.checks.whois.registrar}</div>
                      )}
                      {result.checks.whois.createdDate && (
                        <div><span className="font-semibold">Created:</span> {new Date(result.checks.whois.createdDate).toLocaleDateString()}</div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* URL Display */}
              <div className="bg-white rounded-xl border border-gray-200 shadow-md p-4">
                <p className="text-sm text-gray-600 font-mono break-all">{result.url}</p>
              </div>

              {/* Back Button */}
              <div className="text-center">
                <button
                  onClick={() => {
                    setResult(null);
                    setInput('');
                  }}
                  className="inline-flex items-center gap-2 px-6 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold rounded-lg transition-colors duration-200"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                  </svg>
                  Check Another URL
                </button>
              </div>
            </div>
          )}

          {/* Multi URL Results */}
          {multiResult && !loading && (
            <div className="space-y-6 fade-in">
              {/* Summary */}
              <div className="bg-white rounded-xl border border-gray-200 shadow-lg p-8">
                <h3 className="text-2xl font-bold text-gray-900 mb-6">Scan Results</h3>
                <div className="grid grid-cols-3 gap-6 mb-6">
                  <div className="text-center p-6 bg-gray-50 rounded-xl">
                    <div className="text-4xl font-bold text-gray-900">{multiResult.totalUrls}</div>
                    <div className="text-sm text-gray-600 mt-2 font-medium">Total URLs</div>
                  </div>
                  <div className="text-center p-6 bg-red-50 rounded-xl">
                    <div className="text-4xl font-bold text-red-600">{multiResult.suspiciousCount}</div>
                    <div className="text-sm text-gray-600 mt-2 font-medium">Suspicious</div>
                  </div>
                  <div className="text-center p-6 bg-green-50 rounded-xl">
                    <div className="text-4xl font-bold text-green-600">{multiResult.cleanCount}</div>
                    <div className="text-sm text-gray-600 mt-2 font-medium">Clean</div>
                  </div>
                </div>
                {multiResult.suspiciousCount > 0 && (
                  <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-3">
                    <svg className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                    <p className="text-sm text-red-800 font-semibold">Warning: Suspicious URLs detected. Do not click these links.</p>
                  </div>
                )}
              </div>

              {/* URL List */}
              <div className="space-y-4">
                {multiResult.results.map((res, idx) => (
                  <div key={idx} className={`bg-white rounded-xl border-2 shadow-md p-5 ${
                    res.verdict === 'SUSPICIOUS' ? 'border-red-200' : 'border-green-200'
                  }`}>
                    <div className="flex items-start gap-4">
                      <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${
                        res.verdict === 'SUSPICIOUS' ? 'bg-red-100' : 'bg-green-100'
                      }`}>
                        {res.verdict === 'SUSPICIOUS' ? (
                          <svg className="w-5 h-5 text-red-600" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                          </svg>
                        ) : (
                          <svg className="w-5 h-5 text-green-600" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                          </svg>
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-mono break-all text-gray-900 mb-3">{res.url}</p>
                        <div className="flex items-center gap-2 mb-3">
                          <span className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
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
                              <li key={reasonIdx} className="flex items-start gap-2">
                                <span className="text-gray-400 font-bold">•</span>
                                <span>{reason}</span>
                              </li>
                            ))}
                          </ul>
                        )}

                        {res.checks.virustotal?.detections && res.checks.virustotal.detections.length > 0 && (
                          <div className="mt-3">
                            <button
                              onClick={() => setExpandedUrlIndex(expandedUrlIndex === idx ? null : idx)}
                              className="text-sm text-blue-600 hover:text-blue-700 font-semibold flex items-center gap-2"
                            >
                              <svg className={`w-4 h-4 transition-transform duration-200 ${expandedUrlIndex === idx ? 'rotate-90' : ''}`} fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                              </svg>
                              {expandedUrlIndex === idx ? 'Hide' : 'Show'} {res.checks.virustotal.detections.length} engine detections
                            </button>

                            {expandedUrlIndex === idx && (
                              <div className="mt-3 max-h-40 overflow-y-auto border border-gray-200 rounded-lg bg-gray-50">
                                {res.checks.virustotal.detections.map((detection: any, detIdx: number) => (
                                  <div key={detIdx} className="flex justify-between items-center px-3 py-2 border-b border-gray-200 last:border-0 text-sm hover:bg-white transition-colors">
                                    <span className="font-semibold text-gray-800">{detection.engine}</span>
                                    <span className="text-red-600 font-medium">{detection.result}</span>
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
              <div className="text-center mt-8">
                <button
                  onClick={() => {
                    setMultiResult(null);
                    setInput('');
                  }}
                  className="inline-flex items-center gap-2 px-6 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold rounded-lg transition-colors duration-200"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                  </svg>
                  Check More URLs
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-200 py-6 mt-16">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <p className="text-sm text-gray-600">
            Powered by{' '}
            <a
              href="https://www.sendmarc.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:text-blue-700 font-medium"
            >
              Sendmarc
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}
