'use client';

import { useState } from 'react';
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
    ssl?: any;
    domain?: any;
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
  const [mode, setMode] = useState<'url' | 'email'>('url');
  const [showDetections, setShowDetections] = useState<boolean>(false);
  const [expandedUrlIndex, setExpandedUrlIndex] = useState<number | null>(null);
  const [url, setUrl] = useState('');
  const [emailContent, setEmailContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [multiResult, setMultiResult] = useState<MultiUrlResult | null>(null);
  const [error, setError] = useState('');

  const extractUrls = (text: string): string[] => {
    const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+)/gi;
    const matches = text.match(urlRegex);
    return matches ? [...new Set(matches)] : [];
  };

  const handleCheckUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    setMultiResult(null);

    try {
      const response = await fetch('/api/check-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to check URL');
      }

      setResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCheckEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    setMultiResult(null);

    try {
      const urls = extractUrls(emailContent);

      if (urls.length === 0) {
        throw new Error('No URLs found in the email content');
      }

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
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-3">
          <Image
            src="https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg"
            alt="Sendmarc"
            width={140}
            height={36}
            className="h-9 w-auto"
          />
          <span className="text-gray-300">|</span>
          <h1 className="text-lg font-medium text-gray-700">Phishing URL Checker</h1>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-5xl mx-auto px-6 py-12">
        {/* Hero */}
        <div className="text-center mb-10">
          <h2 className="text-3xl font-bold text-gray-900 mb-3">
            Check URLs for Phishing & Malware
          </h2>
          <p className="text-gray-600">
            Analyze single URLs or paste entire email content
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6">
          <button
            onClick={() => {
              setMode('url');
              setError('');
              setResult(null);
              setMultiResult(null);
            }}
            className={`px-5 py-2.5 font-medium rounded-t-lg transition ${
              mode === 'url'
                ? 'bg-white border-t-2 border-x border-gray-200 text-blue-600'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
            style={mode === 'url' ? { borderTopColor: '#0073EA', color: '#0073EA' } : {}}
          >
            Single URL
          </button>
          <button
            onClick={() => {
              setMode('email');
              setError('');
              setResult(null);
              setMultiResult(null);
            }}
            className={`px-5 py-2.5 font-medium rounded-t-lg transition ${
              mode === 'email'
                ? 'bg-white border-t-2 border-x border-gray-200 text-blue-600'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
            style={mode === 'email' ? { borderTopColor: '#0073EA', color: '#0073EA' } : {}}
          >
            Email Content
          </button>
        </div>

        {/* Input Form */}
        <div className="bg-white rounded-lg border border-gray-200 p-6 shadow-sm mb-8">
          {mode === 'url' ? (
            <form onSubmit={handleCheckUrl} className="space-y-4">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                style={{ '--tw-ring-color': '#0073EA' } as any}
                required
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-lg font-medium text-white transition"
                style={{ backgroundColor: '#0073EA' }}
                onMouseOver={(e) => (e.currentTarget.style.backgroundColor = '#005bb5')}
                onMouseOut={(e) => (e.currentTarget.style.backgroundColor = '#0073EA')}
              >
                {loading ? 'Checking...' : 'Check URL'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleCheckEmail} className="space-y-4">
              <textarea
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                placeholder="Paste email content here..."
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                style={{ '--tw-ring-color': '#0073EA' } as any}
                rows={8}
                required
                disabled={loading}
              />
              <p className="text-xs text-gray-500">
                We'll automatically extract and check all URLs
              </p>
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-lg font-medium text-white transition"
                style={{ backgroundColor: '#0073EA' }}
                onMouseOver={(e) => (e.currentTarget.style.backgroundColor = '#005bb5')}
                onMouseOut={(e) => (e.currentTarget.style.backgroundColor = '#0073EA')}
              >
                {loading ? 'Analyzing...' : 'Analyze Email'}
              </button>
            </form>
          )}

          {error && (
            <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm">
              {error}
            </div>
          )}
        </div>

        {/* Single URL Result */}
        {result && (
          <div className="space-y-6">
            <div className={`rounded-lg border p-6 ${
              result.verdict === 'SUSPICIOUS'
                ? 'bg-red-50 border-red-200'
                : 'bg-green-50 border-green-200'
            }`}>
              <div className="text-center">
                <div className={`text-4xl font-bold mb-3 ${
                  result.verdict === 'SUSPICIOUS' ? 'text-red-600' : 'text-green-600'
                }`}>
                  {result.verdict === 'SUSPICIOUS' ? '🔴 SUSPICIOUS' : '🟢 CLEAN'}
                </div>
                <div className="text-base font-medium text-gray-700 mb-2">
                  {result.verdict === 'SUSPICIOUS' ? 'Avoid this link' : 'No threats detected'}
                </div>
                {result.suspicionReasons && result.suspicionReasons.length > 0 && (
                  <div className="text-sm text-gray-600 space-y-1 mt-3">
                    {result.suspicionReasons.map((reason, idx) => (
                      <div key={idx}>• {reason}</div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold mb-4 text-gray-900">Security Analysis</h3>

              <div className="space-y-5">
                {result.checks.virustotal && !result.checks.virustotal.error && !result.checks.virustotal.status && (
                  <div>
                    <h4 className="font-medium mb-3 text-gray-700">VirusTotal</h4>
                    <div className="grid grid-cols-4 gap-3">
                      <div className="bg-red-50 p-3 rounded-lg text-center">
                        <div className="text-xl font-bold text-red-600">
                          {result.checks.virustotal.malicious}
                        </div>
                        <div className="text-xs text-gray-600 mt-1">Malicious</div>
                      </div>
                      <div className="bg-orange-50 p-3 rounded-lg text-center">
                        <div className="text-xl font-bold text-orange-600">
                          {result.checks.virustotal.suspicious}
                        </div>
                        <div className="text-xs text-gray-600 mt-1">Suspicious</div>
                      </div>
                      <div className="bg-green-50 p-3 rounded-lg text-center">
                        <div className="text-xl font-bold text-green-600">
                          {result.checks.virustotal.harmless}
                        </div>
                        <div className="text-xs text-gray-600 mt-1">Clean</div>
                      </div>
                      <div className="bg-gray-50 p-3 rounded-lg text-center">
                        <div className="text-xl font-bold text-gray-600">
                          {result.checks.virustotal.undetected}
                        </div>
                        <div className="text-xs text-gray-600 mt-1">Undetected</div>
                      </div>
                    </div>

                    {result.checks.virustotal.detections && result.checks.virustotal.detections.length > 0 && (
                      <div className="mt-4">
                        <button
                          onClick={() => setShowDetections(!showDetections)}
                          className="text-sm text-blue-600 hover:text-blue-800 font-medium"
                        >
                          {showDetections ? '▼' : '▶'} Show which engines flagged this ({result.checks.virustotal.detections.length})
                        </button>

                        {showDetections && (
                          <div className="mt-3 p-3 bg-gray-50 rounded border border-gray-200 max-h-60 overflow-y-auto">
                            <div className="space-y-2 text-sm">
                              {result.checks.virustotal.detections.map((detection: any, idx: number) => (
                                <div key={idx} className="flex justify-between items-center py-1 border-b border-gray-200 last:border-0">
                                  <span className="font-medium text-gray-700">{detection.engine}</span>
                                  <span className={`px-2 py-1 rounded text-xs ${
                                    detection.category === 'malicious' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
                                  }`}>
                                    {detection.category}: {detection.result}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {result.checks.safeBrowsing && !result.checks.safeBrowsing.error && (
                  <div>
                    <h4 className="font-medium text-gray-700">Google Safe Browsing</h4>
                    <p className={`text-sm mt-2 ${result.checks.safeBrowsing.safe ? 'text-green-600' : 'text-red-600'}`}>
                      {result.checks.safeBrowsing.safe ? '✓ No threats detected' : '⚠ Threats detected'}
                    </p>
                  </div>
                )}

                {result.checks.ssl && (
                  <div>
                    <h4 className="font-medium text-gray-700">Security</h4>
                    <p className={`text-sm mt-2 ${result.checks.ssl.secure ? 'text-green-600' : 'text-orange-600'}`}>
                      {result.checks.ssl.secure ? '✓ HTTPS' : '⚠ No HTTPS'}
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
              <p className="text-sm text-gray-600 break-all">{result.url}</p>
            </div>
          </div>
        )}

        {/* Multi URL Results */}
        {multiResult && (
          <div className="space-y-6">
            {/* Overall Email Risk */}
            <div className={`rounded-lg border p-6 ${
              multiResult.suspiciousCount > 0
                ? 'bg-red-50 border-red-200'
                : 'bg-green-50 border-green-200'
            }`}>
              <div className="text-center">
                <div className={`text-3xl font-bold mb-2 ${
                  multiResult.suspiciousCount > 0 ? 'text-red-600' : 'text-green-600'
                }`}>
                  {multiResult.suspiciousCount > 0 ? '🔴 SUSPICIOUS EMAIL' : '🟢 SAFE EMAIL'}
                </div>
                <div className="text-sm text-gray-600">
                  {multiResult.suspiciousCount > 0
                    ? `${multiResult.suspiciousCount} suspicious link${multiResult.suspiciousCount > 1 ? 's' : ''} detected`
                    : 'All links are clean'}
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold mb-4 text-gray-900">Summary</h3>

              <div className="grid grid-cols-3 gap-4">
                <div className="bg-gray-50 p-4 rounded-lg text-center">
                  <div className="text-3xl font-bold text-gray-900">{multiResult.totalUrls}</div>
                  <div className="text-sm text-gray-600 mt-1">Total Links</div>
                </div>
                <div className="bg-red-50 p-4 rounded-lg text-center">
                  <div className="text-3xl font-bold text-red-600">{multiResult.suspiciousCount}</div>
                  <div className="text-sm text-gray-600 mt-1">Suspicious</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg text-center">
                  <div className="text-3xl font-bold text-green-600">{multiResult.cleanCount}</div>
                  <div className="text-sm text-gray-600 mt-1">Clean</div>
                </div>
              </div>

              {multiResult.suspiciousCount > 0 && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 mt-4">
                  <p className="text-red-600 text-sm font-medium">⚠️ Do not click on suspicious links</p>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <h3 className="text-lg font-semibold text-gray-900">URL Results</h3>
              {multiResult.results.map((res, idx) => (
                <div key={idx} className={`rounded-lg border p-4 ${
                  res.verdict === 'SUSPICIOUS'
                    ? 'bg-red-50 border-red-200'
                    : 'bg-green-50 border-green-200'
                }`}>
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono break-all text-gray-700 mb-2">{res.url}</p>
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                          res.verdict === 'SUSPICIOUS'
                            ? 'bg-red-100 text-red-700'
                            : 'bg-green-100 text-green-700'
                        }`}>
                          {res.verdict === 'SUSPICIOUS' ? '🔴 SUSPICIOUS' : '🟢 CLEAN'}
                        </span>
                      </div>

                      {res.suspicionReasons && res.suspicionReasons.length > 0 && (
                        <div className="text-xs text-gray-600 space-y-1 mb-2">
                          {res.suspicionReasons.map((reason, reasonIdx) => (
                            <div key={reasonIdx}>• {reason}</div>
                          ))}
                        </div>
                      )}

                      {res.checks.virustotal?.detections && res.checks.virustotal.detections.length > 0 && (
                        <div className="mt-2">
                          <button
                            onClick={() => setExpandedUrlIndex(expandedUrlIndex === idx ? null : idx)}
                            className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                          >
                            {expandedUrlIndex === idx ? '▼' : '▶'} Show which engines flagged this ({res.checks.virustotal.detections.length})
                          </button>

                          {expandedUrlIndex === idx && (
                            <div className="mt-2 p-2 bg-gray-50 rounded border border-gray-200 max-h-40 overflow-y-auto">
                              <div className="space-y-1 text-xs">
                                {res.checks.virustotal.detections.map((detection: any, detIdx: number) => (
                                  <div key={detIdx} className="flex justify-between items-center py-1 border-b border-gray-200 last:border-0">
                                    <span className="font-medium text-gray-700">{detection.engine}</span>
                                    <span className={`px-2 py-0.5 rounded text-xs ${
                                      detection.category === 'malicious' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
                                    }`}>
                                      {detection.category}: {detection.result}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-200 py-6 mt-16">
        <div className="max-w-5xl mx-auto px-6 text-center">
          <p className="text-sm text-gray-600">
            Powered by{' '}
            <a
              href="https://www.sendmarc.com"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:underline"
              style={{ color: '#0073EA' }}
            >
              Sendmarc
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}
