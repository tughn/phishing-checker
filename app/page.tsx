'use client';

import { useState } from 'react';
import Image from 'next/image';

interface CheckResult {
  url: string;
  timestamp: string;
  riskScore: number;
  riskLevel: string;
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
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  safeCount: number;
}

export default function Home() {
  const [mode, setMode] = useState<'url' | 'email'>('url');
  const [url, setUrl] = useState('');
  const [emailContent, setEmailContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [multiResult, setMultiResult] = useState<MultiUrlResult | null>(null);
  const [error, setError] = useState('');

  const extractUrls = (text: string): string[] => {
    // Regex to match URLs
    const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+)/gi;
    const matches = text.match(urlRegex);
    return matches ? [...new Set(matches)] : []; // Remove duplicates
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
        headers: {
          'Content-Type': 'application/json',
        },
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

      // Check all URLs
      const results: CheckResult[] = [];
      let highRisk = 0, mediumRisk = 0, lowRisk = 0, safe = 0;

      for (const url of urls) {
        try {
          const response = await fetch('/api/check-url', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }),
          });

          const data = await response.json();

          if (response.ok) {
            results.push(data);

            // Count risk levels
            if (data.riskLevel === 'HIGH') highRisk++;
            else if (data.riskLevel === 'MEDIUM') mediumRisk++;
            else if (data.riskLevel === 'LOW') lowRisk++;
            else safe++;
          }
        } catch (err) {
          console.error(`Failed to check ${url}:`, err);
        }
      }

      setMultiResult({
        urls,
        results,
        totalUrls: urls.length,
        highRiskCount: highRisk,
        mediumRiskCount: mediumRisk,
        lowRiskCount: lowRisk,
        safeCount: safe,
      });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'HIGH':
        return 'text-red-600';
      case 'MEDIUM':
        return 'text-orange-500';
      case 'LOW':
        return 'text-yellow-600';
      case 'SAFE':
        return 'text-green-600';
      default:
        return 'text-gray-600';
    }
  };

  const getRiskBg = (level: string) => {
    switch (level) {
      case 'HIGH':
        return 'bg-red-50 border-red-200';
      case 'MEDIUM':
        return 'bg-orange-50 border-orange-200';
      case 'LOW':
        return 'bg-yellow-50 border-yellow-200';
      case 'SAFE':
        return 'bg-green-50 border-green-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="border-b border-gray-200 py-4 px-6">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Image
              src="https://help.sendmarc.com/hubfs/Sendmarc-Logo-RGB-Main.jpg"
              alt="Sendmarc"
              width={150}
              height={40}
              className="h-10 w-auto"
            />
            <span className="text-gray-400">|</span>
            <h1 className="text-xl font-medium" style={{ color: 'var(--sendmarc-dark)' }}>
              Phishing URL Checker
            </h1>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-6 py-12">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold mb-4" style={{ color: 'var(--sendmarc-dark)' }}>
            Check URLs for Phishing & Malware
          </h2>
          <p className="text-lg" style={{ color: 'var(--sendmarc-gray)' }}>
            Analyze single URLs or paste entire email content to check all links at once
          </p>
        </div>

        {/* Mode Tabs */}
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => {
              setMode('url');
              setError('');
              setResult(null);
              setMultiResult(null);
            }}
            className={`px-6 py-3 rounded-t-lg font-medium transition-all ${
              mode === 'url'
                ? 'bg-white border-t border-l border-r border-gray-200 text-sendmarc-primary'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            Check Single URL
          </button>
          <button
            onClick={() => {
              setMode('email');
              setError('');
              setResult(null);
              setMultiResult(null);
            }}
            className={`px-6 py-3 rounded-t-lg font-medium transition-all ${
              mode === 'email'
                ? 'bg-white border-t border-l border-r border-gray-200 text-sendmarc-primary'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            Paste Email Content
          </button>
        </div>

        {/* Input Form */}
        <div className="bg-white border border-gray-200 rounded-lg p-8 shadow-sm mb-8">
          {mode === 'url' ? (
            <form onSubmit={handleCheckUrl} className="space-y-4">
              <div>
                <label
                  htmlFor="url"
                  className="block text-sm font-medium mb-2"
                  style={{ color: 'var(--sendmarc-dark)' }}
                >
                  Enter URL to check
                </label>
                <input
                  type="text"
                  id="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com or http://suspicious-site.com"
                  className="w-full px-4 py-3 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-sendmarc-primary"
                  required
                  disabled={loading}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-sendmarc w-full py-3 text-lg font-medium"
              >
                {loading ? 'Checking...' : 'Check URL'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleCheckEmail} className="space-y-4">
              <div>
                <label
                  htmlFor="emailContent"
                  className="block text-sm font-medium mb-2"
                  style={{ color: 'var(--sendmarc-dark)' }}
                >
                  Paste email content
                </label>
                <textarea
                  id="emailContent"
                  value={emailContent}
                  onChange={(e) => setEmailContent(e.target.value)}
                  placeholder="Paste the entire email content here. Example:

Hello,

Please click here to verify your account:
https://suspicious-site.com/verify

Or visit: https://another-link.com

Thank you!"
                  className="w-full px-4 py-3 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-sendmarc-primary"
                  rows={10}
                  required
                  disabled={loading}
                />
                <p className="text-xs mt-2" style={{ color: 'var(--sendmarc-gray)' }}>
                  We'll automatically extract and check all URLs found in the text
                </p>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-sendmarc w-full py-3 text-lg font-medium"
              >
                {loading ? 'Analyzing URLs...' : 'Analyze Email'}
              </button>
            </form>
          )}

          {error && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded">
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          )}
        </div>

        {/* Single URL Result */}
        {result && (
          <div className="space-y-6">
            {/* Risk Score */}
            <div className={`border rounded-lg p-8 ${getRiskBg(result.riskLevel)}`}>
              <div className="text-center">
                <div className="text-6xl font-bold mb-2" style={{ color: 'var(--sendmarc-primary)' }}>
                  {result.riskScore}/100
                </div>
                <div className={`text-2xl font-semibold mb-2 ${getRiskColor(result.riskLevel)}`}>
                  {result.riskLevel} RISK
                </div>
                <div className="text-sm" style={{ color: 'var(--sendmarc-gray)' }}>
                  Checked: {new Date(result.timestamp).toLocaleString()}
                </div>
              </div>
            </div>

            {/* Detailed Results */}
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4" style={{ color: 'var(--sendmarc-dark)' }}>
                Security Analysis
              </h3>

              <div className="space-y-6">
                {/* VirusTotal */}
                {result.checks.virustotal && (
                  <div className="border-b pb-4">
                    <h4 className="font-semibold mb-2 flex items-center gap-2">
                      <span style={{ color: 'var(--sendmarc-primary)' }}>●</span>
                      VirusTotal Analysis
                    </h4>
                    {result.checks.virustotal.status === 'scanning' ? (
                      <p className="text-sm" style={{ color: 'var(--sendmarc-gray)' }}>
                        {result.checks.virustotal.message}
                      </p>
                    ) : result.checks.virustotal.error ? (
                      <p className="text-sm text-red-600">{result.checks.virustotal.error}</p>
                    ) : (
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-2">
                        <div className="bg-red-50 p-3 rounded">
                          <div className="text-2xl font-bold text-red-600">
                            {result.checks.virustotal.malicious}
                          </div>
                          <div className="text-xs text-gray-600">Malicious</div>
                        </div>
                        <div className="bg-orange-50 p-3 rounded">
                          <div className="text-2xl font-bold text-orange-600">
                            {result.checks.virustotal.suspicious}
                          </div>
                          <div className="text-xs text-gray-600">Suspicious</div>
                        </div>
                        <div className="bg-green-50 p-3 rounded">
                          <div className="text-2xl font-bold text-green-600">
                            {result.checks.virustotal.harmless}
                          </div>
                          <div className="text-xs text-gray-600">Harmless</div>
                        </div>
                        <div className="bg-gray-50 p-3 rounded">
                          <div className="text-2xl font-bold text-gray-600">
                            {result.checks.virustotal.undetected}
                          </div>
                          <div className="text-xs text-gray-600">Undetected</div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Google Safe Browsing */}
                {result.checks.safeBrowsing && (
                  <div className="border-b pb-4">
                    <h4 className="font-semibold mb-2 flex items-center gap-2">
                      <span style={{ color: 'var(--sendmarc-primary)' }}>●</span>
                      Google Safe Browsing
                    </h4>
                    {result.checks.safeBrowsing.error ? (
                      <p className="text-sm text-red-600">{result.checks.safeBrowsing.error}</p>
                    ) : result.checks.safeBrowsing.safe ? (
                      <p className="text-sm text-green-600">✓ No threats detected</p>
                    ) : (
                      <div className="space-y-2">
                        <p className="text-sm text-red-600">⚠ Threats detected:</p>
                        {result.checks.safeBrowsing.threats.map((threat: any, idx: number) => (
                          <div key={idx} className="text-sm bg-red-50 p-2 rounded">
                            {threat.threatType}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* SSL Check */}
                {result.checks.ssl && (
                  <div className="border-b pb-4">
                    <h4 className="font-semibold mb-2 flex items-center gap-2">
                      <span style={{ color: 'var(--sendmarc-primary)' }}>●</span>
                      SSL/TLS Security
                    </h4>
                    {result.checks.ssl.error ? (
                      <p className="text-sm text-red-600">{result.checks.ssl.error}</p>
                    ) : (
                      <p className={`text-sm ${result.checks.ssl.secure ? 'text-green-600' : 'text-red-600'}`}>
                        {result.checks.ssl.secure ? '✓ HTTPS secured' : '⚠ Not using HTTPS'}
                      </p>
                    )}
                  </div>
                )}

                {/* Domain Info */}
                {result.checks.domain && (
                  <div>
                    <h4 className="font-semibold mb-2 flex items-center gap-2">
                      <span style={{ color: 'var(--sendmarc-primary)' }}>●</span>
                      Domain Information
                    </h4>
                    <p className="text-sm" style={{ color: 'var(--sendmarc-gray)' }}>
                      {result.checks.domain.hostname}
                    </p>
                    {result.checks.domain.note && (
                      <p className="text-xs text-gray-500 mt-1">{result.checks.domain.note}</p>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* URL Checked */}
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
              <p className="text-sm font-medium mb-1" style={{ color: 'var(--sendmarc-dark)' }}>
                URL Checked:
              </p>
              <p className="text-sm break-all" style={{ color: 'var(--sendmarc-gray)' }}>
                {result.url}
              </p>
            </div>
          </div>
        )}

        {/* Multi URL Results */}
        {multiResult && (
          <div className="space-y-6">
            {/* Summary */}
            <div className="bg-white border border-gray-200 rounded-lg p-6">
              <h3 className="text-xl font-semibold mb-4" style={{ color: 'var(--sendmarc-dark)' }}>
                Email Analysis Summary
              </h3>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <div className="bg-gray-50 p-4 rounded text-center">
                  <div className="text-3xl font-bold" style={{ color: 'var(--sendmarc-dark)' }}>
                    {multiResult.totalUrls}
                  </div>
                  <div className="text-xs text-gray-600">Total URLs</div>
                </div>
                <div className="bg-red-50 p-4 rounded text-center">
                  <div className="text-3xl font-bold text-red-600">
                    {multiResult.highRiskCount}
                  </div>
                  <div className="text-xs text-gray-600">High Risk</div>
                </div>
                <div className="bg-orange-50 p-4 rounded text-center">
                  <div className="text-3xl font-bold text-orange-600">
                    {multiResult.mediumRiskCount}
                  </div>
                  <div className="text-xs text-gray-600">Medium Risk</div>
                </div>
                <div className="bg-yellow-50 p-4 rounded text-center">
                  <div className="text-3xl font-bold text-yellow-600">
                    {multiResult.lowRiskCount}
                  </div>
                  <div className="text-xs text-gray-600">Low Risk</div>
                </div>
                <div className="bg-green-50 p-4 rounded text-center">
                  <div className="text-3xl font-bold text-green-600">
                    {multiResult.safeCount}
                  </div>
                  <div className="text-xs text-gray-600">Safe</div>
                </div>
              </div>

              {multiResult.highRiskCount > 0 && (
                <div className="bg-red-50 border border-red-200 rounded p-4 mb-4">
                  <p className="text-red-600 font-semibold">⚠ Warning: High risk URLs detected in this email!</p>
                </div>
              )}
            </div>

            {/* Individual URL Results */}
            <div className="space-y-4">
              <h3 className="text-xl font-semibold" style={{ color: 'var(--sendmarc-dark)' }}>
                Individual URL Results
              </h3>

              {multiResult.results.map((res, idx) => (
                <div key={idx} className={`border rounded-lg p-4 ${getRiskBg(res.riskLevel)}`}>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <p className="text-sm font-mono break-all mb-2" style={{ color: 'var(--sendmarc-gray)' }}>
                        {res.url}
                      </p>
                      <div className="flex items-center gap-4 text-sm">
                        <span className={`font-semibold ${getRiskColor(res.riskLevel)}`}>
                          {res.riskLevel}
                        </span>
                        {res.checks.safeBrowsing?.safe === false && (
                          <span className="text-red-600">⚠ Phishing Threat</span>
                        )}
                        {res.checks.virustotal?.malicious > 0 && (
                          <span className="text-red-600">
                            {res.checks.virustotal.malicious} engines flagged
                          </span>
                        )}
                        {!res.checks.ssl?.secure && (
                          <span className="text-orange-600">No HTTPS</span>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold" style={{ color: 'var(--sendmarc-primary)' }}>
                        {res.riskScore}
                      </div>
                      <div className="text-xs text-gray-600">Risk Score</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* URLs Found */}
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
              <p className="text-sm font-medium mb-2" style={{ color: 'var(--sendmarc-dark)' }}>
                URLs Found ({multiResult.urls.length}):
              </p>
              <ul className="text-sm space-y-1">
                {multiResult.urls.map((url, idx) => (
                  <li key={idx} className="break-all" style={{ color: 'var(--sendmarc-gray)' }}>
                    • {url}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-200 py-8 px-6 mt-16">
        <div className="max-w-6xl mx-auto text-center">
          <p className="text-sm" style={{ color: 'var(--sendmarc-gray)' }}>
            Powered by{' '}
            <a
              href="https://www.sendmarc.com"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--sendmarc-primary)' }}
              className="hover:underline"
            >
              Sendmarc
            </a>{' '}
            | Free Phishing URL Security Check
          </p>
        </div>
      </footer>
    </div>
  );
}
