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
      let highRisk = 0, mediumRisk = 0, lowRisk = 0, safe = 0;

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
      case 'HIGH': return 'text-red-600';
      case 'MEDIUM': return 'text-orange-500';
      case 'LOW': return 'text-yellow-600';
      case 'SAFE': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getRiskBg = (level: string) => {
    switch (level) {
      case 'HIGH': return 'bg-red-50 border-red-200';
      case 'MEDIUM': return 'bg-orange-50 border-orange-200';
      case 'LOW': return 'bg-yellow-50 border-yellow-200';
      case 'SAFE': return 'bg-green-50 border-green-200';
      default: return 'bg-gray-50 border-gray-200';
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
            <div className={`rounded-lg border p-6 ${getRiskBg(result.riskLevel)}`}>
              <div className="text-center">
                <div className="text-5xl font-bold mb-2" style={{ color: '#0073EA' }}>
                  {result.riskScore}
                </div>
                <div className={`text-xl font-semibold mb-2 ${getRiskColor(result.riskLevel)}`}>
                  {result.riskLevel}
                </div>
                <div className="text-sm text-gray-600 space-y-1">
                  {result.checks.virustotal?.malicious > 0 && (
                    <div>{result.checks.virustotal.malicious} security engines flagged this</div>
                  )}
                  {result.checks.safeBrowsing?.safe === false && (
                    <div>Google detected phishing threat</div>
                  )}
                  {!result.checks.ssl?.secure && (
                    <div>Not using secure HTTPS</div>
                  )}
                  {result.riskScore === 0 && <div>No threats detected</div>}
                </div>
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
              multiResult.highRiskCount > 0 ? 'bg-red-50 border-red-200' :
              multiResult.mediumRiskCount > 0 ? 'bg-orange-50 border-orange-200' :
              multiResult.lowRiskCount > 0 ? 'bg-yellow-50 border-yellow-200' :
              'bg-green-50 border-green-200'
            }`}>
              <div className="text-center">
                <div className={`text-2xl font-bold mb-2 ${
                  multiResult.highRiskCount > 0 ? 'text-red-600' :
                  multiResult.mediumRiskCount > 0 ? 'text-orange-600' :
                  multiResult.lowRiskCount > 0 ? 'text-yellow-600' :
                  'text-green-600'
                }`}>
                  {multiResult.highRiskCount > 0 ? 'HIGH RISK EMAIL' :
                   multiResult.mediumRiskCount > 0 ? 'MEDIUM RISK EMAIL' :
                   multiResult.lowRiskCount > 0 ? 'LOW RISK EMAIL' :
                   'SAFE EMAIL'}
                </div>
                <div className="text-sm text-gray-600">
                  {multiResult.highRiskCount > 0 && `${multiResult.highRiskCount} high risk link${multiResult.highRiskCount > 1 ? 's' : ''} detected`}
                  {multiResult.mediumRiskCount > 0 && !multiResult.highRiskCount && `${multiResult.mediumRiskCount} medium risk link${multiResult.mediumRiskCount > 1 ? 's' : ''} detected`}
                  {multiResult.lowRiskCount > 0 && !multiResult.highRiskCount && !multiResult.mediumRiskCount && `${multiResult.lowRiskCount} low risk link${multiResult.lowRiskCount > 1 ? 's' : ''} detected`}
                  {multiResult.safeCount === multiResult.totalUrls && 'All links are safe'}
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold mb-4 text-gray-900">Summary</h3>

              <div className="grid grid-cols-5 gap-3">
                <div className="bg-gray-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-gray-900">{multiResult.totalUrls}</div>
                  <div className="text-xs text-gray-600 mt-1">Total</div>
                </div>
                <div className="bg-red-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-red-600">{multiResult.highRiskCount}</div>
                  <div className="text-xs text-gray-600 mt-1">High</div>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-orange-600">{multiResult.mediumRiskCount}</div>
                  <div className="text-xs text-gray-600 mt-1">Medium</div>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-yellow-600">{multiResult.lowRiskCount}</div>
                  <div className="text-xs text-gray-600 mt-1">Low</div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg text-center">
                  <div className="text-2xl font-bold text-green-600">{multiResult.safeCount}</div>
                  <div className="text-xs text-gray-600 mt-1">Safe</div>
                </div>
              </div>

              {multiResult.highRiskCount > 0 && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 mt-4">
                  <p className="text-red-600 text-sm font-medium">⚠ High risk URLs detected</p>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <h3 className="text-lg font-semibold text-gray-900">URL Results</h3>
              {multiResult.results.map((res, idx) => (
                <div key={idx} className={`rounded-lg border p-4 ${getRiskBg(res.riskLevel)}`}>
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono break-all text-gray-700 mb-1">{res.url}</p>
                      <div className="flex items-center gap-3 text-xs">
                        <span className={`font-medium ${getRiskColor(res.riskLevel)}`}>
                          {res.riskLevel}
                        </span>
                        {res.checks.virustotal?.malicious > 0 && (
                          <span className="text-red-600">{res.checks.virustotal.malicious} flagged</span>
                        )}
                        {!res.checks.ssl?.secure && <span className="text-orange-600">No HTTPS</span>}
                      </div>
                    </div>
                    <div className="text-2xl font-bold" style={{ color: '#0073EA' }}>
                      {res.riskScore}
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
