import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import client from '../api/client';
import { Shield, Play, Loader2, AlertCircle, CheckCircle } from 'lucide-react';

export default function NewScan() {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const attackVectors = [
    { code: 'A01', name: 'Prompt Injection', desc: 'Checks if input arguments allow system instruction overrides.' },
    { code: 'A02', name: 'Tool Poisoning', desc: 'Checks for semantic changes to manifest tools over subsequent calls.' },
    { code: 'A03', name: 'Token/Secret Exposure', desc: 'Checks tool outputs for API credentials, tokens, or private configurations.' },
    { code: 'A04', name: 'Shell Injection', desc: 'Injects system shell command characters into tool variables.' },
    { code: 'A05', name: 'SSRF Verification', desc: 'Detects internal IP loopbacks (e.g. AWS metadata endpoints) inside url variables.' },
    { code: 'A06', name: 'Rug Pull Detection', desc: 'Checks stability of tool definitions at different runtime intervals.' },
    { code: 'A07', name: 'Supply Chain & Channel Integrity', desc: 'Checks SSL validation, transport layer protocol, and CSP headers.' },
  ];

  const validateUrl = (testUrl) => {
    try {
      const parsed = new URL(testUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return 'URL must start with http:// or https://';
      }
      // Simple localhost/internal checks
      const hostname = parsed.hostname.toLowerCase();
      if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('10.') ||
        hostname.startsWith('172.16.')
      ) {
        return 'Scanning local / private network coordinates directly is restricted for safety.';
      }
      return null;
    } catch (err) {
      return 'Please enter a valid absolute URL (e.g., https://mcp-server.example.com).';
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    const urlError = validateUrl(url);
    if (urlError) {
      setError(urlError);
      return;
    }

    setLoading(true);

    try {
      const response = await client.post('/scans', { target_url: url });
      const scanId = response.data.scan_id || response.data.id;
      navigate(`/scans/${scanId}/progress`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to dispatch scan. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 max-w-4xl w-full mx-auto px-6 py-10">
      <div className="mb-8">
        <h1 className="text-[20px] font-semibold text-text-primary">Launch Security Scan</h1>
        <p className="text-text-secondary text-sm mt-1">
          Perform a comprehensive suite of security attacks against your Model Context Protocol server.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* URL Form Input */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-surface border border-border rounded p-6">
            {error && (
              <div className="bg-critical/10 border border-critical/30 rounded p-3 mb-6 flex items-start gap-2 text-sm text-critical">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
                  MCP Server Endpoints URL
                </label>
                <input
                  type="url"
                  required
                  placeholder="https://mcp-server.mycompany.com/tools"
                  className="w-full bg-surface-2 border border-border focus:border-primary focus:ring-1 focus:ring-primary rounded p-3 font-mono text-[13px] text-text-primary placeholder-text-muted outline-none transition-colors"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
                <p className="text-text-muted text-xs mt-2 leading-relaxed">
                  Enter the public HTTP/HTTPS endpoint of the MCP server. We will fetch the manifest first.
                </p>
              </div>

              <div>
                <span className="block text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
                  Scan Configuration
                </span>
                <div className="p-4 bg-surface-2/40 border border-border rounded">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-text-primary block">Full Security Audit</span>
                      <span className="text-xs text-text-secondary">Executes all 7 OWASP MCP security attack nodes</span>
                    </div>
                    <span className="text-[12px] font-semibold text-primary uppercase">
                      Active
                    </span>
                  </div>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white font-medium p-3 rounded-md transition-colors flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Deploying Attack Agents...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white" />
                    <span>Start Security Audit</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Informational Checklist Sidebar */}
        <div className="space-y-6">
          <div className="bg-surface border border-border rounded-lg p-6 shadow-md">
            <h3 className="text-sm font-bold text-text-primary mb-4 uppercase tracking-wider">
              Scan Audit Checklist
            </h3>
            <div className="space-y-4">
              {attackVectors.map((vector) => (
                <div key={vector.code} className="flex gap-3 text-xs">
                  <div className="mt-0.5 shrink-0">
                    <CheckCircle className="w-4 h-4 text-text-muted" />
                  </div>
                  <div>
                    <span className="font-semibold text-text-primary block">
                      {vector.code} — {vector.name}
                    </span>
                    <span className="text-text-secondary mt-0.5 block leading-relaxed">
                      {vector.desc}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
