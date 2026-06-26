import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import client from '../api/client';
import RiskScoreCircle from '../components/RiskScoreCircle';
import VulnerabilityCard from '../components/VulnerabilityCard';
import { Loader2, Download, Share2 } from 'lucide-react';

export default function Report() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);

  const fetchReport = async () => {
    if (id === 'demo') {
      setReport({
        scan_id: 'demo',
        risk_score: 72,
        risk_level: 'HIGH',
        total_critical: 1,
        total_high: 1,
        total_medium: 0,
        total_low: 0,
        total_passed: 5,
        target_url: 'https://api.copilot.corp/mcp',
        vulnerabilities: [
          {
            attack_id: 'A01',
            attack_name: 'Prompt Injection',
            status: 'VULNERABLE',
            severity: 'CRITICAL',
            cvss_score: 9.1,
            description: 'Tool description field or input parameters accept injected instructions.',
            evidence: 'Magic flag matched directly in response: {"content": [{"type": "text", "text": "INJECTION_SUCCESS_7x9k"}]}',
            fix_suggestion: 'Sanitize all input arguments. Ensure downstream agent/LLM treats tool outputs purely as untrusted data, applying rigid system prompt boundaries.',
            references: ['OWASP MCP Top 10 - MCP03']
          },
          {
            attack_id: 'A03',
            attack_name: 'Token/Secret Exposure',
            status: 'VULNERABLE',
            severity: 'HIGH',
            cvss_score: 7.8,
            description: 'Checks tool outputs for API credentials, tokens, or private configurations.',
            evidence: 'Pattern matched (AWS_SECRET_ACCESS_KEY) in tool execution output: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            fix_suggestion: 'Filter out environment variables and credential patterns from tool output strings before passing them to the agent context.',
            references: ['OWASP MCP Top 10 - MCP01']
          },
          {
            attack_id: 'A02',
            attack_name: 'Tool Poisoning',
            status: 'SAFE',
            severity: null,
            cvss_score: 0.0,
            description: 'Checks for semantic changes to manifest tools over subsequent calls.',
            evidence: 'No changes detected in tool definitions over runtime intervals.',
            fix_suggestion: null,
            references: ['OWASP MCP Top 10 - MCP04']
          },
          {
            attack_id: 'A04',
            attack_name: 'Shell Injection',
            status: 'SAFE',
            severity: null,
            cvss_score: 0.0,
            description: 'Injects system shell command characters into tool variables.',
            evidence: 'Command characters correctly sanitized by execution sandbox.',
            fix_suggestion: null,
            references: ['OWASP MCP Top 10 - MCP06']
          },
          {
            attack_id: 'A05',
            attack_name: 'SSRF Verification',
            status: 'SAFE',
            severity: null,
            cvss_score: 0.0,
            description: 'Detects internal IP loopbacks inside url variables.',
            evidence: 'Internal network endpoints are successfully rejected.',
            fix_suggestion: null,
            references: ['OWASP MCP Top 10 - MCP05']
          },
          {
            attack_id: 'A06',
            attack_name: 'Rug Pull Detection',
            status: 'SAFE',
            severity: null,
            cvss_score: 0.0,
            description: 'Checks stability of tool definitions at different runtime intervals.',
            evidence: 'Tool definition manifest remained stable throughout tests.',
            fix_suggestion: null,
            references: ['OWASP MCP Top 10 - MCP08']
          },
          {
            attack_id: 'A07',
            attack_name: 'Supply Chain Check',
            status: 'SAFE',
            severity: null,
            cvss_score: 0.0,
            description: 'Checks SSL validation, transport layer protocol, and CSP headers.',
            evidence: 'HTTPS transport validated and valid certificate detected.',
            fix_suggestion: null,
            references: ['OWASP MCP Top 10 - MCP09']
          }
        ],
        scan: {
          created_at: new Date().toISOString(),
          target_url: 'https://api.copilot.corp/mcp',
          server_name: 'Copilot Production MCP'
        }
      });
      setLoading(false);
      return;
    }
    try {
      const response = await client.get(`/reports/${id}`);
      setReport(response.data);
    } catch (err) {
      setError('Failed to fetch the scan report.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [id]);

  const handleShare = async () => {
    try {
      const response = await client.post(`/reports/${id}/share`);
      const shareUrl = response.data.share_url;
      const fullUrl = shareUrl.startsWith('http') 
        ? shareUrl 
        : `${window.location.origin}${shareUrl}`;
        
      await navigator.clipboard.writeText(fullUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      alert('Failed to generate sharing URL.');
    }
  };

  const handleDownloadPdf = async () => {
    setPdfLoading(true);
    try {
      const response = await client.get(`/reports/${id}/pdf`);
      const presignedUrl = response.data.presigned_url;
      window.open(presignedUrl, '_blank');
    } catch (err) {
      alert('Failed to download PDF report.');
    } finally {
      setPdfLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary mb-2" />
        <span className="text-text-secondary text-[14px]">Generating security report...</span>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-center p-6">
        <h3 className="text-[20px] font-semibold text-text-primary mb-2">Report Not Found</h3>
        <p className="text-[14px] text-text-secondary mb-6">{error || 'The requested scan ID does not exist.'}</p>
        <button
          onClick={() => navigate('/dashboard')}
          className="bg-primary text-white text-[14px] font-semibold px-4 py-2 rounded hover:bg-primary-hover transition-colors"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  const criticalFindings = report.vulnerabilities?.filter(v => v.status === 'VULNERABLE' && v.severity === 'CRITICAL').length || 0;
  const highFindings = report.vulnerabilities?.filter(v => v.status === 'VULNERABLE' && v.severity === 'HIGH').length || 0;
  const mediumFindings = report.vulnerabilities?.filter(v => v.status === 'VULNERABLE' && v.severity === 'MEDIUM').length || 0;
  const safeCount = report.vulnerabilities?.filter(v => v.status === 'SAFE').length || 0;

  const sortedVulns = [...(report.vulnerabilities || [])].sort((a, b) => {
    if (a.status !== 'VULNERABLE' && b.status === 'VULNERABLE') return 1;
    if (a.status === 'VULNERABLE' && b.status !== 'VULNERABLE') return -1;
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'SAFE': 4 };
    const aOrder = severityOrder[a.severity] ?? 5;
    const bOrder = severityOrder[b.severity] ?? 5;
    return aOrder - bOrder;
  });

  return (
    <div className="flex-1 max-w-7xl w-full mx-auto px-6 py-10 space-y-8">
      
      {/* Header Actions row */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-6">
        <div className="flex items-center gap-4">
          <div>
            <h1 className="text-[20px] font-semibold text-text-primary">Security Assessment</h1>
            <p className="text-[13px] text-text-secondary font-mono mt-1 bg-surface-2 border border-border px-2 py-0.5 rounded inline-block">
              Target: {report.scan?.target_url || report.target_url}
            </p>
          </div>
          <RiskScoreCircle score={report.risk_score} />
        </div>
        
        <div className="flex items-center gap-3">
          <button
            onClick={handleShare}
            className="flex items-center gap-1.5 border border-border bg-surface hover:bg-surface-2 text-text-primary text-[14px] font-semibold px-4 py-2 rounded transition-colors"
          >
            <Share2 className="w-4 h-4" />
            <span>{copied ? 'Copied Link!' : 'Share'}</span>
          </button>
          
          <button
            onClick={handleDownloadPdf}
            disabled={pdfLoading}
            className="flex items-center gap-1.5 bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white text-[14px] font-semibold px-4 py-2 rounded transition-colors"
          >
            {pdfLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            <span>Export PDF</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left column (40% width): Scan Info & Stats */}
        <div className="lg:col-span-4 space-y-6">
          <div className="bg-surface border border-border rounded p-6 space-y-4">
            <h4 className="text-[14px] font-semibold uppercase tracking-[0.04em] text-text-secondary">Scan Summary</h4>
            <div className="border-t border-border/40 pt-3 space-y-3 text-[14px]">
              <div className="flex justify-between items-center">
                <span className="text-text-secondary">Critical:</span>
                <span className="font-semibold text-critical">{criticalFindings}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-text-secondary">High:</span>
                <span className="font-semibold text-high">{highFindings}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-text-secondary">Passed:</span>
                <span className="font-semibold text-safe">{safeCount}</span>
              </div>
            </div>
          </div>

          <div className="bg-surface border border-border rounded p-6 space-y-4 text-[14px]">
            <h4 className="text-[14px] font-semibold uppercase tracking-[0.04em] text-text-secondary">Information</h4>
            <div className="border-t border-border/40 pt-3 space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-text-secondary">Status:</span>
                <span className="font-semibold text-safe uppercase text-[12px] font-mono">Completed</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-text-secondary">Scan Run On:</span>
                <span className="text-text-primary">{report.scan?.created_at ? new Date(report.scan.created_at).toLocaleDateString() : new Date().toLocaleDateString()}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-text-secondary">Attack Vectors:</span>
                <span className="text-text-primary">7/7 Evaluated</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right column (60% width): Vulnerability list Table */}
        <div className="lg:col-span-8 space-y-4">
          <h3 className="text-[14px] font-semibold uppercase tracking-[0.04em] text-text-secondary mb-2">
            Vulnerabilities ({sortedVulns.filter(v => v.status === 'VULNERABLE').length} Findings)
          </h3>
          
          <div className="overflow-x-auto bg-surface border border-border rounded">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-surface-2/40 text-[12px] font-medium text-text-muted uppercase tracking-wider">
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Vulnerability</th>
                  <th className="px-4 py-3 font-medium">CVSS</th>
                  <th className="px-4 py-3 text-right font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {sortedVulns.map((vuln) => (
                  <VulnerabilityCard key={vuln.attack_id || vuln.id} vuln={vuln} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
