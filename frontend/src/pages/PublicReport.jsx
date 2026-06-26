import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import RiskScoreCircle from '../components/RiskScoreCircle';
import VulnerabilityCard from '../components/VulnerabilityCard';
import { Loader2 } from 'lucide-react';

export default function PublicReport() {
  const { token } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchPublicReport = async () => {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
    try {
      const response = await axios.get(`${baseUrl}/report/public/${token}`);
      setReport(response.data);
    } catch (err) {
      setError('This report is no longer available or the sharing token is invalid.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPublicReport();
  }, [token]);

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary mb-2" />
        <span className="text-text-secondary text-[14px]">Loading shared security report...</span>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-center p-6">
        <h3 className="text-[20px] font-semibold text-text-primary mb-2">Public Report Not Accessible</h3>
        <p className="text-[14px] text-text-secondary max-w-sm mb-6">{error}</p>
      </div>
    );
  }

  const criticalFindings = report.vulnerabilities?.filter(v => v.status === 'VULNERABLE' && v.severity === 'CRITICAL').length || 0;
  const highFindings = report.vulnerabilities?.filter(v => v.status === 'VULNERABLE' && v.severity === 'HIGH').length || 0;
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
    <div className="flex-1 flex flex-col">
      {/* Clean solid banner for public views */}
      <div className="bg-surface border-b border-border py-3 px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-center sm:text-left">
        <div className="text-[14px] text-text-primary font-medium">
          <span>You are viewing a shared MCP Shield security report. Want to secure your own agents?</span>
        </div>
        <a
          href="/"
          className="bg-primary hover:bg-primary-hover text-white text-[14px] font-semibold px-3 py-1.5 rounded transition-colors"
        >
          Scan For Free
        </a>
      </div>

      <div className="max-w-7xl w-full mx-auto px-6 py-10 space-y-8">
        <div className="flex items-center gap-4 border-b border-border pb-6">
          <div>
            <h1 className="text-[20px] font-semibold text-text-primary">Shared Security Assessment</h1>
            <p className="text-[13px] text-text-secondary font-mono mt-1 bg-surface-2 border border-border px-2 py-0.5 rounded inline-block">
              Target: {report.scan?.target_url || report.target_url}
            </p>
          </div>
          <RiskScoreCircle score={report.risk_score} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left Column stats */}
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
          </div>

          {/* Right Column Vulnerabilities Table */}
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
    </div>
  );
}
