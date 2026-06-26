import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import client from '../api/client';
import ScanTable from '../components/ScanTable';
import { Play, Loader2, AlertTriangle, Database, ShieldCheck, ArrowRight, Server } from 'lucide-react';

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [criticalIssues, setCriticalIssues] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const fetchScansAndIssues = async () => {
    try {
      const response = await client.get('/scans?limit=50');
      const scanList = response.data.scans || response.data || [];
      setScans(scanList);

      // Fetch reports for completed critical/high risk scans in the background
      const criticalOrHighScans = scanList.filter(
        s => s.status === 'complete' && (s.risk_level === 'CRITICAL' || s.risk_level === 'HIGH')
      );

      if (criticalOrHighScans.length > 0) {
        const reports = await Promise.all(
          criticalOrHighScans.map(s =>
            client.get(`/reports/${s.id}`).then(r => r.data).catch(() => null)
          )
        );

        const issues = [];
        reports.forEach(report => {
          if (report && report.vulnerabilities) {
            report.vulnerabilities.forEach(v => {
              if (v.status === 'VULNERABLE' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')) {
                issues.push({
                  ...v,
                  scanId: report.scan_id,
                  serverName: report.scan?.server_name || "Unnamed Server",
                  targetUrl: report.scan?.target_url || report.target_url
                });
              }
            });
          }
        });
        setCriticalIssues(issues);
      } else {
        setCriticalIssues([]);
      }
    } catch (err) {
      setError('Failed to fetch scans. Please reload page.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScansAndIssues();
  }, []);

  const handleRescan = async (url) => {
    try {
      const response = await client.post('/scans', { target_url: url });
      const scanId = response.data.scan_id || response.data.id;
      navigate(`/scans/${scanId}/progress`);
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to dispatch scan.');
    }
  };

  // Stats calculation
  const totalScans = scans.length;
  const criticalCount = scans.filter(s => s.status === 'complete' && s.risk_level === 'CRITICAL').length;
  const safeCount = scans.filter(s => s.status === 'complete' && s.risk_level === 'SAFE').length;

  // Unique Assets (servers/URLs)
  const uniqueAssets = Array.from(new Set(scans.map(s => s.target_url))).map(url => {
    const matched = scans.find(s => s.target_url === url);
    return {
      url,
      serverName: matched?.server_name || "Unnamed Server"
    };
  });

  if (loading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary mb-2" />
        <span className="text-text-secondary text-[14px]">Loading dashboard data...</span>
      </div>
    );
  }

  return (
    <div className="flex-1 max-w-7xl w-full mx-auto px-6 py-10 space-y-8">
      
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[20px] font-semibold text-text-primary">Dashboard</h1>
        </div>
        <button
          onClick={() => navigate('/scans/new')}
          className="bg-primary hover:bg-primary-hover text-white text-[14px] font-semibold px-4 py-2 rounded transition-colors flex items-center gap-2"
        >
          <Play className="w-4 h-4 fill-white" />
          New Security Scan
        </button>
      </div>

      {error && (
        <div className="bg-critical/10 border border-border rounded p-4 text-[14px] text-critical">
          {error}
        </div>
      )}

      {/* 1. Critical Issues Requiring Action */}
      <div className="bg-surface border border-border rounded p-6">
        <h2 className="text-[14px] font-semibold uppercase tracking-[0.04em] text-text-secondary mb-4">
          Critical Issues Requiring Action
        </h2>
        {criticalIssues.length === 0 ? (
          <div className="text-[14px] text-text-muted py-2">
            No critical issues open. All systems within acceptable risk thresholds.
          </div>
        ) : (
          <div className="divide-y divide-border/40">
            {criticalIssues.map((issue, idx) => (
              <div key={idx} className="flex items-center justify-between py-4 first:pt-0 last:pb-0">
                <div className="flex items-center gap-4">
                  <AlertTriangle className="w-5 h-5 text-critical shrink-0" />
                  <div>
                    <h3 className="text-[14px] font-semibold text-text-primary">
                      {issue.attack_name}
                    </h3>
                    <div className="flex items-center gap-2 text-[14px] text-text-muted mt-1">
                      <span>{issue.serverName}</span>
                      <span>·</span>
                      <span className="font-mono text-[13px]">{issue.targetUrl}</span>
                    </div>
                  </div>
                </div>
                <Link
                  to={`/reports/${issue.scanId}`}
                  className="text-primary hover:text-primary-hover text-[14px] font-semibold flex items-center gap-1"
                >
                  <span>View</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 2. Recent Scans */}
      <div className="space-y-4">
        <h2 className="text-[14px] font-semibold uppercase tracking-[0.04em] text-text-secondary">
          Recent Scans
        </h2>
        {scans.length === 0 ? (
          <div className="bg-surface border border-border rounded p-12 flex flex-col items-center justify-center text-center">
            <p className="text-text-secondary text-[14px] max-w-sm mb-6">
              No scans run yet. Run a scan to analyze your MCP Server.
            </p>
            <button
              onClick={() => navigate('/scans/new')}
              className="bg-primary hover:bg-primary-hover text-white text-[14px] font-semibold px-4 py-2 rounded transition-colors"
            >
              Run Your First Scan
            </button>
          </div>
        ) : (
          <ScanTable scans={scans} onRescan={handleRescan} />
        )}
      </div>

      {/* 3. Security Posture (Compact summary row) */}
      <div className="border-t border-border pt-4 text-[14px] text-text-muted flex items-center gap-4">
        <span>Security Posture:</span>
        <span className="font-semibold text-text-primary">{totalScans} scans</span>
        <span>·</span>
        <span className="font-semibold text-critical">{criticalCount} critical</span>
        <span>·</span>
        <span className="font-semibold text-safe">{safeCount} safe</span>
      </div>

      {/* 4. Assets Tracked */}
      <div className="bg-surface border border-border rounded p-6">
        <h2 className="text-[14px] font-semibold uppercase tracking-[0.04em] text-text-secondary mb-4">
          Assets Tracked
        </h2>
        {uniqueAssets.length === 0 ? (
          <div className="text-[14px] text-text-muted">No assets registered.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {uniqueAssets.map((asset, idx) => (
              <div key={idx} className="flex items-center gap-3 p-3 bg-surface-2 rounded border border-border/60">
                <Server className="w-4 h-4 text-text-secondary" />
                <div>
                  <div className="text-[14px] font-semibold text-text-primary">{asset.serverName}</div>
                  <div className="font-mono text-[13px] text-text-secondary mt-0.5">{asset.url}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}
