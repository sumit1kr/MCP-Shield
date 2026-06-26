import React from 'react';
import { Link } from 'react-router-dom';
import { Play, ArrowRight } from 'lucide-react';

export default function ScanTable({ scans, onRescan }) {
  const getRiskStyle = (score, level) => {
    if (level === 'CRITICAL' || score > 80) return { text: 'Critical', color: 'text-critical' };
    if (level === 'HIGH' || score > 60) return { text: 'High', color: 'text-high' };
    if (level === 'MEDIUM' || score > 40) return { text: 'Medium', color: 'text-medium' };
    if (level === 'LOW' || score > 20) return { text: 'Low', color: 'text-low' };
    return { text: 'Safe', color: 'text-safe' };
  };

  return (
    <div className="overflow-x-auto bg-surface border border-border rounded">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="border-b border-border bg-surface-2/40 text-[12px] font-medium text-text-muted uppercase tracking-wider">
            <th className="px-4 py-3 font-medium">Server Name</th>
            <th className="px-4 py-3 font-medium">Target URL</th>
            <th className="px-4 py-3 font-medium">Risk Level</th>
            <th className="px-4 py-3 font-medium">Score</th>
            <th className="px-4 py-3 font-medium">Scanned</th>
            <th className="px-4 py-3 text-right font-medium">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border/40">
          {scans.map((scan) => {
            const score = scan.risk_score;
            const level = scan.risk_level;
            const status = scan.status;
            
            let riskInfo = { text: '—', color: 'text-text-muted' };
            if (status === 'complete' && score !== null && score !== undefined) {
              riskInfo = getRiskStyle(score, level);
            }

            return (
              <tr
                key={scan.id}
                className="hover:bg-surface-2 transition-colors"
              >
                <td className="px-4 py-3 text-[14px] font-semibold text-text-primary">
                  {scan.server_name || "Unnamed Server"}
                </td>
                <td className="px-4 py-3 font-mono text-[13px] text-text-secondary truncate max-w-[240px]">
                  {scan.target_url}
                </td>
                <td className="px-4 py-3 text-[14px] font-semibold">
                  <span className={riskInfo.color}>{riskInfo.text}</span>
                </td>
                <td className="px-4 py-3 text-[14px] font-mono text-text-secondary">
                  {status === 'complete' && score !== null && score !== undefined ? `${score}%` : '—'}
                </td>
                <td className="px-4 py-3 text-[14px] text-text-muted">
                  {new Date(scan.created_at).toLocaleDateString()} {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-3">
                    {status === 'complete' ? (
                      <Link
                        to={`/reports/${scan.id}`}
                        className="text-primary hover:text-primary-hover text-[14px] font-semibold flex items-center gap-1"
                      >
                        <span>Report</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    ) : status === 'running' ? (
                      <Link
                        to={`/scans/${scan.id}/progress`}
                        className="text-primary hover:underline text-[14px] font-semibold"
                      >
                        Track
                      </Link>
                    ) : (
                      <span className="text-text-muted text-[14px]">—</span>
                    )}
                    
                    {status !== 'running' && (
                      <button
                        onClick={() => onRescan(scan.target_url)}
                        className="p-1 text-text-secondary hover:text-text-primary hover:bg-surface-2 rounded transition-colors"
                        title="Run Scan Again"
                      >
                        <Play className="w-3.5 h-3.5 fill-current" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
