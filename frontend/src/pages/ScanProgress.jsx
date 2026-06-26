import React, { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useScanStatus } from '../hooks/useScanStatus';
import ScanProgressRow from '../components/ScanProgressRow';
import { Shield, Loader2 } from 'lucide-react';

export default function ScanProgress() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { scan, error } = useScanStatus(id);

  useEffect(() => {
    if (scan && scan.status === 'complete') {
      const timer = setTimeout(() => {
        navigate(`/reports/${id}`);
      }, 1500);
      return () => clearTimeout(timer);
    }
  }, [scan, navigate, id]);

  const attackVectors = [
    { code: 'A01', name: 'Prompt Injection', val: 1 },
    { code: 'A02', name: 'Tool Poisoning', val: 2 },
    { code: 'A03', name: 'Token/Secret Exposure', val: 3 },
    { code: 'A04', name: 'Shell Injection', val: 4 },
    { code: 'A05', name: 'SSRF Verification', val: 5 },
    { code: 'A06', name: 'Rug Pull Detection', val: 6 },
    { code: 'A07', name: 'Supply Chain Check', val: 7 },
  ];

  if (error) {
    return (
      <div className="flex-1 max-w-md mx-auto flex flex-col items-center justify-center p-6 text-center">
        <div className="w-12 h-12 bg-critical/10 text-critical border border-critical/30 rounded flex items-center justify-center mb-4">
          <Shield className="w-6 h-6" />
        </div>
        <h3 className="text-[20px] font-semibold text-text-primary mb-2">Scan Failed to Load</h3>
        <p className="text-[14px] text-text-secondary mb-6">{error}</p>
        <button
          onClick={() => navigate('/dashboard')}
          className="bg-surface-2 border border-border px-4 py-2 rounded hover:bg-surface text-[14px]"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  const progress = scan ? scan.progress : 10;
  const currentAttackIdx = scan ? scan.attacks_done : 0;
  const currentStatusMsg = scan ? (scan.current_attack || 'Executing attack nodes...') : 'Initializing scan...';
  const targetUrl = scan ? scan.target_url : 'Connecting...';

  return (
    <div className="flex-1 max-w-3xl w-full mx-auto px-6 py-12 flex flex-col items-center justify-center">
      
      {/* Target URL Info */}
      <div className="mb-8 flex flex-col items-center">
        <div className="w-14 h-14 bg-surface border border-border rounded-full flex items-center justify-center text-primary z-10">
          <Shield className="w-6 h-6" />
        </div>
        <h2 className="text-[20px] font-semibold text-text-primary mt-6">
          Scanning Target Server
        </h2>
        <span className="font-mono text-[13px] text-text-secondary mt-2 bg-surface-2 border border-border px-3 py-1 rounded">
          {targetUrl}
        </span>
      </div>

      {/* Progress Bar Container */}
      <div className="w-full bg-surface border border-border rounded p-6 mb-8">
        <div className="flex justify-between items-center mb-3">
          <span className="text-[14px] font-semibold uppercase tracking-[0.04em] text-text-secondary">
            {currentStatusMsg}
          </span>
          <span className="font-mono text-[13px] font-bold text-primary">
            {progress}%
          </span>
        </div>
        <div className="w-full h-2 bg-surface-2 border border-border rounded overflow-hidden">
          <div
            className="h-full bg-primary transition-all duration-500 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>
        
        {scan?.status === 'failed' && (
          <div className="bg-critical/10 border border-critical/30 rounded p-3 mt-4 text-[14px] text-critical leading-relaxed">
            <strong>Scan Aborted:</strong> {scan.error_message || 'Target was unreachable.'}
          </div>
        )}
      </div>

      {/* Attack Nodes List */}
      <div className="w-full bg-surface border border-border rounded overflow-hidden">
        <div className="bg-surface-2/50 border-b border-border px-4 py-3 text-[12px] font-medium text-text-secondary uppercase tracking-wider">
          Attack Audit Pipeline ({scan?.attacks_done || 0}/7 Completed)
        </div>
        <div className="divide-y divide-border/50">
          {attackVectors.map((vector) => {
            const isDone = currentAttackIdx >= vector.val;
            const isCurrent = scan?.status === 'running' && currentAttackIdx === vector.val - 1;
            
            let result = 'SAFE';
            if (scan?.results && Array.isArray(scan.results)) {
              const resObj = scan.results.find(r => r.attack_id === vector.code);
              if (resObj) result = resObj.status;
            }

            return (
              <ScanProgressRow
                key={vector.code}
                code={vector.code}
                name={vector.name}
                isCurrent={isCurrent}
                isDone={isDone}
                result={result}
              />
            );
          })}
        </div>
      </div>
      
      {scan?.status === 'complete' && (
        <div className="text-[14px] text-safe mt-6 flex items-center gap-1.5 font-medium">
          <Loader2 className="w-4 h-4 animate-spin" />
          Preparing comprehensive security audit report...
        </div>
      )}
    </div>
  );
}
