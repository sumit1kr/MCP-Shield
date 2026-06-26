import React from 'react';
import { CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';

export default function ScanProgressRow({ code, name, isCurrent, isDone, result }) {
  const getStatusIcon = () => {
    if (isDone) {
      if (result === 'VULNERABLE') {
        return <AlertTriangle className="w-4 h-4 text-critical" />;
      }
      return <CheckCircle2 className="w-4 h-4 text-safe" />;
    }
    if (isCurrent) {
      return <Loader2 className="w-4 h-4 text-primary animate-spin" />;
    }
    return <div className="w-4 h-4 rounded-full border border-border bg-surface-2 flex items-center justify-center text-[10px] text-text-muted font-mono">{code}</div>;
  };

  const getResultTag = () => {
    if (isDone) {
      if (result === 'VULNERABLE') {
        return (
          <span className="text-[12px] font-semibold text-critical">
            VULNERABLE
          </span>
        );
      }
      if (result === 'SAFE') {
        return (
          <span className="text-[12px] font-semibold text-safe">
            SAFE
          </span>
        );
      }
      return (
        <span className="text-[12px] font-semibold text-text-secondary">
          INCONCLUSIVE
        </span>
      );
    }
    if (isCurrent) {
      return (
        <span className="text-[12px] font-semibold text-primary">
          Running
        </span>
      );
    }
    return (
      <span className="text-[12px] text-text-muted font-medium">
        Waiting
      </span>
    );
  };

  return (
    <div className={`h-11 flex items-center justify-between px-4 transition-colors ${
      isCurrent ? 'bg-primary/5' : isDone ? 'bg-surface-2/10' : ''
    }`}>
      <div className="flex items-center gap-3">
        {getStatusIcon()}
        <span className={`text-[14px] font-medium ${isCurrent ? 'text-primary font-semibold' : 'text-text-primary'}`}>
          {code} — {name}
        </span>
      </div>
      <div>{getResultTag()}</div>
    </div>
  );
}
