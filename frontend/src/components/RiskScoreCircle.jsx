import React, { useState, useEffect } from 'react';

export default function RiskScoreCircle({ score }) {
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = score || 0;
    if (end === 0) {
      setDisplayScore(0);
      return;
    }
    
    const duration = 800;
    const stepTime = Math.abs(Math.floor(duration / end));
    
    const timer = setInterval(() => {
      start += 1;
      setDisplayScore(start);
      if (start >= end) {
        clearInterval(timer);
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [score]);

  const getTextColor = (val) => {
    if (val > 80) return 'text-critical';
    if (val > 60) return 'text-high';
    if (val > 40) return 'text-medium';
    if (val > 20) return 'text-low';
    return 'text-safe';
  };

  return (
    <div className="flex items-center gap-2">
      <div className={`w-14 h-14 rounded border border-border flex items-center justify-center font-bold text-lg ${getTextColor(displayScore)}`}>
        {displayScore}%
      </div>
      <div className="flex flex-col">
        <span className="text-[10px] font-semibold text-text-muted uppercase tracking-wider">
          Risk Score
        </span>
      </div>
    </div>
  );
}
