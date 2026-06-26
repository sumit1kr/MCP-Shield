import React from 'react';

export default function RiskScoreBadge({ score }) {
  let textColor = 'text-safe';
  let level = 'SAFE';

  if (score > 80) {
    textColor = 'text-critical';
    level = 'CRITICAL';
  } else if (score > 60) {
    textColor = 'text-high';
    level = 'HIGH';
  } else if (score > 40) {
    textColor = 'text-medium';
    level = 'MEDIUM';
  } else if (score > 20) {
    textColor = 'text-low';
    level = 'LOW';
  }

  return (
    <span className={`text-xs font-semibold uppercase tracking-wider ${textColor}`}>
      {level} ({score})
    </span>
  );
}
