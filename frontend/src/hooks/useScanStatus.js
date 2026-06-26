import { useState, useEffect } from 'react';
import client from '../api/client';

export const useScanStatus = (scanId) => {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!scanId) return;

    let intervalId;

    const pollStatus = async () => {
      try {
        const response = await client.get(`/scans/${scanId}/status`);
        const data = response.data;
        setScan(data);
        
        if (data.status === 'complete' || data.status === 'failed') {
          clearInterval(intervalId);
        }
      } catch (err) {
        setError(err.response?.data?.detail || 'Failed to update scan progress.');
        clearInterval(intervalId);
      } finally {
        setLoading(false);
      }
    };

    pollStatus();
    intervalId = setInterval(pollStatus, 3000);

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [scanId]);

  return { scan, loading, error };
};
