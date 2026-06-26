import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import client from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { Shield, Loader2, AlertCircle } from 'lucide-react';

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState('');
  
  const { setToken, setUser } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);

    try {
      const response = await client.post('/auth/register', { email, password });
      setToken(response.data.access_token);
      setUser(response.data.user);
      navigate('/dashboard');
    } catch (err) {
      if (err.response && err.response.status === 409) {
        setError('Email address is already registered.');
      } else {
        setError('Something went wrong. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-surface border border-border rounded-lg p-8 shadow-xl">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-surface-2 border border-border rounded-lg flex items-center justify-center mb-3">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <h2 className="text-[20px] font-semibold text-text-primary">Create an account</h2>
          <p className="text-sm text-text-secondary mt-1">Start scanning your MCP servers</p>
        </div>

        {error && (
          <div className="bg-critical/10 border border-critical/30 rounded-md p-3 mb-6 flex items-start gap-2 text-sm text-critical">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
              Email Address
            </label>
            <input
              type="email"
              required
              className="w-full bg-surface-2 border border-border focus:border-primary focus:ring-1 focus:ring-primary rounded-md p-3 text-sm text-text-primary placeholder-text-muted outline-none transition-colors"
              placeholder="name@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
              Password
            </label>
            <input
              type="password"
              required
              className="w-full bg-surface-2 border border-border focus:border-primary focus:ring-1 focus:ring-primary rounded-md p-3 text-sm text-text-primary placeholder-text-muted outline-none transition-colors"
              placeholder="Min. 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
              Confirm Password
            </label>
            <input
              type="password"
              required
              className="w-full bg-surface-2 border border-border focus:border-primary focus:ring-1 focus:ring-primary rounded-md p-3 text-sm text-text-primary placeholder-text-muted outline-none transition-colors"
              placeholder="Repeat password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-white font-medium p-3 rounded-md transition-colors flex items-center justify-center gap-2"
          >
            {loading && <Loader2 className="w-4 h-4 animate-spin" />}
            <span>Sign Up</span>
          </button>
        </form>

        <p className="text-sm text-text-secondary text-center mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-primary hover:underline font-medium">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
