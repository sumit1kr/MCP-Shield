import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Shield, LogOut, LayoutDashboard, Play, User } from 'lucide-react';

export default function Navbar() {
  const { isAuthenticated, user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <nav className="sticky top-0 z-50 h-14 bg-bg border-b border-border px-6 flex items-center justify-between">
      <Link to="/" className="flex items-center gap-2 text-text-primary hover:opacity-90">
        <Shield className="w-5 h-5 text-primary" />
        <span className="font-semibold text-lg tracking-tight">MCP Shield</span>
      </Link>

      <div className="flex items-center gap-6">
        {isAuthenticated ? (
          <>
            <Link to="/dashboard" className="flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors">
              <LayoutDashboard className="w-4 h-4" />
              <span>Dashboard</span>
            </Link>
            <Link to="/scans/new" className="flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors">
              <Play className="w-4 h-4" />
              <span>New Scan</span>
            </Link>
            
            <div className="relative group flex items-center gap-2 cursor-pointer">
              <div className="w-8 h-8 rounded-full bg-surface-2 border border-border flex items-center justify-center text-primary text-sm font-semibold uppercase">
                {user?.email?.charAt(0) || <User className="w-4 h-4" />}
              </div>
              <span className="text-sm text-text-secondary group-hover:text-text-primary hidden sm:inline">{user?.email}</span>
              
              <div className="absolute right-0 top-full mt-1 w-48 bg-surface border border-border rounded-md shadow-lg py-1 hidden group-hover:block hover:block">
                <button
                  onClick={handleLogout}
                  className="w-full px-4 py-2 text-left text-sm text-critical hover:bg-surface-2 flex items-center gap-2"
                >
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex items-center gap-4">
            <Link to="/login" className="text-sm text-text-secondary hover:text-text-primary transition-colors">
              Login
            </Link>
            <Link
              to="/register"
              className="bg-primary hover:bg-primary-hover text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
            >
              Get Started
            </Link>
          </div>
        )}
      </div>
    </nav>
  );
}
