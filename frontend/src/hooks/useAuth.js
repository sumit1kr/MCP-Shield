import { useEffect } from 'react';
import { useAuthStore } from '../store/authStore';

export const useAuth = () => {
  const { token, user, setToken, setUser, logout } = useAuthStore();

  useEffect(() => {
    const handleUnauthorized = () => {
      logout();
    };

    window.addEventListener('auth-unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('auth-unauthorized', handleUnauthorized);
    };
  }, [logout]);

  return {
    isAuthenticated: !!token,
    token,
    user,
    setToken,
    setUser,
    logout,
  };
};
