// src/lib/auth-context.tsx
'use client';
import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import Cookies from 'js-cookie';
import { auth as authApi } from './api';

type User = { user_id: string; email: string; username: string; role: string } | null;

type AuthCtx = {
  user: User;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthCtx>({} as AuthCtx);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = Cookies.get('eso_token');
    if (token) {
      authApi.me().then(u => setUser(u)).catch(() => Cookies.remove('eso_token')).finally(() => setLoading(false));
    } else {
      // Dev mode — try without token
      authApi.me().then(u => { setUser(u); }).catch(() => {}).finally(() => setLoading(false));
    }
  }, []);

  const login = async (email: string, password: string) => {
    const res = await authApi.login(email, password);
    Cookies.set('eso_token', res.access_token, { expires: 1 });
    setUser(res.user);
  };

  const register = async (email: string, username: string, password: string) => {
    const res = await authApi.register(email, username, password);
    Cookies.set('eso_token', res.access_token, { expires: 1 });
    setUser(res.user);
  };

  const logout = () => { Cookies.remove('eso_token'); setUser(null); };

  return <AuthContext.Provider value={{ user, loading, login, register, logout }}>{children}</AuthContext.Provider>;
}
