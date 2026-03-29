// src/lib/api.ts
import Cookies from 'js-cookie';

const BASE = '/api/v1';

async function request(method: string, path: string, body?: any) {
  const token = Cookies.get('eso_token');
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || err.error?.message || 'Request failed');
  }
  return res.json();
}

export const api = {
  get: (path: string) => request('GET', path),
  post: (path: string, body?: any) => request('POST', path, body),
  del: (path: string) => request('DELETE', path),
};

// Auth
export const auth = {
  register: (email: string, username: string, password: string) =>
    api.post('/auth/register', { email, username, password }),
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),
  me: () => api.get('/auth/me'),
  createApiKey: (name: string) => api.post('/auth/api-keys', { name }),
  listApiKeys: () => api.get('/auth/api-keys'),
  revokeApiKey: (keyId: string) => api.del(`/auth/api-keys/${keyId}`),
};

// Scans
export const scans = {
  execute: (goal: string, target: string) =>
    api.post('/hybrid/execute', { goal, target }),
  status: (id: string) => api.get(`/hybrid/status/${id}`),
  proposals: (id: string) => api.get(`/hybrid/proposals/${id}`),
  approve: (id: string, approved: string[]) =>
    api.post(`/hybrid/approve/${id}`, { approved }),
  list: () => api.get('/hybrid/list'),
  pdfUrl: (id: string) => `${BASE}/hybrid/report/${id}/pdf`,
};

// History
export const history = {
  list: (limit = 20, offset = 0) => api.get(`/auth/scans?limit=${limit}&offset=${offset}`),
  get: (id: string) => api.get(`/auth/scans/${id}`),
};

// System
export const system = {
  health: () => api.get('/health'),
  info: () => api.get('/system/info'),
  switchLLM: (provider: string, model?: string) =>
    api.post('/system/llm/switch', { provider, model }),
  testLLM: () => api.get('/system/llm/test'),
};
