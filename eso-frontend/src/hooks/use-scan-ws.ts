// src/hooks/use-scan-ws.ts
'use client';
import { useEffect, useRef, useState, useCallback } from 'react';

export type ScanEvent = {
  type: string;
  process_id: string;
  data: Record<string, any>;
  timestamp: string;
};

export function useScanWS(processId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [state, setState] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('disconnected');
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<NodeJS.Timeout>();
  const seenRef = useRef<Set<string>>(new Set());

  const connect = useCallback(() => {
    if (!processId) return;

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const url = `${proto}//${host}:8000/api/v1/ws/scan/${processId}`;

    setState('connecting');
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => { setState('connected'); };
    ws.onmessage = (msg) => {
      try {
        const ev: ScanEvent = JSON.parse(msg.data);
        // Deduplicate by timestamp + type
        const key = `${ev.timestamp}:${ev.type}`;
        if (seenRef.current.has(key)) return;
        seenRef.current.add(key);
        setEvents(prev => [...prev, ev]);
      } catch {}
    };
    ws.onclose = () => { setState('disconnected'); wsRef.current = null; };
    ws.onerror = () => { setState('error'); ws.close(); retryRef.current = setTimeout(connect, 3000); };
  }, [processId]);

  useEffect(() => {
    if (processId) { setEvents([]); seenRef.current.clear(); connect(); }
    return () => { wsRef.current?.close(); clearTimeout(retryRef.current); };
  }, [processId, connect]);

  const latest = events.length > 0 ? events[events.length - 1] : null;
  const isTerminal = latest?.type === 'complete' || latest?.type === 'error';
  const ofType = (t: string) => events.filter(e => e.type === t);
  const lastOf = (t: string) => { const m = ofType(t); return m.length ? m[m.length - 1] : null; };

  return { events, latest, state, isTerminal, ofType, lastOf };
}
